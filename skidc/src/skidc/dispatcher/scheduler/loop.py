from __future__ import annotations

import logging
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import requests

from skidc.dispatcher.config import DispatchConfig, WorkerConfig
from skidc.dispatcher.models import ReasonCheckpoint, RunningTask
from skidc.dispatcher.protocol.client import SkidcClient
from skidc.dispatcher.recon_extractor import check_recon_executed, extract_potential_targets
from skidc.dispatcher.runtime.cancellation import TaskCancellation
from skidc.dispatcher.runtime.containers import ContainerManager
from skidc.dispatcher.runtime.startup_healthcheck import (
    format_failure_summary,
    missing_healthy_task_types,
    run_startup_healthchecks,
)
from skidc.dispatcher.scheduler.worker_select import choose_worker
from skidc.dispatcher.tasks.bootstrap import run_bootstrap_task
from skidc.dispatcher.tasks.explore import run_explore_task
from skidc.dispatcher.tasks.reason import ensure_coverage_work, run_reason_task
from skidc.server.models import Intent, ProjectDetail, ProjectSummary
from skidc.server.services import scope_violation_reason, utcnow

LOG = logging.getLogger(__name__)
UNHEALTHY_RETRY_AFTER_SECONDS = 5
REJECTED_RETRY_AFTER_SECONDS = 5
MAX_TASK_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = (5, 15, 60)
BOOTSTRAP_INTENT_DESCRIPTION = "bootstrap"
BOOTSTRAP_INTENT_CREATOR = "dispatcher.bootstrap"
RETRYABLE_OUTCOMES = {"failed", "rejected"}
_RECON_INTENT_CATEGORY_HINTS: dict[str, tuple[str, ...]] = {
    "port_scan": ("port", "service", "nmap", "naabu", "tcp", "udp"),
    "subdomain": ("subdomain", "dns", "subfinder", "amass", "cname"),
    "directory": ("directory", "dir", "path", "endpoint", "ffuf", "gobuster", "dirsearch"),
    "asset": ("asset", "crawl", "url", "js", "javascript", "katana"),
    "android_app": ("android_app", "apk", "package", "manifest"),
    "android_ui": ("android_ui", "ui", "screen", "activity"),
    "mobile_api": ("mobile_api", "mobile api", "api call", "network"),
    "android_storage": ("android_storage", "storage", "sqlite", "keystore"),
}


def _retry_backoff_seconds(attempt_count: int) -> int:
    index = max(0, min(attempt_count, len(RETRY_BACKOFF_SECONDS) - 1))
    return RETRY_BACKOFF_SECONDS[index]


def _potential_target_key(description: str) -> str:
    return " ".join(description.casefold().split())


def _intent_recon_category(intent: Intent) -> str | None:
    haystack = " ".join(
        value
        for value in (
            intent.action_kind,
            intent.surface_type,
            intent.description,
            " ".join(intent.suggested_tools),
        )
        if value
    ).casefold()
    for category, hints in _RECON_INTENT_CATEGORY_HINTS.items():
        if category.casefold() in haystack or any(hint in haystack for hint in hints):
            return category
    return None


@dataclass(slots=True)
class WorkerSelection:
    worker: WorkerConfig | None
    blocked_busy: list[str]
    blocked_unhealthy: list[str]
    blocked_rejected: list[str]
    blocked_task_type: list[str]


class DispatcherLoop:
    """The control plane. Reads the graph from the server, decides which task type to
    dispatch per project (bootstrap -> reason -> explore), claims the lease, runs the
    worker in the project container, and writes results back. Sole protocol writer."""

    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.config = DispatchConfig.load(config_path)
        self.client = SkidcClient(
            self.config.server,
            timeout=self.config.runtime.server_timeout,
            detail_timeout=self.config.runtime.project_detail_timeout,
            dispatch_timeout=self.config.runtime.dispatch_view_timeout,
        )
        self.container_manager = ContainerManager(self.config.container)
        self.executor = ThreadPoolExecutor(max_workers=self.config.runtime.max_workers)
        self.cleanup_executor = ThreadPoolExecutor(max_workers=max(1, min(8, self.config.runtime.max_workers)))
        self.futures: dict[Future[str], RunningTask] = {}
        self.cleanup_futures: dict[Future[bool], tuple[str, str | None, str | None]] = {}
        self.reason_checkpoints: dict[str, ReasonCheckpoint] = {}
        self.runtime_project_ids: set[str] = set()
        self.worker_unhealthy_until: dict[str, float] = {}
        self.worker_rejected_until: dict[tuple[str, str, str], float] = {}
        self.startup_unhealthy_workers: set[str] = set()
        self._log_state: dict[str, tuple[int, str, tuple[object, ...]]] = {}
        self._cleanup_pending: set[str] = set()
        self._inactive_cleanup_done: dict[str, str] = {}
        self.project_cursor = 0
        self._settings_checked = False
        self._startup_healthchecks_checked = False

    def close(self) -> None:
        if self.futures:
            LOG.info(
                "dispatcher shutting down waiting_for_tasks=%s running_projects=%s",
                len(self.futures),
                sorted({task.project_id for task in self.futures.values()}),
            )
        self.executor.shutdown(wait=True)
        self.cleanup_executor.shutdown(wait=True)
        self.container_manager.close()
        self.client.close()

    def run(self, once: bool = False) -> None:
        try:
            self.run_startup_healthchecks()
            while True:
                try:
                    if not self._settings_checked:
                        self._validate_server_settings()
                        self._settings_checked = True
                    self._reap_futures()
                    self._reap_cleanup_futures()
                    summaries = self.client.list_projects()
                    self._initialize_reason_checkpoints(summaries)
                    self._refresh_runtime_projects(summaries)
                    self._cancel_inactive_tasks(summaries)
                    self._queue_container_cleanups(summaries)
                    self._dispatch_available(summaries)
                except requests.RequestException as exc:
                    if once:
                        raise
                    LOG.warning("dispatcher server request failed error=%s retry_in=%ss", exc, self.config.runtime.interval)
                    time.sleep(self.config.runtime.interval)
                    continue
                except Exception as exc:
                    if once:
                        raise
                    LOG.exception("dispatcher cycle failed error=%s retry_in=%ss", exc, self.config.runtime.interval)
                    time.sleep(self.config.runtime.interval)
                    continue
                if once:
                    break
                time.sleep(self.config.runtime.interval)
        finally:
            self.close()

    def run_startup_healthchecks_only(self) -> None:
        try:
            self.run_startup_healthchecks(show_commands=True, force=True)
        finally:
            self.close()

    def run_startup_healthchecks(self, *, show_commands: bool = False, force: bool = False) -> None:
        if self._startup_healthchecks_checked and not force:
            return
        if not force and self.config.runtime.worker_healthcheck == "disabled":
            LOG.info("skip startup worker healthchecks because runtime.worker_healthcheck=disabled")
            self._startup_healthchecks_checked = True
            return
        results = run_startup_healthchecks(self.config, self.container_manager, show_commands=show_commands)
        now = time.time()
        for result in results:
            if result.ok:
                self.startup_unhealthy_workers.discard(result.worker_name)
                self.worker_unhealthy_until.pop(result.worker_name, None)
            else:
                self.startup_unhealthy_workers.add(result.worker_name)
                self.worker_unhealthy_until[result.worker_name] = now + UNHEALTHY_RETRY_AFTER_SECONDS
        if missing_healthy_task_types(self.config, results):
            raise RuntimeError(format_failure_summary(results, self.config))
        self._startup_healthchecks_checked = True

    # ---- dispatch decision tree -------------------------------------------------

    def _dispatch_available(self, summaries: list[ProjectSummary]) -> None:
        if len(self.futures) >= self.config.runtime.max_workers:
            self._log_changed("dispatch/global", logging.INFO, "skip dispatch because max_workers reached running_tasks=%s", len(self.futures))
            return
        active = [summary for summary in summaries if summary.status == "active"]
        if not active:
            self._log_changed("dispatch/global", logging.INFO, "skip dispatch because no active projects")
            return

        live_project_ids = self._live_project_ids()
        running_projects = self._ordered_projects([s for s in active if s.id in live_project_ids])
        idle_projects = self._ordered_projects([s for s in active if s.id not in live_project_ids])

        dispatched = True
        while dispatched and len(self.futures) < self.config.runtime.max_workers:
            dispatched = False
            for summary in running_projects:
                if self._try_dispatch_project(summary):
                    dispatched = True
                    if len(self.futures) >= self.config.runtime.max_workers:
                        return
            if dispatched:
                continue
            if self._running_project_count(active) >= self.config.runtime.max_running_projects:
                self._log_changed("dispatch/idle-limit", logging.INFO, "skip idle project dispatch because max_running_projects reached running_projects=%s", self._running_project_count(active))
                return
            for summary in idle_projects:
                if self._running_project_count(active) >= self.config.runtime.max_running_projects:
                    return
                if self._try_dispatch_project(summary):
                    dispatched = True
                    break

    def _ordered_projects(self, summaries: list[ProjectSummary]) -> list[ProjectSummary]:
        if not summaries:
            return []
        ids = [summary.id for summary in summaries]
        ids.sort()
        offset = self.project_cursor % len(ids)
        ordered_ids = ids[offset:] + ids[:offset]
        by_id = {summary.id: summary for summary in summaries}
        self.project_cursor += 1
        return [by_id[project_id] for project_id in ordered_ids]

    def _try_dispatch_project(self, summary: ProjectSummary) -> bool:
        skip_scope = f"project:{summary.id}:skip"
        container_name = self.container_manager.container_name(summary.id)
        if container_name in self._cleanup_pending:
            return False
        if self._project_running_task_count(summary.id) >= self.config.runtime.max_project_workers:
            self._log_changed(f"{skip_scope}:max_project_workers", logging.INFO, "skip project=%s because max_project_workers reached running_tasks=%s", summary.id, self._project_running_task_summary(summary.id))
            return False

        project = self.client.get_project(summary.id)
        if project.project.status != "active":
            return False
        if project.project.mode == "real_website" and project.project.phase == "explore":
            created = ensure_coverage_work(self.client, project, "dispatcher.coverage")
            if created:
                LOG.info(
                    "coverage planner created work project=%s intents=%s", project.project.id, created
                )
                return True
            project = self.client.get_project(summary.id)
        if self._is_initial_project(project):
            if project.project.reason is not None:
                return False
            if self._project_requires_bootstrap(project):
                return self._dispatch_initial_project(project)
            export_yaml = self.client.export_project(summary.id)
            return self._dispatch_reason(project, export_yaml, "initial")

        running_intent_ids = self._project_running_explore_intents(summary.id)
        unclaimed_intents = self._scope_allowed_intents(
            project,
            [
                intent
                for intent in project.intents
                if intent.to is None
                and intent.worker is None
                and intent.id not in running_intent_ids
                and not self._is_bootstrap_intent(intent)
                and self._intent_is_dispatchable(intent)
            ],
        )
        if unclaimed_intents:
            next_intent = self._select_next_intent(project, unclaimed_intents)
            export_yaml = self.client.export_project(summary.id)
            return self._dispatch_explore(project, export_yaml, next_intent)

        if project.project.phase == "recon" and self._recon_gate_check(project):
            transition = self.client.advance_phase(project.project.id)
            if not transition.ok:
                LOG.warning(
                    "deterministic recon transition failed project=%s status=%s body=%s",
                    project.project.id,
                    transition.status_code,
                    transition.text,
                )
                return False
            result = transition.data if isinstance(transition.data, dict) else {}
            if not result.get("advanced") and result.get("code") != "already_explore":
                self._log_changed(
                    f"project:{project.project.id}:phase-transition",
                    logging.WARNING,
                    "structured recon transition blocked project=%s code=%s missing=%s open=%s",
                    project.project.id,
                    result.get("code"),
                    result.get("missing_categories"),
                    result.get("open_recon_intents"),
                )
                return False
            self._clear_log_state(f"project:{project.project.id}:phase-transition")
            refreshed = self.client.get_project(project.project.id)
            created = ensure_coverage_work(self.client, refreshed, "dispatcher.coverage")
            LOG.info(
                "deterministic recon transition completed project=%s baseline_intents=%s",
                project.project.id,
                created,
            )
            return True

        if project.project.reason is None:
            reason_trigger = self._reason_trigger(project)
            if reason_trigger is not None:
                export_yaml = self.client.export_project(summary.id)
                return self._dispatch_reason(project, export_yaml, reason_trigger)
        return False

    def _intent_is_dispatchable(self, intent: Intent) -> bool:
        if intent.status != "open":
            return False
        if intent.next_retry_at is not None and intent.next_retry_at > utcnow():
            return False
        return True

    def _scope_allowed_intents(self, project: ProjectDetail, intents: list[Intent]) -> list[Intent]:
        allowed = []
        for intent in intents:
            reason = scope_violation_reason(
                project.project.scope_policy,
                target=intent.target,
                port=intent.port,
                path=intent.path,
                action_kind=intent.action_kind,
            )
            if reason is not None:
                LOG.warning(
                    "skip out-of-scope intent project=%s intent=%s reason=%s",
                    project.project.id,
                    intent.id,
                    reason,
                )
                continue
            allowed.append(intent)
        return allowed

    def _select_next_intent(self, project: ProjectDetail, intents: list[Intent]) -> Intent:
        status = check_recon_executed(project.facts, profile=project.project.recon_profile)
        missing = status.missing_executions if project.project.phase == "recon" else []
        missing_index = {category: index for index, category in enumerate(missing)}

        def sort_key(intent: Intent) -> tuple[int, int, int, str, str]:
            category = _intent_recon_category(intent)
            category_rank = missing_index.get(category, len(missing_index))
            unknown_rank = 1 if missing and category not in missing_index else 0
            priority_rank = -(intent.priority or 0)
            return (category_rank, unknown_rank, priority_rank, intent.created_at, intent.id)

        return min(intents, key=sort_key)

    def _dispatch_initial_project(self, project: ProjectDetail) -> bool:
        intent = self._get_bootstrap_intent(project)
        if intent is None:
            intent = self._create_bootstrap_intent(project.project.id)
            if intent is None:
                return False
        elif not self._intent_is_dispatchable(intent):
            return False
        if self._project_has_running_bootstrap(project.project.id):
            return False
        if intent.worker is not None:
            return False
        return self._dispatch_bootstrap(project, intent)

    def _dispatch_reason(self, project: ProjectDetail, export_yaml: str, trigger: str) -> bool:
        selection = self._select_worker(project.project.id, "reason")
        worker = selection.worker
        if worker is None:
            self._log_changed(f"project:{project.project.id}:worker:reason", logging.INFO, "no worker available for reason project=%s blocked_busy=%s blocked_unhealthy=%s blocked_rejected=%s", project.project.id, selection.blocked_busy, selection.blocked_unhealthy, selection.blocked_rejected)
            return False
        self._clear_log_state(f"project:{project.project.id}:worker:reason")
        claim = self.client.claim_reason(project.project.id, worker.name, trigger)
        detail = claim.data.get("detail") if isinstance(claim.data, dict) else None
        detail_code = detail.get("code") if isinstance(detail, dict) else None
        if claim.status_code == 409 and detail_code == "reason_state_unchanged":
            self.reason_checkpoints[project.project.id] = ReasonCheckpoint(
                fact_count=len(project.facts),
                hint_count=len(project.hints),
                open_intent_count=self._project_open_intent_count(project),
            )
            self._log_changed(
                f"project:{project.project.id}:reason-unchanged",
                logging.INFO,
                "reason suppressed for unchanged semantic state project=%s",
                project.project.id,
            )
            return False
        if claim.status_code in (403, 409) or not claim.ok:
            LOG.log(logging.INFO if claim.status_code == 403 else logging.WARNING, "reason claim failed project=%s worker=%s status=%s", project.project.id, worker.name, claim.status_code)
            return False
        try:
            future = self.executor.submit(
                run_reason_task, self.config, self.client, self.container_manager,
                project, export_yaml, worker, cancellation := TaskCancellation(), trigger,
            )
        except Exception:
            LOG.exception("failed to submit reason task project=%s worker=%s", project.project.id, worker.name)
            self._best_effort_release_reason(project.project.id, worker.name)
            return False
        self.futures[future] = RunningTask(
            project.project.id, "reason", worker.name, cancellation, intent_id=None,
            attempt_count=project.project.reason_attempt_count,
            fact_count=len(project.facts), hint_count=len(project.hints),
            open_intent_count=self._project_open_intent_count(project),
            trigger=trigger,
        )
        self.runtime_project_ids.add(project.project.id)
        self._clear_project_log_state(project.project.id)
        LOG.info("dispatched reason project=%s worker=%s trigger=%s", project.project.id, worker.name, trigger)
        return True

    def _dispatch_bootstrap(self, project: ProjectDetail, intent: Intent) -> bool:
        selection = self._select_worker(project.project.id, "bootstrap")
        worker = selection.worker
        if worker is None:
            self._log_changed(f"project:{project.project.id}:worker:bootstrap", logging.INFO, "no worker available for bootstrap project=%s intent=%s blocked_busy=%s blocked_unhealthy=%s blocked_rejected=%s", project.project.id, intent.id, selection.blocked_busy, selection.blocked_unhealthy, selection.blocked_rejected)
            return False
        self._clear_log_state(f"project:{project.project.id}:worker:bootstrap")
        claim = self.client.heartbeat(project.project.id, intent.id, worker.name)
        if claim.status_code in (403, 409) or not claim.ok:
            LOG.log(logging.INFO if claim.status_code == 403 else logging.WARNING, "bootstrap claim failed project=%s intent=%s worker=%s status=%s", project.project.id, intent.id, worker.name, claim.status_code)
            return False
        try:
            future = self.executor.submit(
                run_bootstrap_task, self.config, self.client, self.container_manager,
                project, intent, worker, cancellation := TaskCancellation(),
            )
        except Exception:
            LOG.exception("failed to submit bootstrap task project=%s intent=%s worker=%s", project.project.id, intent.id, worker.name)
            self._best_effort_release(project.project.id, intent.id, worker.name)
            return False
        self.futures[future] = RunningTask(
            project.project.id, "bootstrap", worker.name, cancellation,
            intent_id=intent.id, attempt_count=intent.attempt_count,
        )
        self.runtime_project_ids.add(project.project.id)
        self._clear_project_log_state(project.project.id)
        LOG.info("dispatched bootstrap project=%s intent=%s worker=%s", project.project.id, intent.id, worker.name)
        return True

    def _dispatch_explore(self, project: ProjectDetail, export_yaml: str, intent: Intent) -> bool:
        selection = self._select_worker(project.project.id, "explore")
        worker = selection.worker
        if worker is None:
            self._log_changed(f"project:{project.project.id}:worker:explore", logging.INFO, "no worker available for explore project=%s intent=%s blocked_busy=%s blocked_unhealthy=%s blocked_rejected=%s", project.project.id, intent.id, selection.blocked_busy, selection.blocked_unhealthy, selection.blocked_rejected)
            return False
        self._clear_log_state(f"project:{project.project.id}:worker:explore")
        claim = self.client.heartbeat(project.project.id, intent.id, worker.name)
        if claim.status_code in (403, 409) or not claim.ok:
            LOG.log(logging.INFO if claim.status_code == 403 else logging.WARNING, "explore claim failed project=%s intent=%s worker=%s status=%s", project.project.id, intent.id, worker.name, claim.status_code)
            return False
        try:
            future = self.executor.submit(
                run_explore_task, self.config, self.client, self.container_manager,
                project, export_yaml, intent, worker, cancellation := TaskCancellation(),
            )
        except Exception:
            LOG.exception("failed to submit explore task project=%s intent=%s worker=%s", project.project.id, intent.id, worker.name)
            self._best_effort_release(project.project.id, intent.id, worker.name)
            return False
        self.futures[future] = RunningTask(
            project.project.id, "explore", worker.name, cancellation,
            intent_id=intent.id, attempt_count=intent.attempt_count,
        )
        self.runtime_project_ids.add(project.project.id)
        self._clear_project_log_state(project.project.id)
        LOG.info("dispatched explore project=%s intent=%s worker=%s", project.project.id, intent.id, worker.name)
        return True

    # ---- worker selection -------------------------------------------------------

    def _select_worker(self, project_id: str, task_type: str) -> WorkerSelection:
        now = time.time()
        candidates: list[WorkerConfig] = []
        blocked_busy: list[str] = []
        blocked_unhealthy: list[str] = []
        blocked_rejected: list[str] = []
        blocked_task_type: list[str] = []
        running_counts = self._worker_counts()
        for worker in self.config.workers:
            if task_type not in worker.task_types:
                blocked_task_type.append(worker.name)
                continue
            running = running_counts.get(worker.name, 0)
            if running >= worker.max_running:
                blocked_busy.append(f"{worker.name}({running}/{worker.max_running})")
                continue
            if worker.name in getattr(self, "startup_unhealthy_workers", set()):
                blocked_unhealthy.append(f"{worker.name}(startup)")
                continue
            if self.worker_unhealthy_until.get(worker.name, 0) > now:
                blocked_unhealthy.append(f"{worker.name}({self.worker_unhealthy_until[worker.name] - now:.1f}s)")
                continue
            if self.worker_rejected_until.get((project_id, task_type, worker.name), 0) > now:
                blocked_rejected.append(f"{worker.name}({self.worker_rejected_until[(project_id, task_type, worker.name)] - now:.1f}s)")
                continue
            candidates.append(worker)
        ordered = choose_worker(candidates, running_counts) if candidates else []
        return WorkerSelection(
            worker=ordered[0] if ordered else None,
            blocked_busy=blocked_busy,
            blocked_unhealthy=blocked_unhealthy,
            blocked_rejected=blocked_rejected,
            blocked_task_type=blocked_task_type,
        )

    def _worker_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for task in self.futures.values():
            counts[task.worker_name] = counts.get(task.worker_name, 0) + 1
        return counts

    def _project_running_task_count(self, project_id: str) -> int:
        return sum(1 for task in self.futures.values() if task.project_id == project_id)

    def _project_running_task_summary(self, project_id: str) -> list[str]:
        summary: list[str] = []
        for task in self.futures.values():
            if task.project_id != project_id:
                continue
            if task.intent_id is None:
                summary.append(f"{task.task_type}:{task.worker_name}")
            else:
                summary.append(f"{task.task_type}:{task.worker_name}:{task.intent_id}")
        summary.sort()
        return summary

    def _project_has_running_bootstrap(self, project_id: str) -> bool:
        return any(task.project_id == project_id and task.task_type == "bootstrap" for task in self.futures.values())

    def _project_running_explore_intents(self, project_id: str) -> set[str]:
        return {
            task.intent_id
            for task in self.futures.values()
            if task.project_id == project_id and task.task_type == "explore" and task.intent_id is not None
        }

    def _running_project_count(self, summaries: list[ProjectSummary]) -> int:
        active_ids = {summary.id for summary in summaries if summary.status == "active"}
        return len(self._live_project_ids() & active_ids)

    def _live_project_ids(self) -> set[str]:
        return {task.project_id for task in self.futures.values()}

    def _project_open_intent_count(self, project: ProjectDetail) -> int:
        return sum(1 for intent in project.intents if intent.to is None and intent.status == "open")

    # ---- bootstrap / initial-project helpers ------------------------------------

    def _is_bootstrap_intent(self, intent: Intent) -> bool:
        return (
            intent.description == BOOTSTRAP_INTENT_DESCRIPTION
            and intent.creator == BOOTSTRAP_INTENT_CREATOR
            and intent.from_ == ["origin"]
            and intent.to is None
        )

    def _get_bootstrap_intent(self, project: ProjectDetail) -> Intent | None:
        intents = [
            intent for intent in project.intents
            if self._is_bootstrap_intent(intent) and intent.status == "open"
        ]
        if not intents:
            return None
        intents.sort(key=lambda intent: (intent.worker is not None, intent.created_at, intent.id))
        return intents[0]

    def _is_initial_project(self, project: ProjectDetail) -> bool:
        if project.project.completion_blocked_at is not None:
            return False
        fact_ids = {fact.id for fact in project.facts}
        if fact_ids != {"origin", "goal"} or len(project.facts) != 2:
            return False
        if not project.intents:
            return True
        return all(self._is_bootstrap_intent(intent) for intent in project.intents) and any(
            intent.status == "open" for intent in project.intents
        )

    def _project_requires_bootstrap(self, project: ProjectDetail) -> bool:
        if not project.project.bootstrap_enabled:
            return False
        bootstrap_intents = [intent for intent in project.intents if self._is_bootstrap_intent(intent)]
        if bootstrap_intents:
            return any(intent.status == "open" for intent in bootstrap_intents)
        return any("bootstrap" in worker.task_types for worker in self.config.workers)

    def _create_bootstrap_intent(self, project_id: str) -> Intent | None:
        response = self.client.create_intent(project_id, ["origin"], BOOTSTRAP_INTENT_DESCRIPTION, BOOTSTRAP_INTENT_CREATOR)
        if response.status_code == 403:
            return None
        if not response.ok or not isinstance(response.data, dict):
            LOG.warning("bootstrap intent write failed project=%s status=%s", project_id, response.status_code)
            return None
        intent = Intent.model_validate(response.data)
        LOG.info("created bootstrap intent project=%s intent=%s", project_id, intent.id)
        return intent

    # ---- RECON gate (real-website mode) -----------------------------------------

    def _recon_gate_check(self, project: ProjectDetail) -> bool:
        """Check if all profile-required recon categories have been executed."""
        if project.project.phase != "recon":
            return True

        status = check_recon_executed(project.facts, profile=project.project.recon_profile)
        if not status.all_executed:
            self._log_changed(
                f"project:{project.project.id}:recon-gate",
                logging.INFO,
                "RECON gate not passed project=%s target_type=%s missing_executions=%s",
                project.project.id,
                project.project.recon_profile.target_type,
                status.missing_executions,
            )
            return False

        self._clear_log_state(f"project:{project.project.id}:recon-gate")
        self._try_extract_potential_targets(project)
        LOG.info(
            "RECON gate passed project=%s target_type=%s required_categories=%s",
            project.project.id,
            project.project.recon_profile.target_type,
            status.required_categories,
        )
        return True

    def _try_extract_potential_targets(self, project: ProjectDetail) -> None:
        pid = project.project.id
        source_facts = [fact for fact in project.facts if fact.goal_type != "potential_target"]
        targets = extract_potential_targets(source_facts)
        if not targets:
            return
        existing = {
            _potential_target_key(fact.description)
            for fact in project.facts
            if fact.goal_type == "potential_target"
        }
        written = 0
        for target in targets:
            key = _potential_target_key(target.description)
            if key in existing:
                continue
            result = self.client.create_fact_direct(
                pid,
                description=target.description,
                goal_type="potential_target",
                status="pending",
            )
            if result.ok:
                existing.add(key)
                written += 1
            else:
                LOG.warning("failed to write potential target fact project=%s status=%s", pid, result.status_code)
        if written:
            LOG.info("extracted %d potential targets project=%s", written, pid)

    # ---- reason re-trigger (stigmergy checkpoint) -------------------------------

    def _reason_trigger(self, project: ProjectDetail) -> str | None:
        if project.project.reason_next_retry_at is not None and project.project.reason_next_retry_at > utcnow():
            return None
        open_intent_count = self._project_open_intent_count(project)

        checkpoint = self.reason_checkpoints.get(project.project.id)
        if checkpoint is None:
            return "initial"
        changes: list[str] = []
        if len(project.facts) > checkpoint.fact_count:
            changes.append(f"facts:{checkpoint.fact_count}->{len(project.facts)}")
        if len(project.hints) > checkpoint.hint_count:
            changes.append(f"hints:{checkpoint.hint_count}->{len(project.hints)}")
        if checkpoint.open_intent_count > 0 and open_intent_count == 0:
            changes.append(f"open_intents:{checkpoint.open_intent_count}->0")
        if not changes:
            return None
        return ",".join(changes)

    # ---- future / cleanup reaping -----------------------------------------------

    def _reap_futures(self) -> None:
        done = [future for future in self.futures if future.done()]
        for future in done:
            task = self.futures.pop(future)
            try:
                outcome = future.result()
                if outcome == "cancelled":
                    LOG.info("task cancelled project=%s task=%s worker=%s", task.project_id, task.task_type, task.worker_name)
                elif outcome not in ("success", "completion_blocked", "stalled"):
                    LOG.warning("task finished project=%s task=%s worker=%s outcome=%s", task.project_id, task.task_type, task.worker_name, outcome)
                elif outcome == "completion_blocked":
                    LOG.info("task finished project=%s task=%s worker=%s outcome=completion_blocked", task.project_id, task.task_type, task.worker_name)
                elif outcome == "stalled":
                    LOG.info("task finished project=%s task=%s worker=%s outcome=stalled", task.project_id, task.task_type, task.worker_name)
                self._clear_project_log_state(task.project_id)
                if outcome == "unhealthy":
                    self.worker_unhealthy_until[task.worker_name] = time.time() + UNHEALTHY_RETRY_AFTER_SECONDS
                    LOG.info("worker marked unhealthy worker=%s retry_after=%.0fs", task.worker_name, UNHEALTHY_RETRY_AFTER_SECONDS)
                else:
                    self.worker_unhealthy_until.pop(task.worker_name, None)
                rejection_key = (task.project_id, task.task_type, task.worker_name)
                if outcome == "rejected":
                    self.worker_rejected_until[rejection_key] = time.time() + REJECTED_RETRY_AFTER_SECONDS
                    LOG.info("worker marked rejected project=%s task=%s worker=%s retry_after=%.0fs", task.project_id, task.task_type, task.worker_name, REJECTED_RETRY_AFTER_SECONDS)
                else:
                    self.worker_rejected_until.pop(rejection_key, None)
                if outcome in ("success", "stalled", "completion_blocked") and task.task_type == "reason":
                    self._record_reason_success(task)
                    refreshed = self.client.get_project(task.project_id)
                    self.reason_checkpoints[task.project_id] = ReasonCheckpoint(
                        fact_count=len(refreshed.facts),
                        hint_count=len(refreshed.hints),
                        open_intent_count=self._project_open_intent_count(refreshed),
                    )
                elif outcome in RETRYABLE_OUTCOMES:
                    self._record_task_failure(task, outcome)
            except Exception:
                LOG.exception("task crashed project=%s task=%s worker=%s", task.project_id, task.task_type, task.worker_name)
                self._record_task_failure(task, "crashed")

    def _record_task_failure(self, task: RunningTask, outcome: str) -> None:
        backoff_seconds = _retry_backoff_seconds(task.attempt_count)
        if task.task_type == "reason":
            response = self.client.record_reason_failure(
                task.project_id,
                task.worker_name,
                outcome,
                max_attempts=MAX_TASK_ATTEMPTS,
                backoff_seconds=backoff_seconds,
            )
            if response.ok:
                LOG.info(
                    "recorded reason failure project=%s worker=%s outcome=%s attempt=%s backoff=%ss",
                    task.project_id, task.worker_name, outcome, task.attempt_count + 1, backoff_seconds,
                )
            else:
                LOG.warning(
                    "failed to record reason failure project=%s worker=%s outcome=%s status=%s body=%s",
                    task.project_id, task.worker_name, outcome, response.status_code, response.text,
                )
            return

        if task.intent_id is None:
            return
        response = self.client.record_intent_failure(
            task.project_id,
            task.intent_id,
            task.worker_name,
            outcome,
            max_attempts=MAX_TASK_ATTEMPTS,
            backoff_seconds=backoff_seconds,
        )
        if response.ok:
            LOG.info(
                "recorded intent failure project=%s intent=%s worker=%s outcome=%s attempt=%s backoff=%ss",
                task.project_id, task.intent_id, task.worker_name, outcome, task.attempt_count + 1, backoff_seconds,
            )
        else:
            LOG.warning(
                "failed to record intent failure project=%s intent=%s worker=%s outcome=%s status=%s body=%s",
                task.project_id, task.intent_id, task.worker_name, outcome, response.status_code, response.text,
            )

    def _record_reason_success(self, task: RunningTask) -> None:
        response = self.client.record_reason_success(task.project_id, task.worker_name)
        if response.ok:
            return
        LOG.warning(
            "failed to clear reason failure state project=%s worker=%s status=%s body=%s",
            task.project_id, task.worker_name, response.status_code, response.text,
        )

    def _cleanup_completed_containers(self, summaries: list[ProjectSummary]) -> None:
        for summary in summaries:
            if summary.status != "completed" or self._inactive_cleanup_done.get(summary.id) == summary.status:
                continue
            container_name = self.container_manager.container_name(summary.id)
            if container_name in self._cleanup_pending:
                continue
            if not self.container_manager.needs_completed_cleanup(summary.id):
                self._inactive_cleanup_done[summary.id] = summary.status
                continue
            future = self.cleanup_executor.submit(self.container_manager.cleanup_completed, summary.id)
            self.cleanup_futures[future] = (container_name, summary.id, summary.status)
            self._cleanup_pending.add(container_name)

    def _cleanup_stopped_containers(self, summaries: list[ProjectSummary]) -> None:
        for summary in summaries:
            if summary.status != "stopped" or self._inactive_cleanup_done.get(summary.id) == summary.status:
                continue
            container_name = self.container_manager.container_name(summary.id)
            if container_name in self._cleanup_pending:
                continue
            if not self.container_manager.needs_stopped_cleanup(summary.id):
                self._inactive_cleanup_done[summary.id] = summary.status
                continue
            future = self.cleanup_executor.submit(self.container_manager.cleanup_stopped, summary.id)
            self.cleanup_futures[future] = (container_name, summary.id, summary.status)
            self._cleanup_pending.add(container_name)

    def _queue_container_cleanups(self, summaries: list[ProjectSummary]) -> None:
        self._cleanup_completed_containers(summaries)
        self._cleanup_stopped_containers(summaries)

    def _reap_cleanup_futures(self) -> None:
        done = [future for future in self.cleanup_futures if future.done()]
        for future in done:
            name, project_id, target_status = self.cleanup_futures.pop(future)
            self._cleanup_pending.discard(name)
            try:
                success = future.result()
                if success and project_id is not None and target_status in ("completed", "stopped"):
                    self._inactive_cleanup_done[project_id] = target_status
                elif project_id is not None:
                    self._inactive_cleanup_done.pop(project_id, None)
            except Exception:
                if project_id is not None:
                    self._inactive_cleanup_done.pop(project_id, None)
                LOG.exception("container cleanup failed container=%s", name)

    def _refresh_runtime_projects(self, summaries: list[ProjectSummary]) -> None:
        active_ids = {summary.id for summary in summaries if summary.status == "active"}
        self.runtime_project_ids.intersection_update(active_ids)
        inactive_status_by_id = {summary.id: summary.status for summary in summaries if summary.status != "active"}
        for project_id, status in list(self._inactive_cleanup_done.items()):
            if inactive_status_by_id.get(project_id) != status:
                self._inactive_cleanup_done.pop(project_id, None)

    def _cancel_inactive_tasks(self, summaries: list[ProjectSummary]) -> None:
        status_by_project = {summary.id: summary.status for summary in summaries}
        for task in self.futures.values():
            status = status_by_project.get(task.project_id, "deleted")
            if status != "active" and task.cancellation.cancel(status):
                LOG.info("cancelling running task for inactive project project=%s task=%s worker=%s status=%s", task.project_id, task.task_type, task.worker_name, status)

    def _initialize_reason_checkpoints(self, summaries: list[ProjectSummary]) -> None:
        for summary in summaries:
            if summary.status != "active" or summary.id in self.reason_checkpoints:
                continue
            open_intent_count = summary.working_intent_count + summary.unclaimed_intent_count
            if open_intent_count == 0:
                continue
            self.reason_checkpoints[summary.id] = ReasonCheckpoint(summary.fact_count, summary.hint_count, open_intent_count)

    # ---- best-effort releases / logging -----------------------------------------

    def _best_effort_release(self, project_id: str, intent_id: str, worker_name: str) -> None:
        response = self.client.release(project_id, intent_id, worker_name)
        if not response.ok and response.status_code not in (403, 409):
            LOG.warning("release failed project=%s intent=%s worker=%s status=%s", project_id, intent_id, worker_name, response.status_code)

    def _best_effort_release_reason(self, project_id: str, worker_name: str) -> None:
        response = self.client.release_reason(project_id, worker_name)
        if not response.ok and response.status_code not in (403, 409):
            LOG.warning("reason release failed project=%s worker=%s status=%s", project_id, worker_name, response.status_code)

    def _log_changed(self, scope: str, level: int, message: str, *args: object) -> None:
        state = (level, message, args)
        if self._log_state.get(scope) == state:
            return
        self._log_state[scope] = state
        LOG.log(level, message, *args)

    def _clear_log_state(self, scope: str) -> None:
        self._log_state.pop(scope, None)

    def _clear_project_log_state(self, project_id: str) -> None:
        prefix = f"project:{project_id}:"
        for scope in list(self._log_state):
            if scope.startswith(prefix):
                self._log_state.pop(scope, None)

    def _validate_server_settings(self) -> None:
        settings = self.client.get_settings()
        interval = self.config.runtime.interval
        for name, value in (("intent_timeout", settings.intent_timeout), ("reason_timeout", settings.reason_timeout)):
            if value <= interval:
                raise RuntimeError(f"server {name}={value}s must be greater than dispatcher interval={interval}s")
            if value < interval * 2:
                LOG.warning("server %s is tight %s=%ss interval=%ss; heartbeat slack is only %ss", name, name, value, interval, value - interval)

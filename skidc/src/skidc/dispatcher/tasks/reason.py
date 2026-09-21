from __future__ import annotations

import json
import hashlib
import logging
import time
from dataclasses import asdict
from urllib.parse import urlparse

from skidc.dispatcher.config import DispatchConfig, WorkerConfig
from skidc.dispatcher.coverage_profile import (
    bind_profile_to_intent,
    build_profile_for_surfaces,
    build_web_coverage_profile,
    normalize_surface_entry,
    normalize_surface_map,
)
from skidc.dispatcher.contracts import (
    extract_reason_handoff,
    parse_json_output,
    validate_reason_payload,
)
from skidc.dispatcher.recon_extractor import check_recon_executed, format_recon_status
from skidc.dispatcher.prompting import (
    format_dispatch_graph,
    format_fact_ids,
    format_open_intents,
    format_scope_constraints,
    load_prompt,
    render_prompt,
)
from skidc.dispatcher.protocol.client import SkidcClient
from skidc.dispatcher.runtime.cancellation import TaskCancellation
from skidc.dispatcher.runtime.containers import ContainerManager
from skidc.dispatcher.runtime.heartbeat import HeartbeatLease
from skidc.dispatcher.tasks.common import (
    best_effort_release_reason,
    cancel_reason,
    did_timeout,
    format_worker_input,
    preview,
    run_healthcheck,
    run_worker_process,
    save_task_log,
    task_healthcheck_enabled,
    write_graph_snapshot_reference,
)
from skidc.dispatcher.workers.registry import get_driver
from skidc.server.models import ProjectDetail
from skidc.planning import behavior_identity, derive_candidates, select_round

LOG = logging.getLogger(__name__)


def run_reason_task(
    config: DispatchConfig,
    client: SkidcClient,
    container_manager: ContainerManager,
    project: ProjectDetail,
    export_yaml: str,
    worker: WorkerConfig,
    cancellation: TaskCancellation,
    trigger: str | None = None,
) -> str:
    driver = get_driver(worker.type)
    task_started = time.perf_counter()
    healthcheck_timeout = config.runtime.healthcheck_timeout
    lease = HeartbeatLease.for_reason(client, project.project.id, worker.name, config.runtime.interval)
    lease.start()
    try:
        container_name = container_manager.ensure_running(project.project.id)

        if task_healthcheck_enabled(config):
            healthcheck = run_healthcheck(
                container_manager,
                container_name,
                worker,
                driver.build_healthcheck(worker),
                timeout_seconds=healthcheck_timeout,
                lease=lease,
                cancellation=cancellation,
            )
            cancelled = cancel_reason(healthcheck.result, cancellation)
            if cancelled is not None:
                LOG.info("reason cancelled during healthcheck project=%s worker=%s reason=%s", project.project.id, worker.name, cancelled)
                return "cancelled"
            if lease.failure is not None:
                LOG.warning("heartbeat lost during reason healthcheck project=%s worker=%s status=%s", project.project.id, worker.name, lease.failure.status_code)
                return "failed"
            if healthcheck.result.returncode != 0:
                LOG.warning("worker unhealthy project=%s worker=%s healthcheck_ms=%s stderr=%s", project.project.id, worker.name, healthcheck.duration_ms, preview(healthcheck.result.stderr))
                return "unhealthy"

        open_intents = [
            {"id": intent.id, "from": intent.from_, "description": intent.description, "worker": intent.worker}
            for intent in project.intents
            if intent.to is None and intent.status == "open"
        ]
        allowed_fact_ids = [fact.id for fact in project.facts if fact.id != "goal"]
        current_phase = project.project.phase
        sub_goals = [
            f"- {fact.id}: {fact.description} (status: {fact.status or 'pending'})"
            for fact in project.facts
            if fact.goal_type == "potential_target"
        ]
        sub_goals_text = "\n".join(sub_goals) if sub_goals else "(none)"
        recon_status_obj = check_recon_executed(project.facts, profile=project.project.recon_profile)
        recon_status_text = format_recon_status(recon_status_obj)
        prompt = render_prompt(
            load_prompt(config.runtime.prompt_group, "reason.md"),
            {
                "current_phase": current_phase,
                "scope_constraints": format_scope_constraints(project),
                "recon_status": recon_status_text,
                "sub_goals": sub_goals_text,
                "graph_yaml": write_graph_snapshot_reference(
                    container_manager,
                    container_name,
                    format_dispatch_graph(project)
                    if project.project.planning_version >= 3
                    else export_yaml.strip(),
                    phase="reason_execute",
                ),
                "fact_ids": format_fact_ids(allowed_fact_ids),
                "open_intents": format_open_intents(open_intents),
                "max_intents": str(config.tasks.reason.max_intents),
            },
        )

        session = driver.prepare_session()
        command = driver.build_execute(worker, prompt, session)
        execute_started = time.perf_counter()
        result = run_worker_process(
            container_manager,
            container_name,
            worker,
            command.argv,
            phase="reason_execute",
            timeout_seconds=config.tasks.reason.timeout,
            lease=lease,
            cancellation=cancellation,
        )
        execute_ms = int((time.perf_counter() - execute_started) * 1000)
        save_task_log(
            client, project.project.id, "reason", worker.name, "reason_execute",
            result, execute_ms,
            stdin=format_worker_input(
                prompt,
                command.argv,
                task_type="reason",
                phase="reason_execute",
                worker_name=worker.name,
                operation="reason over current graph and decide completion or next intents",
                project_id=project.project.id,
                timeout_seconds=config.tasks.reason.timeout,
            ),
        )
        total_ms = int((time.perf_counter() - task_started) * 1000)
        cancelled = cancel_reason(result, cancellation)
        if cancelled is not None:
            LOG.info("reason cancelled project=%s worker=%s reason=%s execute_ms=%s", project.project.id, worker.name, cancelled, execute_ms)
            return "cancelled"
        if lease.failure is not None:
            LOG.warning("heartbeat lost during reason project=%s worker=%s status=%s execute_ms=%s", project.project.id, worker.name, lease.failure.status_code, execute_ms)
            return "failed"
        if did_timeout(result):
            LOG.warning("reason timed out project=%s worker=%s execute_ms=%s total_ms=%s stdout=%s stderr=%s", project.project.id, worker.name, execute_ms, total_ms, preview(result.stdout), preview(result.stderr))
            return "failed"
        if result.returncode != 0:
            LOG.warning("reason command failed project=%s worker=%s code=%s execute_ms=%s stdout=%s stderr=%s", project.project.id, worker.name, result.returncode, execute_ms, preview(result.stdout), preview(result.stderr))
            return "failed"
        try:
            model_output = driver.extract_response_text(result.stdout, result.stderr)
            payload = parse_json_output(model_output)
            kind, data, recon_complete = validate_reason_payload(
                payload,
                open_intents_empty=not open_intents,
                max_intents=config.tasks.reason.max_intents,
            )
        except Exception as exc:
            LOG.warning("reason parse failed project=%s worker=%s error=%s execute_ms=%s stdout=%s stderr=%s", project.project.id, worker.name, exc, execute_ms, preview(result.stdout), preview(result.stderr))
            return "failed"
        if kind == "rejected":
            LOG.warning("reason rejected project=%s worker=%s execute_ms=%s stdout=%s", project.project.id, worker.name, execute_ms, preview(result.stdout))
            return "rejected"
        if project.project.phase == "recon":
            gate_status = check_recon_executed(
                project.facts, profile=project.project.recon_profile
            )
            recon_complete = gate_status.all_executed
            if recon_complete and kind == "complete":
                kind = "noop"
                data = None
        coverage_index = {_coverage_key(item.model_dump()): item.id for item in project.coverage_items}
        handoff_fact_ids = _persist_reason_handoff(
            client,
            project.project.id,
            worker.name,
            extract_reason_handoff(payload),
            coverage_index=coverage_index,
            real_website=project.project.mode == "real_website",
            materialize_coverage=(
                project.project.mode == "real_website" and project.project.planning_version < 2
            ),
            support_ports=project.project.scope_policy.support_ports,
        )

        if (
            kind == "complete"
            and project.project.mode == "real_website"
            and project.project.planning_version >= 3
            and project.project.phase == "explore"
        ):
            breadth_budget = min(
                project.project.recon_profile.frontier_breadth_slots,
                config.tasks.reason.max_intents,
            )
            mapping_created = (
                _ensure_pending_surface_mapping_work(
                    client, project, worker.name, max_items=breadth_budget
                )
                if breadth_budget
                else 0
            )
            if mapping_created:
                LOG.info(
                    "reason completion deferred for pending surface mapping project=%s intents=%s",
                    project.project.id, mapping_created,
                )
                return "success"
        if kind == "complete":
            response = client.complete(project.project.id, data["from"], data["description"], worker.name)
            if response.status_code == 403:
                LOG.info("project became inactive during reason complete project=%s worker=%s", project.project.id, worker.name)
                return "success"
            if _is_completion_blocked_response(response):
                LOG.info(
                    "reason completion blocked project=%s worker=%s blockers=%s",
                    project.project.id,
                    worker.name,
                    _completion_blocker_count(response),
                )
                return "failed"
            if not response.ok:
                LOG.warning("reason complete write failed project=%s worker=%s status=%s body=%s", project.project.id, worker.name, response.status_code, response.text)
                return "failed"
            LOG.info("project completed project=%s worker=%s from=%s execute_ms=%s total_ms=%s", project.project.id, worker.name, data["from"], execute_ms, total_ms)
            return "success"
        if kind == "intents":
            created = 0
            v3_frontier = (
                project.project.mode == "real_website"
                and project.project.planning_version >= 3
                and project.project.phase == "explore"
            )
            frontier_created = 0
            defer_to_baseline = (
                project.project.mode == "real_website"
                and project.project.phase == "recon"
                and recon_complete
            )
            use_hypothesis_planner = (
                project.project.mode == "real_website"
                and project.project.planning_version == 2
                and (project.project.phase == "explore" or recon_complete)
            )
            intent_batch = [] if defer_to_baseline or use_hypothesis_planner else data
            had_pending_behavior = False
            if v3_frontier:
                had_pending_behavior = any(
                    surface.planning_status == "pending"
                    and not surface.traits.get("out_of_scope_support")
                    for surface in project.surface_inventory
                )
                breadth_budget = min(
                    project.project.recon_profile.frontier_breadth_slots,
                    config.tasks.reason.max_intents,
                )
                if breadth_budget:
                    frontier_created = _ensure_pending_surface_mapping_work(
                        client, project, worker.name, max_items=breadth_budget,
                    )
                remaining = max(0, config.tasks.reason.max_intents - frontier_created)
                raw_candidates = list(data)
                if frontier_created:
                    raw_candidates = [
                        item for item in raw_candidates
                        if _clean_signature_text(item.get("test_variant")) != "function_mapping"
                    ]
                intent_batch = _select_v3_frontier(project, raw_candidates, max_items=remaining)
                created = frontier_created
            signatures = _existing_intent_signatures(project)
            for raw_intent_data in intent_batch:
                if v3_frontier:
                    if _create_agent_hypothesis_work(
                        client, project, worker.name, raw_intent_data
                    ):
                        created += 1
                    continue
                intent_data = _bind_matching_coverage(project, raw_intent_data)
                signature = _intent_signature_from_data(project, intent_data)
                if signature in signatures:
                    LOG.info(
                        "reason skipped duplicate intent project=%s coverage=%s variant=%s action=%s",
                        project.project.id,
                        signature[0],
                        signature[1],
                        signature[-1],
                    )
                    continue
                coverage_refs = _optional_str_list(intent_data, "coverage_refs")
                response = client.create_intent(
                    project.project.id,
                    intent_data["from"],
                    intent_data["description"],
                    worker.name,
                    target=_optional_str(intent_data, "target"),
                    port=_optional_int(intent_data, "port"),
                    path=_optional_str(intent_data, "path"),
                    surface_type=_optional_str(intent_data, "surface_type"),
                    action_kind=_optional_str(intent_data, "action_kind"),
                    test_variant=_optional_str(intent_data, "test_variant"),
                    priority=_optional_int(intent_data, "priority"),
                    suggested_tools=_optional_str_list(intent_data, "suggested_tools"),
                    coverage_refs=coverage_refs,
                )
                if response.status_code == 403:
                    LOG.info("project became inactive during reason intent create project=%s worker=%s created=%s", project.project.id, worker.name, created)
                    return "success"
                if response.status_code == 409:
                    LOG.info("reason intent lost race project=%s worker=%s from=%s", project.project.id, worker.name, intent_data["from"])
                    continue
                if not response.ok:
                    LOG.warning("reason intent write failed project=%s worker=%s status=%s body=%s", project.project.id, worker.name, response.status_code, response.text)
                    continue
                created += 1
                if signature is not None:
                    signatures.add(signature)
                intent_id = _response_id(response)
                if intent_id and (
                    project.project.mode != "real_website"
                    or project.project.phase == "recon"
                    or not coverage_refs
                ):
                    if project.project.mode == "real_website":
                        coverage_items = _profile_coverage_from_seed(
                            client,
                            project.project.id,
                            intent_data,
                            support_ports=project.project.scope_policy.support_ports,
                            source_fact_id=handoff_fact_ids.get("explore_seed_deck"),
                            intent_id=intent_id,
                        )
                    else:
                        coverage_items = _coverage_from_seed_deck(
                            [intent_data],
                            source_fact_id=handoff_fact_ids.get("explore_seed_deck"),
                            intent_id=intent_id,
                        )
                    _create_coverage_items(
                        client,
                        project.project.id,
                        worker.name,
                        coverage_items,
                        coverage_index,
                    )
                LOG.info("reason created intent project=%s worker=%s from=%s description=%s", project.project.id, worker.name, intent_data["from"], intent_data["description"])

            baseline_created = 0
            if recon_complete and project.project.phase == "recon":
                baseline_created = _transition_to_explore_with_baseline(
                    client,
                    project,
                    worker.name,
                )
                if baseline_created == -2:
                    return "failed"
                if baseline_created < 0:
                    return "failed"
            elif use_hypothesis_planner and project.project.phase == "explore":
                baseline_created = ensure_coverage_work(
                    client, client.get_project(project.project.id), worker.name
                )
            if (
                v3_frontier
                and created == 0
                and baseline_created == 0
                and not intent_batch
                and not open_intents
                and not had_pending_behavior
            ):
                source_ids = _frontier_completion_sources(project)
                response = client.complete(
                    project.project.id,
                    source_ids,
                    "Adaptive frontier converged: no new evidence-backed, non-duplicate branch remains.",
                    worker.name,
                )
                if response.status_code == 403:
                    return "success"
                if response.ok:
                    LOG.info(
                        "project completed after frontier convergence project=%s sources=%s",
                        project.project.id,
                        source_ids,
                    )
                    return "success"
                LOG.warning(
                    "frontier convergence completion failed project=%s status=%s body=%s",
                    project.project.id,
                    response.status_code,
                    response.text,
                )
                return "failed"
            LOG.info(
                "reason finished project=%s worker=%s created_intents=%s/%s breadth_intents=%s baseline_intents=%s execute_ms=%s total_ms=%s",
                project.project.id,
                worker.name,
                created,
                len(intent_batch),
                frontier_created,
                baseline_created,
                execute_ms,
                total_ms,
            )
            if (
                project.project.planning_version >= 3
                and intent_batch and created == 0
            ):
                return "stalled"
            if created == 0 and baseline_created == 0 and not defer_to_baseline:
                LOG.info("reason produced only duplicate/no-op intents project=%s", project.project.id)
                return "stalled"
            return "success"

        if recon_complete and project.project.phase == "recon":
            baseline_created = _transition_to_explore_with_baseline(client, project, worker.name)
            if baseline_created == -2:
                return "failed"
            if baseline_created < 0:
                return "failed"
            return "success"

        LOG.info("reason finished without graph change project=%s worker=%s execute_ms=%s total_ms=%s", project.project.id, worker.name, execute_ms, total_ms)
        if project.project.planning_version == 2 and project.project.phase == "explore":
            created = ensure_coverage_work(client, client.get_project(project.project.id), worker.name)
            if created:
                return "success"
        return "stalled" if not open_intents else "success"
    finally:
        lease.stop()
        best_effort_release_reason(client, project.project.id, worker.name)


def _frontier_completion_sources(project: ProjectDetail, *, limit: int = 8) -> list[str]:
    """Choose terminal Facts that were actually produced by concluded Intents."""
    produced_fact_ids = {
        intent.to
        for intent in project.intents
        if intent.to not in (None, "goal")
        and intent.status == "concluded"
        and intent.concluded_at is not None
    }
    selected: list[str] = []
    preferred_statuses = {"confirmed", "verified"}
    terminal_statuses = preferred_statuses | {
        "completed",
        "not_vulnerable",
        "refuted",
        "failed",
        "inconclusive",
        "informational",
        "blocked_by_precondition",
    }
    for preferred_only in (True, False):
        for fact in reversed(project.facts):
            status = str(fact.status or "").casefold()
            if fact.id not in produced_fact_ids:
                continue
            if preferred_only and status not in preferred_statuses:
                continue
            if not preferred_only and status not in terminal_statuses:
                continue
            if fact.id not in selected:
                selected.append(fact.id)
            if len(selected) >= limit:
                return selected
    return selected



_VARIANT_FAMILY = {
    "default_credentials": "identity_auth",
    "auth_bypass": "identity_auth",
    "account_enumeration": "identity_auth",
    "idor": "authorization",
    "vertical_access": "authorization",
    "horizontal_access": "authorization",
    "cookie_session": "session_csrf",
    "csrf": "session_csrf",
    "sql": "injection",
    "command": "injection",
    "ssti": "injection",
    "upload": "file_path",
    "path_traversal": "file_path",
    "file_inclusion": "file_path",
    "ssrf": "server_side_processing",
    "xxe": "server_side_processing",
    "unsafe_template": "server_side_processing",
    "xss": "client_side",
    "cors": "client_side",
    "clickjacking": "client_side",
    "bola": "api_behavior",
    "bfla": "api_behavior",
    "mass_assignment": "api_behavior",
    "resource_consumption": "api_behavior",
    "workflow_integrity": "business_logic",
    "tls_transport": "crypto_transport",
}

_BASELINE_TOOLS = {
    "identity_auth": ["curl"],
    "authorization": ["curl"],
    "session_csrf": ["curl"],
    "injection": ["curl", "sqlmap"],
    "file_path": ["curl"],
    "server_side_processing": ["curl"],
    "client_side": ["curl"],
    "business_logic": ["curl"],
    "crypto_transport": ["curl", "openssl"],
    "api_behavior": ["curl"],
}


def _clean_signature_text(value: object) -> str:
    return str(value or "").strip().casefold()


def _clean_signature_path(value: object) -> str:
    text = str(value or "").strip()
    return text.split("?", 1)[0].casefold()


def _coverage_by_id(project: ProjectDetail) -> dict[str, object]:
    return {item.id: item for item in project.coverage_items}


def _intent_signature(
    *,
    coverage_ref: str | None,
    test_variant: str | None,
    target: str | None,
    port: int | None,
    path: str | None,
    action_kind: str | None,
) -> tuple[str, str, str, int, str, str] | None:
    signature = (
        _clean_signature_text(coverage_ref),
        _clean_signature_text(test_variant),
        _clean_signature_text(target),
        int(port or 0),
        _clean_signature_path(path),
        _clean_signature_text(action_kind),
    )
    # An all-empty signature is not an identity. Legacy/CTF reasoning may
    # legitimately create several descriptive Intents without structured web
    # metadata; collapsing them here would silently discard executable work.
    # Real-website Coverage work has at least a coverage ref/variant and is also
    # protected by the database-level work_key uniqueness constraint.
    return signature if any(signature) else None


def _existing_intent_signatures(project: ProjectDetail) -> set[tuple[str, str, str, int, str, str]]:
    coverage = _coverage_by_id(project)
    signatures: set[tuple[str, str, str, int, str, str]] = set()
    for intent in project.intents:
        coverage_ref = intent.coverage_refs[0] if intent.coverage_refs else None
        item = coverage.get(coverage_ref) if coverage_ref else None
        signature = _intent_signature(
            coverage_ref=coverage_ref,
            test_variant=intent.test_variant,
            target=intent.target or getattr(item, "target", None),
            port=intent.port or getattr(item, "port", None),
            path=intent.path or getattr(item, "path", None),
            action_kind=intent.action_kind,
        )
        if signature is not None:
            signatures.add(signature)
    return signatures


def _intent_signature_from_data(
    project: ProjectDetail,
    data: dict,
) -> tuple[str, str, str, int, str, str] | None:
    refs = _optional_str_list(data, "coverage_refs") or []
    coverage_ref = refs[0] if refs else None
    item = _coverage_by_id(project).get(coverage_ref) if coverage_ref else None
    return _intent_signature(
        coverage_ref=coverage_ref,
        test_variant=_optional_str(data, "test_variant"),
        target=_optional_str(data, "target") or getattr(item, "target", None),
        port=_optional_int(data, "port") or getattr(item, "port", None),
        path=_optional_str(data, "path") or getattr(item, "path", None),
        action_kind=_optional_str(data, "action_kind"),
    )


def _bind_matching_coverage(project: ProjectDetail, raw: dict) -> dict:
    data = dict(raw)
    if project.project.mode != "real_website" or _optional_str_list(data, "coverage_refs"):
        return data
    variant = _optional_str(data, "test_variant")
    family = _VARIANT_FAMILY.get(_clean_signature_text(variant))
    if not variant or family is None:
        return data
    target = _clean_signature_text(_optional_str(data, "target"))
    port = _optional_int(data, "port")
    path = _clean_signature_path(_optional_str(data, "path"))
    candidates: list[tuple[int, object]] = []
    for item in project.coverage_items:
        if item.test_family != family:
            continue
        if variant.casefold() not in {value.casefold() for value in item.test_variants}:
            continue
        if target and _clean_signature_text(item.target) not in {"", target}:
            continue
        if port and item.port not in {None, port}:
            continue
        item_path = _clean_signature_path(item.path)
        if path and item_path and path != item_path:
            continue
        score = int(bool(path and item_path == path)) * 4
        score += int(bool(target and _clean_signature_text(item.target) == target)) * 2
        score += int(bool(port and item.port == port))
        candidates.append((score, item))
    if not candidates:
        return data
    candidates.sort(key=lambda entry: (-entry[0], -(entry[1].priority or 0), entry[1].id))
    best_score = candidates[0][0]
    best = [item for score, item in candidates if score == best_score]
    if len(best) == 1 or best_score > 0:
        data["coverage_refs"] = [best[0].id]
    return data


def _coverage_variant_attempted(project: ProjectDetail, coverage_id: str, variant: str) -> bool:
    return any(
        coverage_id in intent.coverage_refs
        and _clean_signature_text(intent.test_variant) == variant.casefold()
        for intent in project.intents
    )


def _profile_unprofiled_surfaces(
    client: SkidcClient,
    project: ProjectDetail,
    worker_name: str,
) -> ProjectDetail:
    if project.project.mode != "real_website":
        return project
    known = {
        item.surface_fingerprint
        for item in project.coverage_items
        if item.surface_fingerprint
    }
    coverage_index = {_coverage_key(item.model_dump()): item.id for item in project.coverage_items}
    for surface in project.surface_inventory:
        if surface.fingerprint in known or surface.traits.get("out_of_scope_support"):
            continue
        items = build_web_coverage_profile(
            surface.model_dump(), source_fact_id=surface.source_fact_id
        )
        _create_coverage_items(client, project.project.id, worker_name, items, coverage_index)
    return client.get_project(project.project.id)


_AGENT_TEST_FAMILIES = {
    "surface_config", "identity_auth", "authorization", "session_csrf",
    "injection", "file_path", "server_side_processing", "client_side",
    "business_logic", "crypto_transport", "api_behavior", "support_service",
}
_DESTRUCTIVE_ACTION_TOKENS = {
    "delete", "drop", "truncate", "reset", "install", "uninstall",
    "password_change", "destructive", "wipe", "shutdown",
}


def _mark_behavior_assessed(
    client: SkidcClient,
    project: ProjectDetail,
    behavior_key: str,
) -> None:
    """Mark every observation of one canonical behavior as assessed."""
    for item in project.surface_inventory:
        if behavior_identity(item)[0] != behavior_key or item.planning_status == "assessed":
            continue
        payload = item.model_dump(exclude={"id", "created_at", "updated_at"})
        payload["planning_status"] = "assessed"
        response = client.upsert_surface_inventory(project.project.id, **payload)
        if not response.ok:
            LOG.warning(
                "behavior assessment update failed project=%s surface=%s status=%s",
                project.project.id, item.id, response.status_code,
            )


def _hypothesis_basis_fingerprint(
    behavior_key: str,
    family: str,
    variant: str,
    source_ids: list[str],
) -> str:
    basis = json.dumps(
        {"behavior_key": behavior_key, "test_family": family, "test_variant": variant, "from": sorted(source_ids)},
        ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def _matching_surface(project: ProjectDetail, data: dict):
    requested_behavior = str(data.get("behavior_key") or "").strip()
    requested_path = _clean_signature_path(data.get("path"))
    surface = next(
        (
            item for item in project.surface_inventory
            if requested_behavior and behavior_identity(item)[0] == requested_behavior
        ),
        None,
    )
    if surface is None and requested_path:
        surface = next(
            (item for item in project.surface_inventory if _clean_signature_path(item.path_template) == requested_path),
            None,
        )
    behavior_key = requested_behavior or (behavior_identity(surface)[0] if surface is not None else "")
    return surface, behavior_key, requested_path


def _create_agent_hypothesis_work(
    client: SkidcClient,
    project: ProjectDetail,
    worker_name: str,
    data: dict,
) -> bool:
    """Materialize one V3 Agent decision as Hypothesis -> Coverage -> Intent."""
    source_ids = _optional_str_list(data, "from") or []
    known_facts = {fact.id for fact in project.facts}
    if not source_ids or any(fact_id not in known_facts for fact_id in source_ids):
        LOG.warning("V3 intent rejected because its Fact basis is invalid: %s", source_ids)
        return False

    variant = _clean_signature_text(data.get("test_variant"))
    family = _clean_signature_text(data.get("test_family")) or _VARIANT_FAMILY.get(variant, "")
    if not variant or family not in _AGENT_TEST_FAMILIES:
        LOG.warning("V3 intent rejected because family/variant is incomplete: %s/%s", family, variant)
        return False

    surface, behavior_key, requested_path = _matching_surface(project, data)
    if surface is None:
        LOG.warning("V3 intent rejected because no normalized Surface matches behavior=%s path=%s", data.get("behavior_key"), requested_path)
        return False

    action_kind = _optional_str(data, "action_kind") or f"{family}_hypothesis"
    action_tokens = set(_clean_signature_text(action_kind).replace("-", "_").split("_"))
    destructive = (
        bool(action_tokens & _DESTRUCTIVE_ACTION_TOKENS)
        or _clean_signature_text(data.get("risk_level")) == "destructive"
    )
    if destructive and not project.project.scope_policy.allow_destructive:
        LOG.warning("V3 destructive intent rejected project=%s action=%s", project.project.id, action_kind)
        return False

    rationale = str(data.get("hypothesis") or data.get("rationale") or data.get("description") or "").strip()
    if not rationale:
        return False
    confidence = _bounded_float(data.get("confidence"), default=0.5, minimum=0.0, maximum=1.0)
    impact = _bounded_float(data.get("impact"), default=1.0, minimum=0.0, maximum=5.0)
    goal_value = _bounded_float(data.get("goal_value"), default=1.0, minimum=0.5, maximum=1.5)
    novelty = _bounded_float(data.get("novelty"), default=1.0, minimum=0.0, maximum=1.5)
    estimated_cost = _bounded_float(data.get("estimated_cost"), default=1.0, minimum=0.1, maximum=10.0)
    score = _bounded_float(
        data.get("_frontier_score"),
        default=confidence * impact * 2.0 / estimated_cost,
        minimum=0.0, maximum=100.0,
    )
    basis_fingerprint = _hypothesis_basis_fingerprint(
        behavior_key, family, variant, source_ids,
    )
    priority = _optional_int(data, "priority") or max(1, min(10, int(round(score * 2))))
    hypothesis_payload = {
        "behavior_key": behavior_key,
        "test_family": family,
        "test_variant": variant,
        "rationale": rationale,
        "trigger_fact_ids": source_ids,
        "confidence": confidence,
        "impact": impact,
        "goal_value": goal_value,
        "novelty": novelty,
        "estimated_cost": estimated_cost,
        "score": score,
        "required": True,
        "status": "candidate",
        "basis_fingerprint": basis_fingerprint,
    }
    coverage_payload = {
        "item_type": "route",
        "description": f"Hypothesis: {rationale}",
        "target": surface.target,
        "port": surface.port,
        "method": surface.method,
        "path": surface.path_template,
        "param": _optional_str(data, "param"),
        "priority": priority,
        "source_fact_id": source_ids[0],
        "surface_group": surface.surface_group,
        "surface_fingerprint": surface.fingerprint,
        "test_family": family,
        "test_variants": [variant],
        "auth_context": surface.auth_context,
        "roles": surface.roles,
        "applicability_reason": rationale,
        "applicability_status": "applicable",
        "required": True,
        "execution_status": "untested",
    }
    intent_payload = {
        "from": source_ids,
        "description": str(data.get("description") or rationale),
        "creator": worker_name,
        "worker": None,
        "target": surface.target,
        "port": surface.port,
        "path": surface.path_template,
        "surface_type": surface.surface_type,
        "action_kind": action_kind,
        "test_variant": variant,
        "priority": priority,
        "suggested_tools": (
            _optional_str_list(data, "suggested_tools")
            or _BASELINE_TOOLS.get(family, ["curl"])
        ),
    }
    surface_ids = [
        item.id
        for item in project.surface_inventory
        if behavior_identity(item)[0] == behavior_key
    ]
    response = client.materialize_hypothesis_work(
        project.project.id,
        hypothesis=hypothesis_payload,
        coverage=coverage_payload,
        intent=intent_payload,
        surface_ids=surface_ids,
    )
    if not response.ok:
        LOG.warning(
            "V3 atomic hypothesis materialization failed project=%s behavior=%s status=%s body=%s",
            project.project.id,
            behavior_key,
            response.status_code,
            response.text[:500],
        )
        return False
    if isinstance(response.data, dict):
        return bool(response.data.get("created", True))
    return True


def _bounded_float(value: object, *, default: float, minimum: float, maximum: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


_CONCLUSIVE_HYPOTHESIS_STATUSES = {"supported", "refuted"}
_NO_PROGRESS_HYPOTHESIS_STATUSES = {"inconclusive", "blocked_by_precondition"}


def _semantic_fact_payload(fact) -> dict:
    return {
        "kind": fact.kind,
        "summary": fact.summary or fact.description[:320],
        "subject": fact.subject,
        "data": fact.data,
        "status": fact.status,
        "vuln_type": fact.vuln_type,
        "severity": fact.severity,
        "evidence_refs": fact.evidence_refs,
    }


def _branch_evidence_basis(
    project: ProjectDetail,
    behavior_key: str,
    family: str,
    source_ids: list[str],
) -> str:
    fact_index = {fact.id: fact for fact in project.facts}
    evidence = [
        _semantic_fact_payload(fact_index[fact_id])
        for fact_id in sorted(set(source_ids))
        if fact_id in fact_index
    ]
    payload = json.dumps(
        {"behavior_key": behavior_key, "test_family": family, "evidence": evidence},
        ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def _hypothesis_branch_basis(project: ProjectDetail, hypothesis) -> str:
    return _branch_evidence_basis(
        project,
        hypothesis.behavior_key,
        hypothesis.test_family,
        hypothesis.trigger_fact_ids,
    )


def _evidence_confidence_cap(project: ProjectDetail, source_ids: list[str]) -> float:
    fact_index = {fact.id: fact for fact in project.facts}
    cap = 0.45
    for fact_id in source_ids:
        fact = fact_index.get(fact_id)
        if fact is None:
            continue
        status = str(fact.status or "").casefold()
        if fact.evidence_refs or status in {
            "confirmed", "verified", "vulnerable", "not_vulnerable", "supported", "refuted",
        }:
            cap = max(cap, 1.0)
        elif fact.kind == "execution_result":
            cap = max(cap, 0.85 if status not in {"failed", "inconclusive"} else 0.7)
        elif fact.data or fact.subject:
            cap = max(cap, 0.75)
        else:
            cap = max(cap, 0.55)
    return cap


def _frontier_candidate(project: ProjectDetail, data: dict) -> dict | None:
    source_ids = _optional_str_list(data, "from") or []
    known_facts = {fact.id for fact in project.facts}
    if not source_ids or any(fact_id not in known_facts for fact_id in source_ids):
        return None
    variant = _clean_signature_text(data.get("test_variant"))
    family = _clean_signature_text(data.get("test_family")) or _VARIANT_FAMILY.get(variant, "")
    if not variant or family not in _AGENT_TEST_FAMILIES:
        return None
    surface, behavior_key, _requested_path = _matching_surface(project, data)
    if surface is None or not behavior_key:
        return None

    branch_basis = _branch_evidence_basis(project, behavior_key, family, source_ids)
    branch_history = [
        hypothesis for hypothesis in project.hypotheses
        if hypothesis.behavior_key == behavior_key and hypothesis.test_family == family
    ]
    same_variant = [item for item in branch_history if item.test_variant == variant]
    for item in same_variant:
        if item.status in {"supported", "refuted", "waived", "planned", "testing"}:
            return None
        if (
            item.status in _NO_PROGRESS_HYPOTHESIS_STATUSES
            and _hypothesis_branch_basis(project, item) == branch_basis
        ):
            return None

    same_basis_history = [
        item for item in branch_history
        if _hypothesis_branch_basis(project, item) == branch_basis
        and item.status not in {"candidate", "planned", "testing", "waived"}
    ]
    no_progress_count = sum(
        item.status in _NO_PROGRESS_HYPOTHESIS_STATUSES for item in same_basis_history
    )
    stall_limit = project.project.recon_profile.branch_no_progress_limit
    if no_progress_count >= stall_limit:
        LOG.info(
            "pruned stalled branch project=%s behavior=%s family=%s attempts=%s limit=%s",
            project.project.id, behavior_key, family, no_progress_count, stall_limit,
        )
        return None

    terminal_history = [
        item for item in branch_history
        if item.status in _CONCLUSIVE_HYPOTHESIS_STATUSES | _NO_PROGRESS_HYPOTHESIS_STATUSES
    ]
    if terminal_history:
        conclusive_rate = sum(
            item.status in _CONCLUSIVE_HYPOTHESIS_STATUSES for item in terminal_history
        ) / len(terminal_history)
        history_factor = 0.7 + (0.3 * conclusive_rate)
    else:
        history_factor = 1.0
    history_factor *= max(0.4, 1.0 - (0.3 * no_progress_count))

    confidence = min(
        _bounded_float(data.get("confidence"), default=0.5, minimum=0.0, maximum=1.0),
        _evidence_confidence_cap(project, source_ids),
    )
    impact = _bounded_float(data.get("impact"), default=1.0, minimum=0.0, maximum=5.0)
    goal_value = _bounded_float(data.get("goal_value"), default=1.0, minimum=0.5, maximum=1.5)
    estimated_cost = _bounded_float(data.get("estimated_cost"), default=1.0, minimum=0.5, maximum=10.0)
    known_bases = {_hypothesis_branch_basis(project, item) for item in branch_history}
    novelty = 1.0 if not branch_history else 0.9 if branch_basis not in known_bases else 0.65
    fact_index = {fact.id: fact for fact in project.facts}
    context_chars = sum(
        len(json.dumps(_semantic_fact_payload(fact_index[fact_id]), ensure_ascii=False, default=str))
        for fact_id in source_ids if fact_id in fact_index
    )
    context_factor = 1.0 + min(context_chars / 16000.0, 1.0)
    score = max(
        0.0,
        (confidence * impact * goal_value * novelty * history_factor * 2.0)
        / (estimated_cost * context_factor),
    )
    if score < project.project.recon_profile.hypothesis_min_score:
        return None

    candidate = dict(data)
    candidate.update({
        "from": source_ids,
        "behavior_key": behavior_key,
        "path": surface.path_template,
        "test_family": family,
        "test_variant": variant,
        "confidence": confidence,
        "impact": impact,
        "goal_value": goal_value,
        "novelty": novelty,
        "estimated_cost": estimated_cost,
        "_frontier_score": round(score, 4),
        "_frontier_history_factor": round(history_factor, 4),
        "_frontier_context_factor": round(context_factor, 4),
        "_frontier_branch_basis": branch_basis,
        "_frontier_no_progress": no_progress_count,
    })
    return candidate


def _select_v3_frontier(
    project: ProjectDetail,
    candidates: list[dict],
    *,
    max_items: int,
) -> list[dict]:
    ranked: dict[tuple[str, str, str, str], dict] = {}
    for raw in candidates:
        candidate = _frontier_candidate(project, raw)
        if candidate is None:
            continue
        key = (
            candidate["behavior_key"], candidate["test_family"],
            candidate["test_variant"], candidate["_frontier_branch_basis"],
        )
        previous = ranked.get(key)
        if previous is None or candidate["_frontier_score"] > previous["_frontier_score"]:
            ranked[key] = candidate
    ordered = sorted(
        ranked.values(),
        key=lambda item: (-item["_frontier_score"], item["estimated_cost"], item["behavior_key"]),
    )
    breadth = [item for item in ordered if item["test_variant"] == "function_mapping"]
    depth = [item for item in ordered if item["test_variant"] != "function_mapping"]
    breadth_limit = min(project.project.recon_profile.frontier_breadth_slots, max_items)
    selected = breadth[:breadth_limit]
    selected.extend(depth[: max(0, max_items - len(selected))])
    if len(selected) < max_items:
        selected.extend(breadth[breadth_limit : breadth_limit + max_items - len(selected)])
    return selected[:max_items]


def _ensure_pending_surface_mapping_work(
    client: SkidcClient,
    project: ProjectDetail,
    worker_name: str,
    *,
    max_items: int = 3,
) -> int:
    """Create at most one mapping hypothesis for each pending Behavior."""
    groups: dict[str, list] = {}
    for surface in project.surface_inventory:
        if surface.traits.get("out_of_scope_support"):
            continue
        key = behavior_identity(surface)[0]
        groups.setdefault(key, []).append(surface)
    pending_groups = [
        (key, surfaces)
        for key, surfaces in groups.items()
        if any(surface.planning_status == "pending" for surface in surfaces)
    ]

    def priority(item: tuple[str, list]) -> tuple[int, str]:
        key, surfaces = item
        score = 0
        if any(surface.auth_context != "anonymous" or surface.roles for surface in surfaces):
            score += 4
        if any(str(surface.method or "GET").upper() not in {"GET", "HEAD", "OPTIONS"} for surface in surfaces):
            score += 3
        if any(surface.params for surface in surfaces):
            score += 2
        if any(surface.surface_type in {"admin_route", "upload_point", "form", "api"} for surface in surfaces):
            score += 2
        return -score, key

    created = 0
    known_facts = {fact.id for fact in project.facts}
    for behavior_key, surfaces in sorted(pending_groups, key=priority):
        if created >= max_items:
            break
        surface = surfaces[0]
        source_ids: list[str] = []
        for observation in surfaces:
            for fact_id in [*observation.evidence_fact_ids, observation.source_fact_id]:
                if fact_id and fact_id in known_facts and fact_id not in source_ids:
                    source_ids.append(fact_id)
        if not source_ids:
            source_ids = ["origin"]
        method = str(surface.method or "GET").upper()
        path = surface.path_template or "/"
        basis = _hypothesis_basis_fingerprint(
            behavior_key, "surface_config", "function_mapping", source_ids,
        )
        existing = next(
            (
                hypothesis for hypothesis in project.hypotheses
                if hypothesis.behavior_key == behavior_key
                and hypothesis.test_family == "surface_config"
                and hypothesis.test_variant == "function_mapping"
                and hypothesis.basis_fingerprint == basis
                and hypothesis.intent_id
            ),
            None,
        )
        if existing is not None:
            _mark_behavior_assessed(client, project, behavior_key)
            continue
        rationale = (
            f"Map the canonical {method} {path} behavior once to identify its request "
            "parameters, identity boundary, state changes, inputs, outputs, and security capabilities."
        )
        if _create_agent_hypothesis_work(
            client,
            project,
            worker_name,
            {
                "from": source_ids,
                "behavior_key": behavior_key,
                "path": surface.path_template,
                "description": rationale,
                "hypothesis": rationale,
                "test_family": "surface_config",
                "test_variant": "function_mapping",
                "action_kind": "surface_discovery",
                "confidence": 0.8,
                "impact": 2.0,
                "estimated_cost": 1.5,
                "priority": max(5, 9 if surface.auth_context != "anonymous" else 6),
                "suggested_tools": ["curl"],
                "risk_level": "safe",
            },
        ):
            created += 1
        else:
            LOG.info(
                "pending behavior mapping was duplicate or invalid project=%s behavior=%s",
                project.project.id, behavior_key,
            )
    return created



def _ensure_hypothesis_work(
    client: SkidcClient,
    project: ProjectDetail,
    worker_name: str,
) -> int:
    if any(
        intent.status == "open" and intent.hypothesis_id
        for intent in project.intents
    ):
        return 0

    profile = project.project.recon_profile

    goal_text = next(
        (fact.description for fact in project.facts if fact.id == "goal"),
        "",
    )
    terminal = {
        (item.behavior_key, item.test_family, item.test_variant)
        for item in project.hypotheses
        if item.status in {"supported", "refuted", "inconclusive", "waived"}
    }
    candidates = derive_candidates(
        project.surface_inventory, goal_text=goal_text,
        terminal_keys=terminal, required_score=profile.hypothesis_min_score,
    )
    remaining_slots = max(0, profile.max_hypotheses - len(project.hypotheses))
    selected = select_round(
        candidates,
        max_items=min(profile.hypothesis_batch_size, remaining_slots),
        min_score=profile.hypothesis_min_score,
    )
    if not selected:
        for surface in project.surface_inventory:
            if surface.planning_status == "assessed":
                continue
            payload = surface.model_dump(exclude={"id", "created_at", "updated_at"})
            payload["planning_status"] = "assessed"
            client.upsert_surface_inventory(project.project.id, **payload)
        return 0

    surfaces_by_behavior = {
        behavior_identity(surface)[0]: surface
        for surface in project.surface_inventory
    }
    created = 0
    for candidate in selected:
        surface = surfaces_by_behavior.get(candidate.behavior_key)
        if surface is None:
            continue
        source_ids = list(candidate.trigger_fact_ids) or [surface.source_fact_id or "origin"]
        hypothesis_payload = asdict(candidate)
        hypothesis_payload["trigger_fact_ids"] = source_ids
        hypothesis_payload["status"] = "candidate"
        response = client.create_hypothesis(project.project.id, hypothesis_payload)
        if not response.ok or not isinstance(response.data, dict):
            if response.status_code != 409:
                LOG.warning(
                    "hypothesis create failed project=%s behavior=%s variant=%s status=%s body=%s",
                    project.project.id, candidate.behavior_key, candidate.test_variant,
                    response.status_code, response.text,
                )
            continue
        hypothesis_id = str(response.data.get("id") or "")
        if not hypothesis_id:
            continue
        priority = max(1, min(10, int(round(candidate.score * 2))))
        coverage = client.create_coverage_item(
            project.project.id,
            item_type="route",
            description=f"Hypothesis {hypothesis_id}: {candidate.rationale}",
            target=surface.target,
            port=surface.port,
            method=surface.method,
            path=surface.path_template,
            priority=priority,
            source_fact_id=source_ids[0],
            surface_group=surface.surface_group,
            surface_fingerprint=surface.fingerprint,
            test_family=candidate.test_family,
            test_variants=[candidate.test_variant],
            auth_context=surface.auth_context,
            roles=surface.roles,
            applicability_reason=candidate.rationale,
            applicability_status="applicable",
            required=candidate.required,
            execution_status="untested",
        )
        if not coverage.ok or not isinstance(coverage.data, dict):
            client.update_hypothesis(
                project.project.id, hypothesis_id,
                last_error=f"Coverage creation failed: {coverage.status_code} {coverage.text[:500]}",
            )
            continue
        coverage_id = str(coverage.data.get("id") or "")
        intent = client.create_intent(
            project.project.id,
            source_ids,
            f"Test hypothesis {hypothesis_id}: {candidate.rationale}",
            worker_name,
            target=surface.target,
            port=surface.port,
            path=surface.path_template,
            surface_type=surface.surface_type,
            action_kind=f"{candidate.test_family}_hypothesis",
            test_variant=candidate.test_variant,
            priority=priority,
            suggested_tools=_BASELINE_TOOLS.get(candidate.test_family, ["curl"]),
            coverage_refs=[coverage_id],
            hypothesis_id=hypothesis_id,
        )
        if intent.ok:
            created += 1
            payload = surface.model_dump(exclude={"id", "created_at", "updated_at"})
            payload["planning_status"] = "assessed"
            client.upsert_surface_inventory(project.project.id, **payload)
            LOG.info(
                "planned hypothesis project=%s hypothesis=%s behavior=%s variant=%s score=%.3f",
                project.project.id, hypothesis_id, candidate.behavior_key,
                candidate.test_variant, candidate.score,
            )
        else:
            client.update_hypothesis(
                project.project.id, hypothesis_id,
                last_error=f"Intent creation failed: {intent.status_code} {intent.text[:500]}",
            )
    return created


def ensure_coverage_work(
    client: SkidcClient,
    project: ProjectDetail,
    worker_name: str,
) -> int:
    if project.project.planning_version >= 3:
        return 0
    if project.project.planning_version == 2:
        return _ensure_hypothesis_work(client, project, worker_name)
    project = _profile_unprofiled_surfaces(client, project, worker_name)
    if any(intent.status == "open" and intent.coverage_refs for intent in project.intents):
        return 0
    created = 0
    planned_count = sum(1 for intent in project.intents if intent.coverage_refs)
    remaining_budget = max(0, project.project.recon_profile.max_coverage_intents - planned_count)
    remaining_batch = project.project.recon_profile.coverage_batch_size
    for item in sorted(
        project.coverage_items,
        key=lambda value: (-(value.priority or 0), value.surface_group or "", value.test_family or "", value.id),
    ):
        if not item.required or item.disposition != "required":
            continue
        if item.test_family is None:
            continue
        if not item.test_variants:
            client.update_coverage_item(
                project.project.id,
                item.id,
                disposition="deferred",
                disposition_reason="No executable Variant is defined for this required Coverage family.",
            )
            LOG.warning(
                "deferred coverage without variants project=%s coverage=%s family=%s",
                project.project.id, item.id, item.test_family,
            )
            continue
        variant_status = {result.variant.casefold(): result.status for result in item.variant_results}
        for variant in item.test_variants:
            if variant_status.get(variant.casefold(), "untested") != "untested":
                continue
            if _coverage_variant_attempted(project, item.id, variant):
                continue
            if remaining_batch <= 0:
                return created
            if remaining_budget <= 0:
                client.update_coverage_item(
                    project.project.id,
                    item.id,
                    disposition="deferred",
                    disposition_reason="Coverage work budget exhausted before this Variant was scheduled.",
                )
                LOG.info(
                    "deferred coverage at work budget project=%s coverage=%s variant=%s",
                    project.project.id, item.id, variant,
                )
                break
            source = item.source_fact_id or "origin"
            path = item.path or "/"
            response = client.create_intent(
                project.project.id,
                [source],
                f"Test {variant} on {item.method or 'GET'} {path} ({item.surface_group or item.id}).",
                worker_name,
                target=item.target,
                port=item.port,
                path=item.path,
                surface_type=item.surface_class,
                action_kind=f"{item.test_family}_probe",
                test_variant=variant,
                priority=item.priority,
                suggested_tools=_BASELINE_TOOLS.get(item.test_family, ["curl"]),
                coverage_refs=[item.id],
            )
            if response.ok:
                created += 1
                remaining_budget -= 1
                remaining_batch -= 1
                LOG.info(
                    "materialized baseline intent project=%s coverage=%s variant=%s",
                    project.project.id,
                    item.id,
                    variant,
                )
            elif response.status_code != 409:
                LOG.warning(
                    "baseline intent write failed project=%s coverage=%s variant=%s status=%s body=%s",
                    project.project.id,
                    item.id,
                    variant,
                    response.status_code,
                    response.text,
                )
    return created


def _transition_to_explore_with_baseline(
    client: SkidcClient,
    project: ProjectDetail,
    worker_name: str,
) -> int:
    response = client.advance_phase(project.project.id)
    if not response.ok:
        LOG.warning(
            "phase transition request failed project=%s status=%s body=%s",
            project.project.id,
            response.status_code,
            response.text,
        )
        return -1
    transition = response.data if isinstance(response.data, dict) else {}
    if not transition.get("advanced") and transition.get("code") != "already_explore":
        LOG.warning(
            "phase transition blocked project=%s code=%s missing=%s open=%s",
            project.project.id,
            transition.get("code"),
            transition.get("missing_categories"),
            transition.get("open_recon_intents"),
        )
        return -2

    refreshed = client.get_project(project.project.id)
    created = ensure_coverage_work(client, refreshed, worker_name)
    LOG.info(
        "phase transition project=%s from=recon to=explore baseline_intents=%s",
        project.project.id,
        created,
    )
    return created




def _completion_detail(response) -> dict | None:
    data = getattr(response, "data", None)
    if not isinstance(data, dict):
        return None
    detail = data.get("detail")
    return detail if isinstance(detail, dict) else None


def _is_completion_blocked_response(response) -> bool:
    detail = _completion_detail(response)
    return response.status_code == 409 and detail is not None and detail.get("code") == "completion_blocked"


def _completion_blocker_count(response) -> int:
    detail = _completion_detail(response)
    blockers = detail.get("blockers") if detail else None
    return len(blockers) if isinstance(blockers, list) else 0


def _persist_reason_handoff(
    client,
    project_id: str,
    worker_name: str,
    handoff: dict[str, object],
    coverage_index: dict[tuple, str] | None = None,
    real_website: bool = False,
    materialize_coverage: bool = True,
    support_ports: list[int] | None = None,
) -> dict[str, str]:
    if not materialize_coverage:
        return {}
    coverage_index = coverage_index if coverage_index is not None else {}
    fact_ids: dict[str, str] = {}
    attack_surface_map = handoff.get("attack_surface_map")
    if isinstance(attack_surface_map, dict):
        response = client.create_fact_direct(
            project_id,
            description=json.dumps(attack_surface_map, ensure_ascii=False, sort_keys=True),
            goal_type="attack_surface_map",
            status="completed",
        )
        if response.ok:
            LOG.info("reason persisted attack_surface_map project=%s worker=%s", project_id, worker_name)
            source_fact_id = _response_id(response)
            if source_fact_id:
                fact_ids["attack_surface_map"] = source_fact_id
            if real_website:
                surfaces = normalize_surface_map(attack_surface_map, support_ports=support_ports or [])
                for surface in surfaces:
                    response = client.upsert_surface_inventory(project_id, **surface, source_fact_id=source_fact_id)
                    if not response.ok:
                        LOG.info("reason surface inventory skipped project=%s fingerprint=%s status=%s", project_id, surface["fingerprint"], response.status_code)
                coverage_items = build_profile_for_surfaces(surfaces, source_fact_id=source_fact_id)
            else:
                coverage_items = _coverage_from_attack_surface_map(attack_surface_map, source_fact_id=source_fact_id)
            if materialize_coverage:
                _create_coverage_items(client, project_id, worker_name, coverage_items, coverage_index)
        else:
            LOG.warning("reason attack_surface_map write failed project=%s worker=%s status=%s body=%s", project_id, worker_name, response.status_code, response.text)

    seed_deck = handoff.get("explore_seed_deck")
    if isinstance(seed_deck, list) and seed_deck:
        response = client.create_fact_direct(
            project_id,
            description=json.dumps({"seeds": seed_deck}, ensure_ascii=False, sort_keys=True),
            goal_type="explore_seed_deck",
            status="pending",
        )
        if response.ok:
            LOG.info("reason persisted explore_seed_deck project=%s worker=%s seeds=%s", project_id, worker_name, len(seed_deck))
            source_fact_id = _response_id(response)
            if source_fact_id:
                fact_ids["explore_seed_deck"] = source_fact_id
        else:
            LOG.warning("reason explore_seed_deck write failed project=%s worker=%s status=%s body=%s", project_id, worker_name, response.status_code, response.text)
    return fact_ids


def _create_coverage_items(
    client,
    project_id: str,
    worker_name: str,
    items: list[dict],
    coverage_index: dict[tuple, str],
) -> None:
    for item in items:
        key = _coverage_key(item)
        existing_id = coverage_index.get(key)
        if existing_id:
            intent_id = item.get("intent_id")
            if intent_id:
                response = client.bind_coverage_intent(project_id, existing_id, intent_id)
                if response.ok:
                    LOG.info(
                        "reason bound existing coverage project=%s coverage=%s intent=%s",
                        project_id,
                        existing_id,
                        intent_id,
                    )
                else:
                    LOG.info(
                        "reason coverage bind skipped project=%s coverage=%s intent=%s status=%s",
                        project_id,
                        existing_id,
                        intent_id,
                        response.status_code,
                    )
            continue
        response = client.create_coverage_item(project_id, **item)
        if response.ok:
            coverage_id = _response_id(response)
            if coverage_id:
                coverage_index[key] = coverage_id
            LOG.info("reason created coverage_item project=%s worker=%s type=%s path=%s priority=%s", project_id, worker_name, item.get("item_type"), item.get("path"), item.get("priority"))
        else:
            LOG.info("reason coverage_item skipped project=%s worker=%s status=%s body=%s", project_id, worker_name, response.status_code, response.text)


def _coverage_from_attack_surface_map(surface_map: dict, *, source_fact_id: str | None = None) -> list[dict]:
    items: list[dict] = []
    for entry in _as_list(surface_map.get("surfaces")):
        if not isinstance(entry, dict):
            continue
        target, port, path, method = _target_port_path_method(entry)
        if not _is_web_surface(entry, port, path):
            continue
        item_type = _item_type_from_surface(entry, path)
        description = _description_from_entry(entry, default=f"Recon surface {target or path or item_type}")
        items.append(_coverage_item(
            item_type=item_type,
            description=description,
            target=target,
            port=port,
            method=method,
            path=path,
            priority=_coverage_priority(item_type, path=path, description=description),
            source_fact_id=source_fact_id,
        ))
    for key, item_type in (
        ("routes", "route"),
        ("endpoints", "route"),
        ("pages", "route"),
        ("admin_routes", "admin_route"),
        ("forms", "form"),
        ("upload_points", "upload_point"),
    ):
        for entry in _as_list(surface_map.get(key)):
            item = _coverage_from_entry(entry, item_type=item_type, source_fact_id=source_fact_id)
            if item:
                items.append(item)
    for entry in _as_list(surface_map.get("params")):
        item = _coverage_from_entry(entry, item_type="param", source_fact_id=source_fact_id)
        if item:
            items.append(item)
    return items


def _coverage_from_seed_deck(
    seed_deck: list[dict],
    *,
    source_fact_id: str | None = None,
    intent_id: str | None = None,
) -> list[dict]:
    items: list[dict] = []
    for seed in seed_deck:
        if not isinstance(seed, dict):
            continue
        item_type = _item_type_from_seed(seed)
        target, port, path, method = _target_port_path_method(seed)
        param = _optional_str(seed, "param") or _optional_str(seed, "parameter")
        description = _description_from_entry(seed, default=f"Explore seed {path or target or item_type}")
        priority = _optional_int(seed, "priority")
        if priority is None:
            priority = _coverage_priority(item_type, path=path, param=param, description=description)
        items.append(_coverage_item(
            item_type=item_type,
            description=description,
            target=target,
            port=port,
            method=method,
            path=path,
            param=param,
            priority=priority,
            source_fact_id=source_fact_id,
            intent_id=intent_id,
        ))
    return items


def _coverage_from_entry(entry, *, item_type: str, source_fact_id: str | None = None) -> dict | None:
    if isinstance(entry, str):
        target, port, path = _parse_target_path(entry)
        description = f"Recon {item_type} {entry}"
        method = None
        param = None
    elif isinstance(entry, dict):
        target, port, path, method = _target_port_path_method(entry)
        param = _optional_str(entry, "param") or _optional_str(entry, "parameter") or _optional_str(entry, "name")
        description = _description_from_entry(entry, default=f"Recon {item_type} {path or target or param or 'item'}")
    else:
        return None
    if item_type == "param" and not param:
        param = _param_from_path(path)
    return _coverage_item(
        item_type=item_type,
        description=description,
        target=target,
        port=port,
        method=method,
        path=path,
        param=param,
        priority=_coverage_priority(item_type, path=path, param=param, description=description),
        source_fact_id=source_fact_id,
    )


def _coverage_item(**values) -> dict:
    return {key: value for key, value in values.items() if value is not None}


def _coverage_key(item: dict) -> tuple:
    if item.get("test_family"):
        return tuple(
            str(value or "").lower()
            for value in (
                item.get("surface_fingerprint"), item.get("target"), item.get("port"),
                item.get("method"), item.get("path"), item.get("surface_group"),
                item.get("test_family"), item.get("auth_context"),
            )
        )
    return tuple(str(item.get(key) or "").lower() for key in ("item_type", "target", "port", "method", "path", "param"))


def _profile_coverage_from_seed(
    client,
    project_id: str,
    seed: dict,
    *,
    support_ports: list[int],
    source_fact_id: str | None,
    intent_id: str,
) -> list[dict]:
    surface = normalize_surface_entry(seed, support_ports=support_ports)
    if surface is None:
        return _coverage_from_seed_deck([seed], source_fact_id=source_fact_id, intent_id=intent_id)
    response = client.upsert_surface_inventory(project_id, **surface, source_fact_id=source_fact_id)
    if not response.ok:
        LOG.info("reason seed surface inventory skipped project=%s fingerprint=%s status=%s", project_id, surface["fingerprint"], response.status_code)
    items = build_web_coverage_profile(surface, source_fact_id=source_fact_id)
    return bind_profile_to_intent(items, seed, intent_id)


def _response_id(response) -> str | None:
    data = getattr(response, "data", None)
    if isinstance(data, dict):
        value = data.get("id")
        if isinstance(value, str) and value:
            return value
    return None


def _item_type_from_surface(entry: dict, path: str | None) -> str:
    raw_type = (_optional_str(entry, "type") or _optional_str(entry, "surface_type") or "").lower()
    if "upload" in raw_type:
        return "upload_point"
    if "form" in raw_type:
        return "form"
    if "admin" in raw_type or _looks_admin(path):
        return "admin_route"
    return "route" if path else "service"


def _item_type_from_seed(seed: dict) -> str:
    text = " ".join(
        value for value in (
            _optional_str(seed, "surface_type"),
            _optional_str(seed, "action_kind"),
            _optional_str(seed, "description"),
            _optional_str(seed, "path"),
        )
        if value
    ).lower()
    if "upload" in text:
        return "upload_point"
    if "admin" in text:
        return "admin_route"
    if "form" in text or "login" in text or "auth" in text:
        return "form"
    if "param" in text or "sqli" in text or "xss" in text or "idor" in text:
        return "param"
    return "route"


def _coverage_priority(item_type: str, *, path: str | None = None, param: str | None = None, description: str = "") -> int:
    text = " ".join(part for part in (path, param, description) if part).lower()
    if item_type == "upload_point":
        return 10
    if item_type == "admin_route":
        return 9
    if any(token in text for token in ("rce", "sql", "sqli", "upload", "shell")):
        return 9
    if any(token in text for token in ("admin", "login", "auth", "session", "password")):
        return 8
    if item_type == "form":
        return 6
    if item_type == "param":
        return 7 if param else 5
    return 5


def _target_port_path_method(entry: dict) -> tuple[str | None, int | None, str | None, str | None]:
    target = _optional_str(entry, "target") or _optional_str(entry, "host") or _optional_str(entry, "url")
    path = _optional_str(entry, "path") or _optional_str(entry, "route") or _optional_str(entry, "endpoint")
    parsed_target, parsed_port, parsed_path = _parse_target_path(target)
    if parsed_target:
        target = parsed_target
    if parsed_path and not path:
        path = parsed_path
    port = _optional_int(entry, "port") or parsed_port
    method = _optional_str(entry, "method")
    return target, port, path, method.upper() if method else None


def _parse_target_path(value: str | None) -> tuple[str | None, int | None, str | None]:
    if not value:
        return None, None, None
    parsed = urlparse(value if "://" in value else f"//{value}")
    target = parsed.hostname
    port = parsed.port
    path = parsed.path or None
    if not target and value.startswith("/"):
        path = value
    return target, port, path


def _is_web_surface(entry: dict, port: int | None, path: str | None) -> bool:
    if path:
        return True
    raw = " ".join(
        value for value in (
            _optional_str(entry, "type"),
            _optional_str(entry, "surface_type"),
            _optional_str(entry, "scheme"),
            _optional_str(entry, "protocol"),
        )
        if value
    ).lower()
    if any(token in raw for token in ("web", "http", "https", "api")):
        return True
    return port in (80, 443, 8000, 8080, 8443)


def _description_from_entry(entry: dict, *, default: str) -> str:
    for key in ("description", "summary", "name"):
        value = _optional_str(entry, key)
        if value:
            return value
    return default


def _as_list(value) -> list:
    return value if isinstance(value, list) else []


def _looks_admin(path: str | None) -> bool:
    return bool(path and "admin" in path.lower())


def _param_from_path(path: str | None) -> str | None:
    if not path or "?" not in path:
        return None
    query = path.split("?", 1)[1]
    first = query.split("&", 1)[0]
    name = first.split("=", 1)[0].strip()
    return name or None


def _optional_str(data: dict, key: str) -> str | None:
    value = data.get(key)
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _optional_int(data: dict, key: str) -> int | None:
    value = data.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _optional_str_list(data: dict, key: str) -> list[str] | None:
    value = data.get(key)
    if not isinstance(value, list):
        return None
    cleaned = [item.strip() for item in value if isinstance(item, str) and item.strip()]
    return cleaned

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
import subprocess
import threading
from typing import Any
import sys

from fastapi.testclient import TestClient
from pydantic import TypeAdapter
import pytest

from skidc.dispatcher.config import DispatchConfig, MOCK_ALLOWED_OUTCOMES
from skidc.dispatcher.protocol.client import ApiResult
from skidc.dispatcher.runtime.process import ProcessResult
from skidc.dispatcher.scheduler.loop import DispatcherLoop
from skidc.server import db
from skidc.server.app import app
from skidc.server.models import ProjectDetail, ProjectSummary, Settings


class InProcessClient:
    """A SkidcClient look-alike that talks to the FastAPI app via TestClient,
    so the whole dispatcher pipeline runs in one process with no network."""

    def __init__(self, http: TestClient):
        self.http = http
        self._summaries = TypeAdapter(list[ProjectSummary])

    def close(self) -> None:
        return None

    def list_projects(self) -> list[ProjectSummary]:
        response = self.http.get("/projects")
        response.raise_for_status()
        return self._summaries.validate_python(response.json())

    def get_project(self, project_id: str) -> ProjectDetail:
        response = self.http.get(f"/projects/{project_id}?view=dispatch")
        response.raise_for_status()
        return ProjectDetail.model_validate(response.json())

    def get_settings(self) -> Settings:
        response = self.http.get("/settings")
        response.raise_for_status()
        return Settings.model_validate(response.json())

    def export_project(self, project_id: str) -> str:
        response = self.http.get(f"/projects/{project_id}/export?format=yaml")
        response.raise_for_status()
        return response.text

    def heartbeat(self, project_id: str, intent_id: str, worker: str) -> ApiResult:
        return self._post(f"/projects/{project_id}/intents/{intent_id}/heartbeat", {"worker": worker})

    def claim_reason(self, project_id: str, worker: str, trigger: str) -> ApiResult:
        return self._post(f"/projects/{project_id}/reason/claim", {"worker": worker, "trigger": trigger})

    def reason_heartbeat(self, project_id: str, worker: str) -> ApiResult:
        return self._post(f"/projects/{project_id}/reason/heartbeat", {"worker": worker})

    def release_reason(self, project_id: str, worker: str) -> ApiResult:
        return self._post(f"/projects/{project_id}/reason/release", {"worker": worker})

    def release(self, project_id: str, intent_id: str, worker: str) -> ApiResult:
        return self._post(f"/projects/{project_id}/intents/{intent_id}/release", {"worker": worker})

    def conclude(
        self,
        project_id: str,
        intent_id: str,
        worker: str,
        description: str,
        fact_fields: dict[str, Any] | None = None,
    ) -> ApiResult:
        body = {"worker": worker, "description": description}
        if fact_fields:
            for key in (
                "scope", "vuln_type", "severity", "parent_fact", "verification_of", "goal_type", "status",
                "recon_category", "recon_executed", "recon_found_results",
                "recon_tool", "recon_target", "recon_evidence_ref", "coverage_refs", "observed_surfaces",
            ):
                value = fact_fields.get(key)
                if value is not None:
                    body[key] = value
        return self._post(
            f"/projects/{project_id}/intents/{intent_id}/conclude",
            body,
        )

    def create_fact_direct(
        self,
        project_id: str,
        description: str,
        goal_type: str | None = None,
        status: str | None = None,
        **fact_fields: Any,
    ) -> ApiResult:
        body: dict[str, Any] = {"description": description}
        if goal_type:
            body["goal_type"] = goal_type
        if status:
            body["status"] = status
        for key in (
            "scope", "vuln_type", "severity", "parent_fact", "verification_of",
            "recon_category", "recon_executed", "recon_found_results",
            "recon_tool", "recon_target", "recon_evidence_ref", "coverage_refs",
        ):
            value = fact_fields.get(key)
            if value is not None:
                body[key] = value
        return self._post(f"/projects/{project_id}/facts", body)

    def advance_phase(self, project_id: str) -> ApiResult:
        return self._post(f"/projects/{project_id}/phase/advance", {})

    def update_phase(self, project_id: str, phase: str) -> ApiResult:
        return self._request("PUT", f"/projects/{project_id}/phase", {"phase": phase})

    def mark_needs_attention(
        self,
        project_id: str,
        worker: str,
        reason_code: str,
        detail: str,
    ) -> ApiResult:
        return self._post(
            f"/projects/{project_id}/needs-attention",
            {
                "worker": worker,
                "reason_code": reason_code,
                "detail": detail,
            },
        )

    def update_mode(self, project_id: str, mode: str) -> ApiResult:
        return self._request("PUT", f"/projects/{project_id}/mode", {"mode": mode})

    def create_task_log(
        self,
        project_id: str,
        task_type: str,
        worker_name: str,
        phase: str,
        stdin: str | None = None,
        stdout: str | None = None,
        stderr: str | None = None,
        return_code: int | None = None,
        timed_out: bool = False,
        duration_ms: int | None = None,
        intent_id: str | None = None,
    ) -> ApiResult:
        body: dict[str, Any] = {
            "task_type": task_type,
            "intent_id": intent_id,
            "worker_name": worker_name,
            "phase": phase,
            "stdin": stdin,
            "stdout": stdout,
            "stderr": stderr,
            "return_code": return_code,
            "timed_out": timed_out,
            "duration_ms": duration_ms,
        }
        return self._post(f"/projects/{project_id}/logs", body)

    def complete(self, project_id: str, from_ids: list[str], description: str, worker: str) -> ApiResult:
        return self._post(
            f"/projects/{project_id}/complete",
            {"from": from_ids, "description": description, "worker": worker},
        )

    def create_intent(
        self,
        project_id: str,
        from_ids: list[str],
        description: str,
        creator: str,
        *,
        target: str | None = None,
        port: int | None = None,
        path: str | None = None,
        surface_type: str | None = None,
        action_kind: str | None = None,
        test_variant: str | None = None,
        priority: int | None = None,
        suggested_tools: list[str] | None = None,
        coverage_refs: list[str] | None = None,
        hypothesis_id: str | None = None,
    ) -> ApiResult:
        body: dict[str, Any] = {
            "from": from_ids,
            "description": description,
            "creator": creator,
            "worker": None,
        }
        for key, value in (
            ("target", target),
            ("port", port),
            ("path", path),
            ("surface_type", surface_type),
            ("action_kind", action_kind),
            ("test_variant", test_variant),
            ("priority", priority),
        ):
            if value is not None:
                body[key] = value
        if suggested_tools is not None:
            body["suggested_tools"] = suggested_tools
        if coverage_refs is not None:
            body["coverage_refs"] = coverage_refs
        if hypothesis_id is not None:
            body["hypothesis_id"] = hypothesis_id
        return self._post(
            f"/projects/{project_id}/intents",
            body,
        )

    def create_attack_path(
        self, project_id: str, name: str, fact_chain: list[str], description: str, severity: str = "medium",
        status: str = "hypothesis",
    ) -> ApiResult:
        return self._post(
            f"/projects/{project_id}/attack-paths",
            {
                "name": name,
                "fact_chain": fact_chain,
                "description": description,
                "severity": severity,
                "status": status,
            },
        )

    def create_coverage_item(
        self,
        project_id: str,
        *,
        item_type: str,
        description: str,
        target: str | None = None,
        port: int | None = None,
        method: str | None = None,
        path: str | None = None,
        param: str | None = None,
        status: str = "untested",
        priority: int | None = None,
        evidence_ref: str | None = None,
        source_fact_id: str | None = None,
        intent_id: str | None = None,
        surface_group: str | None = None,
        surface_fingerprint: str | None = None,
        test_family: str | None = None,
        test_variants: list[str] | None = None,
        auth_context: str | None = None,
        roles: list[str] | None = None,
        applicability_reason: str | None = None,
        required: bool | None = None,
        disposition: str | None = None,
        disposition_reason: str | None = None,
        standard_refs: list[str] | None = None,
        execution_status: str | None = None,
        applicability_status: str | None = None,
        outcome: str | None = None,
    ) -> ApiResult:
        body: dict[str, Any] = {
            "item_type": item_type,
            "description": description,
            "status": status,
        }
        for key, value in (
            ("target", target),
            ("port", port),
            ("method", method),
            ("path", path),
            ("param", param),
            ("priority", priority),
            ("evidence_ref", evidence_ref),
            ("source_fact_id", source_fact_id),
            ("intent_id", intent_id),
            ("surface_group", surface_group),
            ("surface_fingerprint", surface_fingerprint),
            ("test_family", test_family),
            ("test_variants", test_variants),
            ("auth_context", auth_context),
            ("roles", roles),
            ("applicability_reason", applicability_reason),
            ("required", required),
            ("disposition", disposition),
            ("disposition_reason", disposition_reason),
            ("standard_refs", standard_refs),
            ("execution_status", execution_status),
            ("applicability_status", applicability_status),
            ("outcome", outcome),
        ):
            if value is not None:
                body[key] = value
        return self._post(f"/projects/{project_id}/coverage", body)

    def upsert_surface_inventory(self, project_id: str, **surface: Any) -> ApiResult:
        return self._post(f"/projects/{project_id}/surfaces", surface)

    def update_coverage_item(
        self,
        project_id: str,
        coverage_id: str,
        *,
        status: str | None = None,
        evidence_ref: str | None = None,
        intent_id: str | None = None,
        execution_status: str | None = None,
        outcome: str | None = None,
        disposition: str | None = None,
        disposition_reason: str | None = None,
    ) -> ApiResult:
        body = {
            key: value
            for key, value in {
                "status": status,
                "evidence_ref": evidence_ref,
                "intent_id": intent_id,
                "execution_status": execution_status,
                "outcome": outcome,
                "disposition": disposition,
                "disposition_reason": disposition_reason,
            }.items()
            if value is not None
        }
        return self._request("PUT", f"/projects/{project_id}/coverage/{coverage_id}", body)

    def bind_coverage_intent(self, project_id: str, coverage_id: str, intent_id: str) -> ApiResult:
        return self._post(
            f"/projects/{project_id}/coverage/{coverage_id}/intents",
            {"intent_id": intent_id},
        )

    def materialize_hypothesis_work(
        self,
        project_id: str,
        *,
        hypothesis: dict[str, Any],
        coverage: dict[str, Any],
        intent: dict[str, Any],
        surface_ids: list[str],
    ) -> ApiResult:
        return self._post(
            f"/projects/{project_id}/hypothesis-work",
            {
                "hypothesis": hypothesis,
                "coverage": coverage,
                "intent": intent,
                "surface_ids": surface_ids,
            },
        )

    def create_hypothesis(self, project_id: str, candidate: dict[str, Any]) -> ApiResult:
        return self._post(f"/projects/{project_id}/hypotheses", candidate)

    def update_hypothesis(self, project_id: str, hypothesis_id: str, **fields: Any) -> ApiResult:
        return self._request(
            "PUT", f"/projects/{project_id}/hypotheses/{hypothesis_id}",
            {key: value for key, value in fields.items() if value is not None},
        )

    def record_execution_success(
        self, project_id: str, intent_id: str, worker: str, task_log_id: str,
    ) -> ApiResult:
        return self._post(
            f"/projects/{project_id}/intents/{intent_id}/execution-success",
            {"worker": worker, "task_log_id": task_log_id},
        )

    def record_conclusion_failure(
        self, project_id: str, intent_id: str, worker: str, error: str,
    ) -> ApiResult:
        return self._post(
            f"/projects/{project_id}/intents/{intent_id}/conclusion-failure",
            {"worker": worker, "error": error},
        )

    def get_task_log(self, project_id: str, log_id: str):
        from skidc.server.models import TaskLog

        response = self.http.get(f"/projects/{project_id}/logs/{log_id}")
        response.raise_for_status()
        return TaskLog.model_validate(response.json())

    def record_intent_failure(
        self,
        project_id: str,
        intent_id: str,
        worker: str,
        error: str,
        *,
        max_attempts: int,
        backoff_seconds: int,
    ) -> ApiResult:
        return self._post(
            f"/projects/{project_id}/intents/{intent_id}/failure",
            {
                "worker": worker,
                "error": error,
                "max_attempts": max_attempts,
                "backoff_seconds": backoff_seconds,
            },
        )

    def record_reason_failure(
        self,
        project_id: str,
        worker: str,
        error: str,
        *,
        max_attempts: int,
        backoff_seconds: int,
    ) -> ApiResult:
        return self._post(
            f"/projects/{project_id}/reason/failure",
            {
                "worker": worker,
                "error": error,
                "max_attempts": max_attempts,
                "backoff_seconds": backoff_seconds,
            },
        )

    def record_reason_success(self, project_id: str, worker: str) -> ApiResult:
        return self._post(f"/projects/{project_id}/reason/success", {"worker": worker})

    def _post(self, path: str, payload: dict[str, Any]) -> ApiResult:
        return self._request("POST", path, payload)

    def _request(self, method: str, path: str, payload: dict[str, Any]) -> ApiResult:
        response = self.http.request(method, path, json=payload)
        data = response.json() if response.headers.get("content-type", "").startswith("application/json") else None
        return ApiResult(response.status_code, data, response.text)


class LocalProcess:
    """Runs the mock worker command as a real local subprocess (no Docker)."""

    def __init__(self, command: list[str], env: dict[str, str]):
        self.command = list(command)
        if os.name == "nt" and self.command and self.command[0] == "python3":
            self.command[0] = sys.executable
        self.env = env
        self._process: subprocess.Popen[str] | None = None
        self._cancel_reason: str | None = None
        self._lock = threading.Lock()

    def start(self) -> None:
        with self._lock:
            self._process = subprocess.Popen(
                self.command,
                env={**os.environ, **self.env},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

    def communicate(self, timeout: float | None) -> ProcessResult:
        assert self._process is not None
        timed_out = False
        try:
            stdout, stderr = self._process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self.kill()
            stdout, stderr = self._process.communicate()
        return ProcessResult(
            returncode=self._process.returncode,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            cancelled=self._cancel_reason is not None,
            cancel_reason=self._cancel_reason,
        )

    def kill(self) -> None:
        with self._lock:
            process = self._process
        if process is not None and process.poll() is None:
            process.kill()

    def cancel(self, reason: str) -> None:
        if self._cancel_reason is None:
            self._cancel_reason = reason
        self.kill()


class LocalContainerManager:
    """ContainerManager stand-in: no Docker, just runs mock commands locally and
    captures the graph-snapshot file writes the tasks would have injected."""

    def __init__(self) -> None:
        self.writes: list[tuple[str, str, str]] = []

    def close(self) -> None:
        return None

    def container_name(self, project_id: str) -> str:
        return f"local-{project_id}"

    def ensure_running(self, project_id: str) -> str:
        return self.container_name(project_id)

    def build_exec_process(
        self,
        _container_name: str,
        env: dict[str, str],
        command: list[str],
        timeout_seconds: int | None = None,
        kill_after_seconds: int = 5,
    ) -> LocalProcess:
        assert timeout_seconds is not None
        assert kill_after_seconds == 5
        return LocalProcess(command, env)

    def write_text_file(self, container_name: str, path: str, content: str) -> None:
        self.writes.append((container_name, path, content))

    def needs_completed_cleanup(self, _project_id: str) -> bool:
        return False

    def needs_stopped_cleanup(self, _project_id: str) -> bool:
        return False

    def managed_container_names(self) -> list[str]:
        return []


@pytest.fixture
def http_client(tmp_path, monkeypatch) -> TestClient:
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(tmp_path / "skidc.db")
    with TestClient(app) as client:
        yield client


def phase(outcome: str, *, rules: list[dict[str, Any]] | None = None, zero_outcomes: list[str] | None = None) -> str:
    outcomes = {name: 0 for name in zero_outcomes or []}
    outcomes[outcome] = 1
    payload: dict[str, Any] = {"delay": [0, 0], "outcomes": outcomes}
    if rules is not None:
        payload["rules"] = rules
    return json.dumps(payload)


def _mock_phase_payload(phase_name: str, payload_json: str) -> str:
    payload = json.loads(payload_json)
    raw_outcomes = payload.get("outcomes", {})
    payload["outcomes"] = {
        outcome: raw_outcomes.get(outcome, 0)
        for outcome in sorted(MOCK_ALLOWED_OUTCOMES[phase_name])
    }
    return json.dumps(payload)


def mock_config(
    *,
    bootstrap: str,
    reason: str,
    explore: str,
    task_types: list[str] | None = None,
) -> DispatchConfig:
    return DispatchConfig.model_validate(
        {
            "server": "in-process",
            "runtime": {
                "interval": 1,
                "max_workers": 1,
                "max_running_projects": 1,
                "max_project_workers": 1,
                "healthcheck_timeout": 2,
                "prompt_group": "mock",
            },
            "tasks": {
                "bootstrap": {"timeout": 2, "conclude_timeout": 2},
                "reason": {"timeout": 2, "max_intents": 1},
                "explore": {"timeout": 2, "conclude_timeout": 2},
            },
            "container": {"image": "unused", "network_mode": "host", "completed_action": "stop"},
            "workers": [
                {
                    "name": "mock-worker",
                    "type": "mock",
                    "task_types": task_types or ["bootstrap", "reason", "explore"],
                    "max_running": 1,
                    "priority": 0,
                    "env": {
                        "MOCK_HEALTHCHECK": phase("ok"),
                        "MOCK_BOOTSTRAP": _mock_phase_payload("bootstrap", bootstrap),
                        "MOCK_REASON": _mock_phase_payload("reason", reason),
                        "MOCK_EXPLORE_EXECUTE": _mock_phase_payload("explore_execute", explore),
                    },
                }
            ],
        }
    )


def make_loop(config: DispatchConfig, client: InProcessClient, containers: LocalContainerManager) -> DispatcherLoop:
    loop = DispatcherLoop.__new__(DispatcherLoop)
    loop.config = config
    loop.client = client
    loop.container_manager = containers
    loop.executor = ThreadPoolExecutor(max_workers=config.runtime.max_workers)
    loop.cleanup_executor = ThreadPoolExecutor(max_workers=1)
    loop.futures = {}
    loop.cleanup_futures = {}
    loop.reason_checkpoints = {}
    loop.runtime_project_ids = set()
    loop.worker_unhealthy_until = {}
    loop.worker_rejected_until = {}
    loop.startup_unhealthy_workers = set()
    loop._log_state = {}
    loop._cleanup_pending = set()
    loop._inactive_cleanup_done = {}
    loop.project_cursor = 0
    loop._settings_checked = False
    loop._startup_healthchecks_checked = False
    return loop


def dispatch_and_wait(loop: DispatcherLoop) -> None:
    loop._reap_futures()
    summaries = loop.client.list_projects()
    loop._initialize_reason_checkpoints(summaries)
    loop._refresh_runtime_projects(summaries)
    loop._cancel_inactive_tasks(summaries)
    loop._queue_container_cleanups(summaries)
    loop._dispatch_available(summaries)
    assert loop.futures
    for future in list(loop.futures):
        future.result(timeout=10)
    loop._reap_futures()


def create_project(
    http: TestClient,
    *,
    bootstrap_enabled: bool = True,
    required_recon_categories: list[str] | None = None,
) -> str:
    payload: dict[str, Any] = {
        "title": "integration",
        "origin": "start",
        "goal": "finish",
        "bootstrap_enabled": bootstrap_enabled,
    }
    if required_recon_categories is not None:
        payload["recon_profile"] = {"required_categories": required_recon_categories}
    response = http.post(
        "/projects",
        json=payload,
    )
    assert response.status_code == 201
    return response.json()["project"]["id"]

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import logging
import threading

from pydantic import TypeAdapter
import requests
from requests.adapters import HTTPAdapter

from skidc.server.models import Intent, ProjectDetail, ProjectSummary, Settings, TaskLog

LOG = logging.getLogger(__name__)


class ProtocolError(RuntimeError):
    def __init__(self, message: str, status_code: int, response_text: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text


@dataclass(slots=True)
class ApiResult:
    status_code: int
    data: Any | None = None
    text: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300


class SkidcClient:
    def __init__(
        self,
        base_url: str,
        timeout: float = 15.0,
        *,
        detail_timeout: float = 60.0,
        dispatch_timeout: float = 15.0,
    ):
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._detail_timeout = detail_timeout
        self._dispatch_timeout = dispatch_timeout
        self._summary_adapter = TypeAdapter(list[ProjectSummary])
        self._local = threading.local()
        self._sessions: dict[int, requests.Session] = {}
        self._sessions_lock = threading.Lock()

    def close(self) -> None:
        with self._sessions_lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            session.close()

    def list_projects(self) -> list[ProjectSummary]:
        response = self._session().get(self._url("/projects"), timeout=self._timeout)
        response.raise_for_status()
        return self._summary_adapter.validate_python(response.json())

    def get_project(self, project_id: str) -> ProjectDetail:
        response = self._session().get(
            self._url(f"/projects/{project_id}"),
            params={"view": "dispatch"},
            timeout=self._dispatch_timeout,
        )
        response.raise_for_status()
        return ProjectDetail.model_validate(response.json())

    def get_full_project(self, project_id: str) -> ProjectDetail:
        response = self._session().get(
            self._url(f"/projects/{project_id}"),
            params={"view": "full"},
            timeout=self._detail_timeout,
        )
        response.raise_for_status()
        return ProjectDetail.model_validate(response.json())

    def get_settings(self) -> Settings:
        response = self._session().get(self._url("/settings"), timeout=self._timeout)
        response.raise_for_status()
        return Settings.model_validate(response.json())

    def export_project(self, project_id: str) -> str:
        response = self._session().get(
            self._url(f"/projects/{project_id}/export"),
            params={"format": "yaml"},
            timeout=self._detail_timeout,
        )
        response.raise_for_status()
        return response.text

    def heartbeat(self, project_id: str, intent_id: str, worker: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/intents/{intent_id}/heartbeat",
            json={"worker": worker},
        )

    def claim_reason(self, project_id: str, worker: str, trigger: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/reason/claim",
            json={"worker": worker, "trigger": trigger},
        )

    def reason_heartbeat(self, project_id: str, worker: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/reason/heartbeat",
            json={"worker": worker},
        )

    def release_reason(self, project_id: str, worker: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/reason/release",
            json={"worker": worker},
        )

    def release(self, project_id: str, intent_id: str, worker: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/intents/{intent_id}/release",
            json={"worker": worker},
        )

    def conclude(
        self,
        project_id: str,
        intent_id: str,
        worker: str,
        description: str,
        fact_fields: dict[str, Any] | None = None,
    ) -> ApiResult:
        body: dict[str, Any] = {"worker": worker, "description": description}
        if fact_fields:
            for key in (
                "scope", "vuln_type", "severity", "parent_fact", "verification_of", "goal_type", "status",
                "recon_category", "recon_executed", "recon_found_results",
                "recon_tool", "recon_target", "recon_evidence_ref", "coverage_refs", "observed_surfaces",
                "schema_version", "kind", "summary", "subject", "data", "parent_fact_ids",
                "evidence_refs", "confidence", "created_by",
            ):
                value = fact_fields.get(key)
                if value is not None:
                    body[key] = value
        return self._request_json(
            "POST",
            f"/projects/{project_id}/intents/{intent_id}/conclude",
            json=body,
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
            "schema_version", "kind", "summary", "subject", "data", "parent_fact_ids",
            "evidence_refs", "confidence", "created_by",
        ):
            value = fact_fields.get(key)
            if value is not None:
                body[key] = value
        return self._request_json(
            "POST",
            f"/projects/{project_id}/facts",
            json=body,
        )

    def complete(self, project_id: str, from_ids: list[str], description: str, worker: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/complete",
            json={"from": from_ids, "description": description, "worker": worker},
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
        return self._request_json(
            "POST",
            f"/projects/{project_id}/intents",
            json=body,
        )

    def create_attack_path(
        self, project_id: str, name: str, fact_chain: list[str], description: str, severity: str = "medium",
        status: str = "hypothesis",
    ) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/attack-paths",
            json={
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
            ("outcome", outcome),
            ("applicability_status", applicability_status),
        ):
            if value is not None:
                body[key] = value
        return self._request_json(
            "POST",
            f"/projects/{project_id}/coverage",
            json=body,
        )

    def upsert_surface_inventory(self, project_id: str, **surface: Any) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/surfaces",
            json=surface,
        )

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
        return self._request_json(
            "PUT",
            f"/projects/{project_id}/coverage/{coverage_id}",
            json=body,
        )

    def bind_coverage_intent(self, project_id: str, coverage_id: str, intent_id: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/coverage/{coverage_id}/intents",
            json={"intent_id": intent_id},
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
        return self._request_json(
            "POST",
            f"/projects/{project_id}/hypothesis-work",
            json={
                "hypothesis": hypothesis,
                "coverage": coverage,
                "intent": intent,
                "surface_ids": surface_ids,
            },
        )

    def create_hypothesis(self, project_id: str, candidate: dict[str, Any]) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/hypotheses",
            json=candidate,
        )

    def update_hypothesis(
        self,
        project_id: str,
        hypothesis_id: str,
        **fields: Any,
    ) -> ApiResult:
        return self._request_json(
            "PUT",
            f"/projects/{project_id}/hypotheses/{hypothesis_id}",
            json={key: value for key, value in fields.items() if value is not None},
        )

    def record_execution_success(
        self,
        project_id: str,
        intent_id: str,
        worker: str,
        task_log_id: str,
    ) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/intents/{intent_id}/execution-success",
            json={"worker": worker, "task_log_id": task_log_id},
        )

    def record_conclusion_failure(
        self,
        project_id: str,
        intent_id: str,
        worker: str,
        error: str,
    ) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/intents/{intent_id}/conclusion-failure",
            json={"worker": worker, "error": error},
        )

    def get_task_log(self, project_id: str, log_id: str) -> TaskLog:
        response = self._session().get(
            self._url(f"/projects/{project_id}/logs/{log_id}"),
            timeout=self._detail_timeout,
        )
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
        return self._request_json(
            "POST",
            f"/projects/{project_id}/intents/{intent_id}/failure",
            json={
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
        return self._request_json(
            "POST",
            f"/projects/{project_id}/reason/failure",
            json={
                "worker": worker,
                "error": error,
                "max_attempts": max_attempts,
                "backoff_seconds": backoff_seconds,
            },
        )

    def record_reason_success(self, project_id: str, worker: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/reason/success",
            json={"worker": worker},
        )

    def advance_phase(self, project_id: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/phase/advance",
            json={},
        )

    def update_phase(self, project_id: str, phase: str) -> ApiResult:
        return self._request_json(
            "PUT",
            f"/projects/{project_id}/phase",
            json={"phase": phase},
        )

    def mark_needs_attention(
        self,
        project_id: str,
        worker: str,
        reason_code: str,
        detail: str,
    ) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/needs-attention",
            json={
                "worker": worker,
                "reason_code": reason_code,
                "detail": detail,
            },
        )

    def update_mode(self, project_id: str, mode: str) -> ApiResult:
        return self._request_json(
            "PUT",
            f"/projects/{project_id}/mode",
            json={"mode": mode},
        )

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
        body = {
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
        return self._request_json(
            "POST",
            f"/projects/{project_id}/logs",
            json=body,
        )

    def _request_json(self, method: str, path: str, json: dict[str, Any]) -> ApiResult:
        try:
            response = self._session().request(
                method,
                self._url(path),
                json=json,
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            LOG.warning("request failed method=%s path=%s error=%s", method, path, exc)
            return ApiResult(status_code=0, text=str(exc))
        data: Any | None = None
        if response.headers.get("content-type", "").startswith("application/json"):
            data = response.json()
        return ApiResult(status_code=response.status_code, data=data, text=response.text)

    def _url(self, path: str) -> str:
        return f"{self._base_url}{path}"

    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is not None:
            return session

        session = requests.Session()
        adapter = HTTPAdapter(pool_connections=64, pool_maxsize=64, pool_block=False)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        self._local.session = session
        with self._sessions_lock:
            self._sessions[threading.get_ident()] = session
        return session

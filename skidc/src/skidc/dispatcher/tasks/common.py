from __future__ import annotations

import logging
import re
import shlex
import time
import uuid
from dataclasses import dataclass

from skidc.dispatcher.config import DispatchConfig, WorkerConfig
from skidc.dispatcher.protocol.client import SkidcClient
from skidc.dispatcher.runtime.cancellation import TaskCancellation
from skidc.dispatcher.runtime.containers import ContainerManager
from skidc.dispatcher.runtime.heartbeat import HeartbeatLease
from skidc.dispatcher.runtime.process import ProcessResult

HEALTHCHECK_COMMUNICATE_GRACE_SECONDS = 10
PROCESS_COMMUNICATE_GRACE_SECONDS = 15
LOG_PREVIEW_LIMIT = 1200
GRAPH_SNAPSHOT_ROOT = "/tmp/skidc-prompts"
ARGV_ARG_PREVIEW_LIMIT = 160
OPERATION_FIELD_PREVIEW_LIMIT = 500
GRAPH_SNAPSHOT_RE = re.compile(r"(/tmp/skidc-prompts/[^\s]+/graph\.yaml)")
LOG = logging.getLogger(__name__)


@dataclass(slots=True)
class HealthcheckRun:
    result: ProcessResult
    duration_ms: int


@dataclass(slots=True)
class ConcludeWriteResult:
    status: str
    fact_id: str | None = None


def preview(text: str, limit: int = LOG_PREVIEW_LIMIT) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[:limit] + "..."


def did_timeout(result: ProcessResult) -> bool:
    return not result.cancelled and (result.timed_out or result.returncode in (124, 137))


def cancel_reason(result: ProcessResult, cancellation: TaskCancellation | None = None) -> str | None:
    if result.cancelled:
        return result.cancel_reason or "cancelled"
    if cancellation is not None:
        return cancellation.reason
    return None


def communicate_timeout(timeout_seconds: int, grace_seconds: int = PROCESS_COMMUNICATE_GRACE_SECONDS) -> int:
    return timeout_seconds + grace_seconds


def task_healthcheck_enabled(config: DispatchConfig) -> bool:
    return config.runtime.worker_healthcheck == "startup_and_task"


def write_graph_snapshot_reference(
    container_manager: ContainerManager,
    container_name: str,
    graph_yaml: str,
    *,
    phase: str,
) -> str:
    """Write the (potentially large) graph YAML into a file inside the container and
    return a prompt fragment that points the agent at that file, instead of inlining a
    huge blob into argv (which can blow past arg-length limits)."""
    path = f"{GRAPH_SNAPSHOT_ROOT}/{phase}-{uuid.uuid4().hex[:12]}/graph.yaml"
    container_manager.write_text_file(container_name, path, graph_yaml)
    return (
        "The graph YAML snapshot is stored in this file inside the current container:\n\n"
        f"{path}\n\n"
        "Before using the graph, read the entire file and treat its contents as the YAML snapshot "
        "for this Graph section."
    )


def format_worker_input(
    prompt: str,
    argv: list[str],
    *,
    task_type: str,
    phase: str,
    worker_name: str,
    operation: str,
    project_id: str | None = None,
    intent_id: str | None = None,
    intent_description: str | None = None,
    target: str | None = None,
    port: int | None = None,
    surface_type: str | None = None,
    action_kind: str | None = None,
    priority: int | None = None,
    suggested_tools: list[str] | None = None,
    timeout_seconds: int | None = None,
) -> str:
    """Summarize the operation sent to a worker without storing the full prompt.

    The full prompt can be thousands of characters and often repeats the graph.
    Logs should make the attempted action clear, while keeping prompt text out of
    persisted task logs and reports.
    """
    lines = [
        f"task_type: {task_type}",
        f"phase: {phase}",
        f"operation: {_compact_field(operation)}",
        f"worker: {worker_name}",
    ]
    if project_id:
        lines.append(f"project_id: {project_id}")
    if intent_id:
        lines.append(f"intent_id: {intent_id}")
    if intent_description:
        lines.append(f"intent_description: {_compact_field(intent_description)}")
    for label, value in (
        ("target", target),
        ("port", port),
        ("surface_type", surface_type),
        ("action_kind", action_kind),
        ("priority", priority),
    ):
        if value is not None:
            lines.append(f"{label}: {value}")
    if suggested_tools:
        lines.append(f"suggested_tools: {', '.join(suggested_tools)}")
    if timeout_seconds is not None:
        lines.append(f"timeout_seconds: {timeout_seconds}")
    lines.append(f"graph_snapshot: {_extract_graph_snapshot_path(prompt) or '(none)'}")
    lines.append(f"argv_summary: {_summarize_argv(argv)}")
    return "\n".join(lines)


def _extract_graph_snapshot_path(prompt: str) -> str | None:
    match = GRAPH_SNAPSHOT_RE.search(prompt)
    return match.group(1) if match else None


def _summarize_argv(argv: list[str]) -> str:
    summarized = []
    for arg in argv:
        if "\n" in arg or len(arg) > ARGV_ARG_PREVIEW_LIMIT:
            summarized.append(f"<omitted long argument chars={len(arg)}>")
        else:
            summarized.append(arg)
    return shlex.join(summarized)


def _compact_field(value: str) -> str:
    compact = " ".join(value.split())
    if len(compact) <= OPERATION_FIELD_PREVIEW_LIMIT:
        return compact
    return compact[:OPERATION_FIELD_PREVIEW_LIMIT] + "..."


def run_healthcheck(
    container_manager: ContainerManager,
    container_name: str,
    worker: WorkerConfig,
    command: list[str],
    *,
    timeout_seconds: int,
    lease: HeartbeatLease | None = None,
    cancellation: TaskCancellation | None = None,
) -> HealthcheckRun:
    process = container_manager.build_exec_process(
        container_name,
        dict(worker.env),
        command,
        timeout_seconds=timeout_seconds,
    )
    process.start()
    if lease is not None:
        lease.attach_process(process)
    if cancellation is not None:
        cancellation.attach_process(process)
    started = time.perf_counter()
    try:
        result = process.communicate(timeout=communicate_timeout(timeout_seconds, HEALTHCHECK_COMMUNICATE_GRACE_SECONDS))
    finally:
        if lease is not None:
            lease.attach_process(None)
        if cancellation is not None:
            cancellation.attach_process(None)
    duration_ms = int((time.perf_counter() - started) * 1000)
    return HealthcheckRun(result=result, duration_ms=duration_ms)


def run_worker_process(
    container_manager: ContainerManager,
    container_name: str,
    worker: WorkerConfig,
    argv: list[str],
    *,
    phase: str,
    timeout_seconds: int,
    lease: HeartbeatLease | None = None,
    cancellation: TaskCancellation | None = None,
) -> ProcessResult:
    LOG.info(
        "starting container exec container=%s worker=%s phase=%s timeout=%ss",
        container_name, worker.name, phase, timeout_seconds,
    )
    process = container_manager.build_exec_process(
        container_name,
        dict(worker.env),
        argv,
        timeout_seconds=timeout_seconds,
    )
    process.start()
    if lease is not None:
        lease.attach_process(process)
    if cancellation is not None:
        cancellation.attach_process(process)
    try:
        return process.communicate(timeout=communicate_timeout(timeout_seconds))
    finally:
        if lease is not None:
            lease.attach_process(None)
        if cancellation is not None:
            cancellation.attach_process(None)


def project_allows_conclude_fallback(client: SkidcClient, project_id: str, *, worker_name: str, intent_id: str) -> bool:
    project = client.get_project(project_id)
    if project.project.status == "active":
        return True
    LOG.info(
        "skip conclude fallback because project is no longer active project=%s intent=%s worker=%s status=%s",
        project_id, intent_id, worker_name, project.project.status,
    )
    return False


def best_effort_release_reason(client: SkidcClient, project_id: str, worker_name: str) -> None:
    response = client.release_reason(project_id, worker_name)
    if not response.ok and response.status_code not in (403, 409):
        LOG.warning("reason release failed project=%s worker=%s status=%s", project_id, worker_name, response.status_code)
    elif response.ok:
        LOG.info("released reason project=%s worker=%s", project_id, worker_name)
    else:
        LOG.info("reason release skipped project=%s worker=%s status=%s", project_id, worker_name, response.status_code)


def write_conclude_result(
    client: SkidcClient,
    project_id: str,
    intent_id: str,
    worker_name: str,
    description: str,
    *,
    source: str,
    phase_ms: int,
    total_ms: int | None = None,
    fact_fields: dict[str, object] | None = None,
) -> str:
    return write_conclude_result_with_fact_id(
        client, project_id, intent_id, worker_name, description,
        source=source, phase_ms=phase_ms, total_ms=total_ms, fact_fields=fact_fields,
    ).status


def write_conclude_result_with_fact_id(
    client: SkidcClient,
    project_id: str,
    intent_id: str,
    worker_name: str,
    description: str,
    *,
    source: str,
    phase_ms: int,
    total_ms: int | None = None,
    fact_fields: dict[str, object] | None = None,
) -> ConcludeWriteResult:
    response = client.conclude(project_id, intent_id, worker_name, description, fact_fields)
    if response.ok:
        fact_id: str | None = None
        if isinstance(response.data, dict):
            fact = response.data.get("fact")
            if isinstance(fact, dict):
                candidate = fact.get("id")
                if isinstance(candidate, str) and candidate:
                    fact_id = candidate
        if total_ms is None:
            LOG.info(
                "intent concluded project=%s intent=%s worker=%s source=%s phase_ms=%s",
                project_id, intent_id, worker_name, source, phase_ms,
            )
        else:
            LOG.info(
                "intent concluded project=%s intent=%s worker=%s source=%s phase_ms=%s total_ms=%s",
                project_id, intent_id, worker_name, source, phase_ms, total_ms,
            )
        return ConcludeWriteResult(status="success", fact_id=fact_id)
    if response.status_code == 403:
        LOG.info(
            "project became inactive during conclude project=%s intent=%s worker=%s",
            project_id, intent_id, worker_name,
        )
    else:
        LOG.warning(
            "conclude write failed project=%s intent=%s worker=%s status=%s body=%s",
            project_id, intent_id, worker_name, response.status_code, response.text,
        )
    best_effort_release(client, project_id, intent_id, worker_name)
    return ConcludeWriteResult(status="failed", fact_id=None)


def best_effort_release(client: SkidcClient, project_id: str, intent_id: str, worker_name: str) -> None:
    response = client.release(project_id, intent_id, worker_name)
    if not response.ok and response.status_code not in (403, 409):
        LOG.warning(
            "release failed project=%s intent=%s worker=%s status=%s",
            project_id, intent_id, worker_name, response.status_code,
        )
    elif response.ok:
        LOG.info("released intent project=%s intent=%s worker=%s", project_id, intent_id, worker_name)
    else:
        LOG.info(
            "release skipped project=%s intent=%s worker=%s status=%s",
            project_id, intent_id, worker_name, response.status_code,
        )


def save_task_log(
    client: SkidcClient,
    project_id: str,
    task_type: str,
    worker_name: str,
    phase: str,
    result: ProcessResult,
    duration_ms: int,
    intent_id: str | None = None,
    stdin: str | None = None,
) -> str | None:
    """Best-effort: save execution log to server. Failures only log WARNING, never block the main flow."""
    try:
        response = client.create_task_log(
            project_id=project_id,
            task_type=task_type,
            intent_id=intent_id,
            worker_name=worker_name,
            phase=phase,
            stdin=stdin,
            stdout=result.stdout,
            stderr=result.stderr,
            return_code=result.returncode,
            timed_out=result.timed_out,
            duration_ms=duration_ms,
        )
        if response.ok and isinstance(response.data, dict):
            value = response.data.get("id")
            return str(value) if value else None
        LOG.warning(
            "failed to save task log project=%s phase=%s status=%s",
            project_id, phase, response.status_code,
        )
    except Exception:
        LOG.warning("failed to save task log project=%s phase=%s", project_id, phase, exc_info=True)
    return None

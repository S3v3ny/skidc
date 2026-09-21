from __future__ import annotations

import logging
import time

from skidc.dispatcher.config import DispatchConfig, WorkerConfig
from skidc.dispatcher.coverage_profile import normalize_surface_entry
from skidc.dispatcher.contracts import parse_json_output, validate_explore_payload
from skidc.dispatcher.prompting import format_dispatch_graph, format_intent_coverage, format_scope_constraints, load_prompt, render_prompt
from skidc.dispatcher.protocol.client import SkidcClient
from skidc.dispatcher.runtime.cancellation import TaskCancellation
from skidc.dispatcher.runtime.containers import ContainerManager
from skidc.dispatcher.runtime.heartbeat import HeartbeatLease
from skidc.dispatcher.tasks.common import (
    best_effort_release,
    cancel_reason,
    did_timeout,
    format_worker_input,
    project_allows_conclude_fallback,
    preview,
    run_healthcheck,
    run_worker_process,
    save_task_log,
    task_healthcheck_enabled,
    write_conclude_result,
    write_graph_snapshot_reference,
)
from skidc.dispatcher.workers.registry import get_driver
from skidc.server.models import Intent, ProjectDetail

LOG = logging.getLogger(__name__)


def run_explore_task(
    config: DispatchConfig,
    client: SkidcClient,
    container_manager: ContainerManager,
    project: ProjectDetail,
    export_yaml: str,
    intent: Intent,
    worker: WorkerConfig,
    cancellation: TaskCancellation,
) -> str:
    driver = get_driver(worker.type)
    task_started = time.perf_counter()
    healthcheck_timeout = config.runtime.healthcheck_timeout
    lease = HeartbeatLease.for_intent(client, project.project.id, intent.id, worker.name, config.runtime.interval)
    lease.start()
    try:
        container_name = container_manager.ensure_running(project.project.id)

        if task_healthcheck_enabled(config):
            healthcheck = run_healthcheck(
                container_manager, container_name, worker, driver.build_healthcheck(worker),
                timeout_seconds=healthcheck_timeout, lease=lease, cancellation=cancellation,
            )
            cancelled = cancel_reason(healthcheck.result, cancellation)
            if cancelled is not None:
                LOG.info("explore cancelled during healthcheck project=%s intent=%s worker=%s reason=%s", project.project.id, intent.id, worker.name, cancelled)
                best_effort_release(client, project.project.id, intent.id, worker.name)
                return "cancelled"
            if lease.failure is not None:
                best_effort_release(client, project.project.id, intent.id, worker.name)
                return "failed"
            if healthcheck.result.returncode != 0:
                LOG.warning("worker unhealthy project=%s intent=%s worker=%s healthcheck_ms=%s stderr=%s", project.project.id, intent.id, worker.name, healthcheck.duration_ms, preview(healthcheck.result.stderr))
                best_effort_release(client, project.project.id, intent.id, worker.name)
                return "unhealthy"

        if intent.execution_status == "succeeded" and intent.execution_artifact_ref:
            return _resume_conclusion_from_artifact(
                config,
                client,
                container_manager,
                container_name,
                worker,
                driver,
                project,
                intent,
                export_yaml,
                lease,
                cancellation,
            )

        prompt = render_prompt(
            load_prompt(config.runtime.prompt_group, "explore.md"),
            {
                "graph_yaml": write_graph_snapshot_reference(
                    container_manager, container_name,
                    format_dispatch_graph(project) if project.project.planning_version >= 3 else export_yaml.strip(),
                    phase="explore_execute",
                ),
                "intent_id": intent.id,
                "intent_description": intent.description,
                "scope_constraints": format_scope_constraints(project),
                "intent_coverage": format_intent_coverage(project, intent.id),
            },
        )

        session = driver.prepare_session()
        execute = driver.build_execute(worker, prompt, session)
        session = execute.session
        execute_started = time.perf_counter()
        first = run_worker_process(
            container_manager, container_name, worker, execute.argv,
            phase="explore_execute", timeout_seconds=config.tasks.explore.timeout,
            lease=lease, cancellation=cancellation,
        )
        execute_ms = int((time.perf_counter() - execute_started) * 1000)
        execution_log_id = save_task_log(
            client, project.project.id, "explore", worker.name, "explore_execute",
            first, execute_ms, intent_id=intent.id,
            stdin=format_worker_input(
                prompt,
                execute.argv,
                task_type="explore",
                phase="explore_execute",
                worker_name=worker.name,
                operation="explore assigned intent",
                project_id=project.project.id,
                intent_id=intent.id,
                intent_description=intent.description,
                target=intent.target,
                port=intent.port,
                surface_type=intent.surface_type,
                action_kind=intent.action_kind,
                priority=intent.priority,
                suggested_tools=intent.suggested_tools,
                timeout_seconds=config.tasks.explore.timeout,
            ),
        )
        session = driver.extract_session(session, first.stdout, first.stderr)
        cancelled = cancel_reason(first, cancellation)
        if cancelled is not None:
            LOG.info("explore cancelled project=%s intent=%s worker=%s reason=%s execute_ms=%s", project.project.id, intent.id, worker.name, cancelled, execute_ms)
            best_effort_release(client, project.project.id, intent.id, worker.name)
            return "cancelled"
        if lease.failure is not None:
            best_effort_release(client, project.project.id, intent.id, worker.name)
            return "failed"
        if not did_timeout(first) and first.returncode == 0:
            if execution_log_id:
                client.record_execution_success(
                    project.project.id, intent.id, worker.name, execution_log_id
                )
            try:
                model_output = driver.extract_response_text(first.stdout, first.stderr)
                payload = parse_json_output(model_output)
                kind, data = validate_explore_payload(payload)
            except Exception as exc:
                LOG.warning("explore parse failed project=%s intent=%s worker=%s error=%s execute_ms=%s stdout=%s stderr=%s", project.project.id, intent.id, worker.name, exc, execute_ms, preview(first.stdout), preview(first.stderr))
                return _try_conclude_fallback(config, client, container_manager, container_name, worker, driver, project, intent, export_yaml, session, lease, cancellation)
            if kind == "rejected":
                LOG.warning("explore rejected project=%s intent=%s worker=%s execute_ms=%s stdout=%s", project.project.id, intent.id, worker.name, execute_ms, preview(first.stdout))
                best_effort_release(client, project.project.id, intent.id, worker.name)
                return "rejected"
            return write_conclude_result(
                client, project.project.id, intent.id, worker.name, data["description"],
                source="explore_execute", phase_ms=execute_ms, total_ms=int((time.perf_counter() - task_started) * 1000),
                fact_fields=_normalize_observed_surfaces(project, data),
            )
        if did_timeout(first):
            LOG.warning("explore timed out project=%s intent=%s worker=%s execute_ms=%s stdout=%s stderr=%s", project.project.id, intent.id, worker.name, execute_ms, preview(first.stdout), preview(first.stderr))
            return _try_conclude_fallback(config, client, container_manager, container_name, worker, driver, project, intent, export_yaml, session, lease, cancellation)
        LOG.warning("explore command failed project=%s intent=%s worker=%s code=%s execute_ms=%s stdout=%s stderr=%s", project.project.id, intent.id, worker.name, first.returncode, execute_ms, preview(first.stdout), preview(first.stderr))
        best_effort_release(client, project.project.id, intent.id, worker.name)
        return "failed"
    except Exception:
        LOG.exception("explore task crashed project=%s intent=%s worker=%s", project.project.id, intent.id, worker.name)
        best_effort_release(client, project.project.id, intent.id, worker.name)
        return "failed"
    finally:
        lease.stop()


def _resume_conclusion_from_artifact(
    config: DispatchConfig,
    client: SkidcClient,
    container_manager: ContainerManager,
    container_name: str,
    worker: WorkerConfig,
    driver,
    project: ProjectDetail,
    intent: Intent,
    export_yaml: str,
    lease: HeartbeatLease,
    cancellation: TaskCancellation,
) -> str:
    """Resume parse/commit without repeating the target-side scan."""
    project_id = project.project.id
    ref = intent.execution_artifact_ref or ""
    if not ref.startswith("task_log:"):
        client.record_conclusion_failure(
            project_id, intent.id, worker.name, "Unsupported execution artifact reference"
        )
        return "success"
    log_id = ref.split(":", 1)[1]
    try:
        artifact = client.get_task_log(project_id, log_id)
    except Exception as exc:
        LOG.warning(
            "execution artifact unavailable project=%s intent=%s log=%s error=%s",
            project_id, intent.id, log_id, exc,
        )
        client.record_conclusion_failure(
            project_id, intent.id, worker.name, f"Execution artifact unavailable: {exc}"
        )
        return "success"

    try:
        model_output = driver.extract_response_text(artifact.stdout or "", artifact.stderr or "")
        payload = parse_json_output(model_output)
        kind, data = validate_explore_payload(payload)
        if kind != "rejected":
            return write_conclude_result(
                client, project_id, intent.id, worker.name, data["description"],
                source="stored_execution_artifact", phase_ms=0,
                fact_fields=_normalize_observed_surfaces(project, data),
            )
    except Exception as exc:
        LOG.info(
            "stored artifact needs conclusion-only pass project=%s intent=%s error=%s",
            project_id, intent.id, exc,
        )

    if cancellation.is_cancelled or lease.failure is not None:
        best_effort_release(client, project_id, intent.id, worker.name)
        return "cancelled" if cancellation.is_cancelled else "failed"

    artifact_text = "\n".join(
        part for part in (
            (artifact.stdout or "")[-24000:],
            (artifact.stderr or "")[-8000:],
        )
        if part
    )
    base_prompt = render_prompt(
        load_prompt(config.runtime.prompt_group, "explore_conclude.md"),
        {
            "graph_yaml": write_graph_snapshot_reference(
                container_manager, container_name,
                format_dispatch_graph(project) if project.project.planning_version >= 3 else export_yaml.strip(),
                phase="explore_conclude_resume",
            ),
            "intent_id": intent.id,
            "intent_description": intent.description,
            "scope_constraints": format_scope_constraints(project),
            "intent_coverage": format_intent_coverage(project, intent.id),
        },
    )
    prompt = (
        base_prompt
        + "\n\nThe target-side execution already succeeded. Do not run any target commands "
        "and do not repeat the scan. Convert only the stored execution artifact below "
        "into the required conclusion JSON.\n\n<stored_execution_artifact>\n"
        + artifact_text
        + "\n</stored_execution_artifact>"
    )
    command = driver.build_execute(worker, prompt, driver.prepare_session())
    started = time.perf_counter()
    result = run_worker_process(
        container_manager, container_name, worker, command.argv,
        phase="explore_conclude_resume",
        timeout_seconds=config.tasks.explore.conclude_timeout,
        lease=lease,
        cancellation=cancellation,
    )
    duration_ms = int((time.perf_counter() - started) * 1000)
    save_task_log(
        client, project_id, "explore", worker.name, "explore_conclude_resume",
        result, duration_ms, intent_id=intent.id,
        stdin=format_worker_input(
            prompt, command.argv, task_type="explore", phase="explore_conclude_resume",
            worker_name=worker.name, operation="conclude from stored execution artifact",
            project_id=project_id, intent_id=intent.id,
            intent_description=intent.description,
            timeout_seconds=config.tasks.explore.conclude_timeout,
        ),
    )
    try:
        if result.timed_out or result.returncode != 0:
            raise RuntimeError(
                f"conclusion-only worker failed code={result.returncode} timed_out={result.timed_out}"
            )
        model_output = driver.extract_response_text(result.stdout, result.stderr)
        payload = parse_json_output(model_output)
        kind, data = validate_explore_payload(payload)
        if kind == "rejected":
            raise RuntimeError("conclusion-only worker rejected the artifact")
    except Exception as exc:
        LOG.warning(
            "conclusion-only pass failed project=%s intent=%s error=%s",
            project_id, intent.id, exc,
        )
        client.record_conclusion_failure(project_id, intent.id, worker.name, str(exc))
        return "success"
    return write_conclude_result(
        client, project_id, intent.id, worker.name, data["description"],
        source="explore_conclude_resume", phase_ms=duration_ms,
        fact_fields=_normalize_observed_surfaces(project, data),
    )


def _try_conclude_fallback(
    config: DispatchConfig,
    client: SkidcClient,
    container_manager: ContainerManager,
    container_name: str,
    worker: WorkerConfig,
    driver,
    project: ProjectDetail,
    intent: Intent,
    export_yaml: str,
    session: str | None,
    lease: HeartbeatLease,
    cancellation: TaskCancellation,
) -> str:
    project_id = project.project.id
    if not driver.supports_conclude() or not session:
        LOG.info("conclude fallback unavailable project=%s intent=%s worker=%s supports_conclude=%s has_session=%s", project_id, intent.id, worker.name, driver.supports_conclude(), bool(session))
        best_effort_release(client, project_id, intent.id, worker.name)
        return "failed"
    if lease.failure is not None:
        best_effort_release(client, project_id, intent.id, worker.name)
        return "failed"
    if cancellation.is_cancelled:
        LOG.info("conclude fallback skipped because task was cancelled project=%s intent=%s worker=%s reason=%s", project_id, intent.id, worker.name, cancellation.reason)
        best_effort_release(client, project_id, intent.id, worker.name)
        return "cancelled"

    if not project_allows_conclude_fallback(client, project_id, worker_name=worker.name, intent_id=intent.id):
        best_effort_release(client, project_id, intent.id, worker.name)
        return "failed"

    container_name = container_manager.ensure_running(project_id)

    prompt = render_prompt(
        load_prompt(config.runtime.prompt_group, "explore_conclude.md"),
        {
            "graph_yaml": write_graph_snapshot_reference(
                container_manager, container_name,
                format_dispatch_graph(project) if project.project.planning_version >= 3 else export_yaml.strip(),
                phase="explore_conclude",
            ),
            "intent_id": intent.id,
            "intent_description": intent.description,
            "scope_constraints": format_scope_constraints(project),
            "intent_coverage": format_intent_coverage(project, intent.id),
        },
    )
    conclude_argv = driver.build_conclude(worker, prompt, session)
    LOG.info("starting conclude fallback project=%s intent=%s worker=%s", project_id, intent.id, worker.name)
    conclude_started = time.perf_counter()
    result = run_worker_process(
        container_manager, container_name, worker, conclude_argv,
        phase="explore_conclude", timeout_seconds=config.tasks.explore.conclude_timeout,
        lease=lease, cancellation=cancellation,
    )
    conclude_ms = int((time.perf_counter() - conclude_started) * 1000)
    save_task_log(
        client, project_id, "explore", worker.name, "explore_conclude",
        result, conclude_ms, intent_id=intent.id,
        stdin=format_worker_input(
            prompt,
            conclude_argv,
            task_type="explore",
            phase="explore_conclude",
            worker_name=worker.name,
            operation="summarize assigned intent after execute fallback",
            project_id=project_id,
            intent_id=intent.id,
            intent_description=intent.description,
            target=intent.target,
            port=intent.port,
            surface_type=intent.surface_type,
            action_kind=intent.action_kind,
            priority=intent.priority,
            suggested_tools=intent.suggested_tools,
            timeout_seconds=config.tasks.explore.conclude_timeout,
        ),
    )
    cancelled = cancel_reason(result, cancellation)
    if cancelled is not None:
        LOG.info("conclude cancelled project=%s intent=%s worker=%s reason=%s conclude_ms=%s", project_id, intent.id, worker.name, cancelled, conclude_ms)
        best_effort_release(client, project_id, intent.id, worker.name)
        return "cancelled"
    if lease.failure is not None:
        best_effort_release(client, project_id, intent.id, worker.name)
        return "failed"
    if result.timed_out or result.returncode != 0:
        LOG.warning("conclude failed project=%s intent=%s worker=%s code=%s timed_out=%s conclude_ms=%s stdout=%s stderr=%s", project_id, intent.id, worker.name, result.returncode, result.timed_out, conclude_ms, preview(result.stdout), preview(result.stderr))
        best_effort_release(client, project_id, intent.id, worker.name)
        return "failed"
    try:
        model_output = driver.extract_response_text(result.stdout, result.stderr)
        payload = parse_json_output(model_output)
        kind, data = validate_explore_payload(payload)
    except Exception as exc:
        LOG.warning("conclude parse failed project=%s intent=%s worker=%s error=%s conclude_ms=%s stdout=%s stderr=%s", project_id, intent.id, worker.name, exc, conclude_ms, preview(result.stdout), preview(result.stderr))
        best_effort_release(client, project_id, intent.id, worker.name)
        return "failed"
    if kind == "rejected":
        LOG.warning("conclude rejected project=%s intent=%s worker=%s conclude_ms=%s stdout=%s", project_id, intent.id, worker.name, conclude_ms, preview(result.stdout))
        best_effort_release(client, project_id, intent.id, worker.name)
        return "rejected"
    return write_conclude_result(
        client, project_id, intent.id, worker.name, data["description"],
        source="explore_conclude", phase_ms=conclude_ms,
        fact_fields=_normalize_observed_surfaces(project, data),
    )

def _normalize_observed_surfaces(project: ProjectDetail, data: dict) -> dict:
    normalized = dict(data)
    raw_surfaces = data.get("observed_surfaces")
    if not isinstance(raw_surfaces, list):
        return normalized
    surfaces = []
    for entry in raw_surfaces:
        surface = normalize_surface_entry(entry, support_ports=project.project.scope_policy.support_ports)
        if surface is not None:
            surfaces.append(surface)
    normalized["observed_surfaces"] = surfaces
    return normalized

from __future__ import annotations

import logging
import time

from skidc.dispatcher.config import DispatchConfig, WorkerConfig
from skidc.dispatcher.contracts import (
    parse_json_output,
    validate_bootstrap_conclude_payload,
    validate_bootstrap_execute_payload,
)
from skidc.dispatcher.prompting import format_hints, format_scope_constraints, load_prompt, render_prompt
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
    write_conclude_result_with_fact_id,
)
from skidc.dispatcher.workers.registry import get_driver
from skidc.server.models import Intent, ProjectDetail

LOG = logging.getLogger(__name__)


def run_bootstrap_task(
    config: DispatchConfig,
    client: SkidcClient,
    container_manager: ContainerManager,
    project: ProjectDetail,
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
                best_effort_release(client, project.project.id, intent.id, worker.name)
                return "cancelled"
            if lease.failure is not None:
                best_effort_release(client, project.project.id, intent.id, worker.name)
                return "failed"
            if healthcheck.result.returncode != 0:
                LOG.warning("worker unhealthy project=%s intent=%s worker=%s healthcheck_ms=%s stderr=%s", project.project.id, intent.id, worker.name, healthcheck.duration_ms, preview(healthcheck.result.stderr))
                best_effort_release(client, project.project.id, intent.id, worker.name)
                return "unhealthy"

        prompt = render_prompt(
            load_prompt(config.runtime.prompt_group, "bootstrap.md"),
            _bootstrap_prompt_replacements(project),
        )

        session = driver.prepare_session()
        execute = driver.build_execute(worker, prompt, session)
        session = execute.session
        execute_started = time.perf_counter()
        first = run_worker_process(
            container_manager, container_name, worker, execute.argv,
            phase="bootstrap", timeout_seconds=config.tasks.bootstrap.timeout,
            lease=lease, cancellation=cancellation,
        )
        execute_ms = int((time.perf_counter() - execute_started) * 1000)
        save_task_log(
            client, project.project.id, "bootstrap", worker.name, "bootstrap",
            first, execute_ms, intent_id=intent.id,
            stdin=format_worker_input(
                prompt,
                execute.argv,
                task_type="bootstrap",
                phase="bootstrap",
                worker_name=worker.name,
                operation="bootstrap initial project exploration",
                project_id=project.project.id,
                intent_id=intent.id,
                intent_description=intent.description,
                target=intent.target,
                port=intent.port,
                surface_type=intent.surface_type,
                action_kind=intent.action_kind,
                priority=intent.priority,
                suggested_tools=intent.suggested_tools,
                timeout_seconds=config.tasks.bootstrap.timeout,
            ),
        )
        session = driver.extract_session(session, first.stdout, first.stderr)
        cancelled = cancel_reason(first, cancellation)
        if cancelled is not None:
            best_effort_release(client, project.project.id, intent.id, worker.name)
            return "cancelled"
        if lease.failure is not None:
            best_effort_release(client, project.project.id, intent.id, worker.name)
            return "failed"
        if not did_timeout(first) and first.returncode == 0:
            try:
                model_output = driver.extract_response_text(first.stdout, first.stderr)
                payload = parse_json_output(model_output)
                kind, data = validate_bootstrap_execute_payload(payload)
            except Exception as exc:
                LOG.warning("bootstrap parse failed project=%s intent=%s worker=%s error=%s execute_ms=%s stdout=%s stderr=%s", project.project.id, intent.id, worker.name, exc, execute_ms, preview(first.stdout), preview(first.stderr))
                return _try_conclude_fallback(config, client, container_manager, container_name, worker, driver, project, intent, session, lease, cancellation)
            if kind == "rejected":
                LOG.warning("bootstrap rejected project=%s intent=%s worker=%s execute_ms=%s stdout=%s", project.project.id, intent.id, worker.name, execute_ms, preview(first.stdout))
                best_effort_release(client, project.project.id, intent.id, worker.name)
                return "rejected"
            return _write_bootstrap_complete_result(
                client, project.project.id, intent.id, worker.name,
                data["fact_description"], data["complete_description"],
                source="bootstrap", phase_ms=execute_ms, total_ms=int((time.perf_counter() - task_started) * 1000),
            )
        if did_timeout(first):
            LOG.warning("bootstrap timed out project=%s intent=%s worker=%s execute_ms=%s stdout=%s stderr=%s", project.project.id, intent.id, worker.name, execute_ms, preview(first.stdout), preview(first.stderr))
            return _try_conclude_fallback(config, client, container_manager, container_name, worker, driver, project, intent, session, lease, cancellation)
        LOG.warning("bootstrap command failed project=%s intent=%s worker=%s code=%s execute_ms=%s stdout=%s stderr=%s", project.project.id, intent.id, worker.name, first.returncode, execute_ms, preview(first.stdout), preview(first.stderr))
        best_effort_release(client, project.project.id, intent.id, worker.name)
        return "failed"
    except Exception:
        LOG.exception("bootstrap task crashed project=%s intent=%s worker=%s", project.project.id, intent.id, worker.name)
        best_effort_release(client, project.project.id, intent.id, worker.name)
        return "failed"
    finally:
        lease.stop()


def _try_conclude_fallback(
    config: DispatchConfig,
    client: SkidcClient,
    container_manager: ContainerManager,
    container_name: str,
    worker: WorkerConfig,
    driver,
    project: ProjectDetail,
    intent: Intent,
    session: str | None,
    lease: HeartbeatLease,
    cancellation: TaskCancellation,
) -> str:
    if not driver.supports_conclude() or not session:
        LOG.info("bootstrap conclude fallback unavailable project=%s intent=%s worker=%s supports_conclude=%s has_session=%s", project.project.id, intent.id, worker.name, driver.supports_conclude(), bool(session))
        best_effort_release(client, project.project.id, intent.id, worker.name)
        return "failed"
    if lease.failure is not None:
        best_effort_release(client, project.project.id, intent.id, worker.name)
        return "failed"
    if cancellation.is_cancelled:
        best_effort_release(client, project.project.id, intent.id, worker.name)
        return "cancelled"

    if not project_allows_conclude_fallback(client, project.project.id, worker_name=worker.name, intent_id=intent.id):
        best_effort_release(client, project.project.id, intent.id, worker.name)
        return "failed"

    container_name = container_manager.ensure_running(project.project.id)

    prompt = render_prompt(
        load_prompt(config.runtime.prompt_group, "bootstrap_conclude.md"),
        _bootstrap_prompt_replacements(project),
    )
    conclude_argv = driver.build_conclude(worker, prompt, session)
    LOG.info("starting bootstrap conclude fallback project=%s intent=%s worker=%s", project.project.id, intent.id, worker.name)
    conclude_started = time.perf_counter()
    result = run_worker_process(
        container_manager, container_name, worker, conclude_argv,
        phase="bootstrap_conclude", timeout_seconds=config.tasks.bootstrap.conclude_timeout,
        lease=lease, cancellation=cancellation,
    )
    conclude_ms = int((time.perf_counter() - conclude_started) * 1000)
    save_task_log(
        client, project.project.id, "bootstrap", worker.name, "bootstrap_conclude",
        result, conclude_ms, intent_id=intent.id,
        stdin=format_worker_input(
            prompt,
            conclude_argv,
            task_type="bootstrap",
            phase="bootstrap_conclude",
            worker_name=worker.name,
            operation="summarize bootstrap result after execute fallback",
            project_id=project.project.id,
            intent_id=intent.id,
            intent_description=intent.description,
            target=intent.target,
            port=intent.port,
            surface_type=intent.surface_type,
            action_kind=intent.action_kind,
            priority=intent.priority,
            suggested_tools=intent.suggested_tools,
            timeout_seconds=config.tasks.bootstrap.conclude_timeout,
        ),
    )
    cancelled = cancel_reason(result, cancellation)
    if cancelled is not None:
        best_effort_release(client, project.project.id, intent.id, worker.name)
        return "cancelled"
    if lease.failure is not None:
        best_effort_release(client, project.project.id, intent.id, worker.name)
        return "failed"
    if result.timed_out or result.returncode != 0:
        LOG.warning("bootstrap conclude failed project=%s intent=%s worker=%s code=%s timed_out=%s conclude_ms=%s stdout=%s stderr=%s", project.project.id, intent.id, worker.name, result.returncode, result.timed_out, conclude_ms, preview(result.stdout), preview(result.stderr))
        best_effort_release(client, project.project.id, intent.id, worker.name)
        return "failed"
    try:
        model_output = driver.extract_response_text(result.stdout, result.stderr)
        payload = parse_json_output(model_output)
        kind, fact_description = validate_bootstrap_conclude_payload(payload)
    except Exception as exc:
        LOG.warning("bootstrap conclude parse failed project=%s intent=%s worker=%s error=%s conclude_ms=%s stdout=%s stderr=%s", project.project.id, intent.id, worker.name, exc, conclude_ms, preview(result.stdout), preview(result.stderr))
        best_effort_release(client, project.project.id, intent.id, worker.name)
        return "failed"
    if kind == "rejected":
        LOG.warning("bootstrap conclude rejected project=%s intent=%s worker=%s conclude_ms=%s stdout=%s", project.project.id, intent.id, worker.name, conclude_ms, preview(result.stdout))
        best_effort_release(client, project.project.id, intent.id, worker.name)
        return "rejected"
    return write_conclude_result(
        client, project.project.id, intent.id, worker.name, fact_description,
        source="bootstrap_conclude", phase_ms=conclude_ms,
    )


def _bootstrap_prompt_replacements(project: ProjectDetail) -> dict[str, str]:
    facts = {fact.id: fact.description for fact in project.facts}
    hints = [
        {"id": hint.id, "content": hint.content, "creator": hint.creator, "created_at": hint.created_at}
        for hint in project.hints
    ]
    return {
        "origin": facts.get("origin", ""),
        "goal": facts.get("goal", ""),
        "hints": format_hints(hints),
        "scope_constraints": format_scope_constraints(project),
    }


def _write_bootstrap_complete_result(
    client: SkidcClient,
    project_id: str,
    intent_id: str,
    worker_name: str,
    fact_description: str,
    complete_description: str,
    *,
    source: str,
    phase_ms: int,
    total_ms: int | None = None,
) -> str:
    conclude = write_conclude_result_with_fact_id(
        client, project_id, intent_id, worker_name, fact_description,
        source=source, phase_ms=phase_ms, total_ms=total_ms,
    )
    if conclude.status != "success":
        return "failed"
    if conclude.fact_id is None:
        LOG.warning("bootstrap complete deferred because conclude response omitted fact id project=%s intent=%s worker=%s source=%s", project_id, intent_id, worker_name, source)
        return "success"

    response = client.complete(project_id, [conclude.fact_id], complete_description, worker_name)
    if response.status_code in (403, 409):
        LOG.info("bootstrap complete deferred project=%s intent=%s worker=%s source=%s status=%s fact_id=%s", project_id, intent_id, worker_name, source, response.status_code, conclude.fact_id)
        return "success"
    if not response.ok:
        LOG.warning("bootstrap complete write failed project=%s intent=%s worker=%s source=%s fact_id=%s status=%s body=%s", project_id, intent_id, worker_name, source, conclude.fact_id, response.status_code, response.text)
        return "success"
    LOG.info("bootstrap completed project=%s intent=%s worker=%s source=%s from=%s phase_ms=%s", project_id, intent_id, worker_name, source, [conclude.fact_id], phase_ms)
    return "success"

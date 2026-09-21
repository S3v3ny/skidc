import json

from fastapi import APIRouter, HTTPException

from skidc.server.db import get_conn
from skidc.server.models import (
    ConcludeRequest,
    ConcludeResponse,
    CreateIntentRequest,
    Fact,
    HeartbeatRequest,
    Intent,
    RecordIntentConclusionFailureRequest,
    RecordIntentExecutionRequest,
    TaskFailureRequest,
)
from skidc.server.services import (
    bind_coverage_intent,
    coverage_work_key,
    conclude_intent_with_failure_fact,
    clear_completion_blocked,
    check_project_active,
    derive_recon_fact_fields,
    get_claimable_open_intent_or_404,
    get_releasable_open_intent_or_404,
    fact_to_model,
    intent_to_model,
    mark_intent_failure,
    next_fact_id,
    next_intent_id,
    project_meta_from_row,
    reconcile_fact_coverage,
    reconcile_project_attack_paths,
    upsert_surface_inventory_record,
    utcnow,
    validate_coverage_exists,
    validate_verification_reference,
    validate_facts_exist,
    validate_intent_creator_worker,
    validate_intent_scope,
    validate_goal_not_in_sources,
)

router = APIRouter(tags=["intents"])


@router.post(
    "/projects/{project_id}/intents",
    response_model=Intent,
    status_code=201,
)
def create_intent(project_id: str, body: CreateIntentRequest):
    with get_conn() as conn:
        project_row = check_project_active(conn, project_id)
        validate_facts_exist(conn, project_id, body.from_)
        validate_goal_not_in_sources(body.from_)
        validate_intent_creator_worker(body.creator, body.worker)
        validate_coverage_exists(conn, project_id, body.coverage_refs)
        project = project_meta_from_row(project_row)
        hypothesis_row = None
        if body.hypothesis_id:
            hypothesis_row = conn.execute(
                "SELECT * FROM hypotheses WHERE project_id = ? AND id = ?",
                (project_id, body.hypothesis_id),
            ).fetchone()
            if hypothesis_row is None:
                raise HTTPException(404, "Hypothesis not found")
            if project.planning_version < 2:
                raise HTTPException(409, "Hypothesis-bound Intents require planning_version 2")
            if hypothesis_row["status"] not in {"candidate", "planned"}:
                raise HTTPException(409, "Hypothesis is not executable")
        test_variant = _resolve_test_variant(conn, project_id, project.mode, body.coverage_refs, body.test_variant)
        work_key = None
        if project.mode == "real_website" and len(body.coverage_refs) == 1:
            coverage_row = conn.execute(
                "SELECT * FROM coverage_items WHERE project_id = ? AND id = ?",
                (project_id, body.coverage_refs[0]),
            ).fetchone()
            assert coverage_row is not None
            work_key = coverage_work_key(
                coverage_row,
                test_variant or body.action_kind or "general",
                body.action_kind,
            )
            existing_work = conn.execute(
                """SELECT * FROM intents
                   WHERE project_id = ? AND work_key = ? AND status = 'open'""",
                (project_id, work_key),
            ).fetchone()
            if existing_work is not None:
                return intent_to_model(conn, existing_work, project_id)
        validate_intent_scope(
            project.scope_policy,
            target=body.target,
            port=body.port,
            path=body.path,
            action_kind=body.action_kind,
        )

        now = utcnow()
        iid = next_intent_id(conn, project_id)
        claimed = body.worker is not None
        inserted = conn.execute(
            """
            INSERT OR IGNORE INTO intents (
                id, project_id, to_fact_id, description, creator, worker, last_heartbeat_at, created_at, concluded_at,
                target, port, path, surface_type, action_kind, test_variant, priority, suggested_tools, status, work_key, hypothesis_id
            ) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
            """,
            (
                iid,
                project_id,
                body.description,
                body.creator,
                body.worker,
                now if claimed else None,
                now,
                body.target,
                body.port,
                body.path,
                body.surface_type,
                body.action_kind,
                test_variant,
                body.priority,
                json.dumps(body.suggested_tools),
                work_key,
                body.hypothesis_id,
            ),
        )
        if inserted.rowcount == 0:
            if not work_key:
                raise HTTPException(409, "Intent identity already exists")
            existing_work = conn.execute(
                """SELECT * FROM intents
                   WHERE project_id = ? AND work_key = ? AND status = 'open'""",
                (project_id, work_key),
            ).fetchone()
            if existing_work is not None:
                return intent_to_model(conn, existing_work, project_id)
            raise HTTPException(409, "Intent work identity already exists")
        for fid in body.from_:
            conn.execute(
                "INSERT INTO intent_sources (intent_id, project_id, fact_id) VALUES (?, ?, ?)",
                (iid, project_id, fid),
            )
        for coverage_id in body.coverage_refs:
            bind_coverage_intent(conn, project_id, coverage_id, iid, created_at=now)
        if hypothesis_row is not None:
            conn.execute(
                """UPDATE hypotheses SET status = 'planned', intent_id = ?,
                   coverage_id = COALESCE(coverage_id, ?), updated_at = ?
                   WHERE project_id = ? AND id = ?""",
                (iid, body.coverage_refs[0] if body.coverage_refs else None, now, project_id, body.hypothesis_id),
            )

        clear_completion_blocked(conn, project_id)
        return Intent(
            id=iid,
            **{"from": body.from_},
            to=None,
            description=body.description,
            creator=body.creator,
            worker=body.worker,
            last_heartbeat_at=now if claimed else None,
            created_at=now,
            concluded_at=None,
            target=body.target,
            port=body.port,
            path=body.path,
            surface_type=body.surface_type,
            action_kind=body.action_kind,
            test_variant=test_variant,
            priority=body.priority,
            suggested_tools=body.suggested_tools,
            status="open",
            work_key=work_key,
            coverage_refs=body.coverage_refs,
            hypothesis_id=body.hypothesis_id,
        )


@router.post(
    "/projects/{project_id}/intents/{intent_id}/heartbeat",
    response_model=Intent,
)
def heartbeat(project_id: str, intent_id: str, body: HeartbeatRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        get_claimable_open_intent_or_404(conn, project_id, intent_id, body.worker)

        now = utcnow()
        conn.execute(
            "UPDATE intents SET worker = ?, last_heartbeat_at = ?, execution_status = CASE WHEN execution_status = 'pending' THEN 'running' ELSE execution_status END WHERE id = ? AND project_id = ?",
            (body.worker, now, intent_id, project_id),
        )
        conn.execute(
            """
            UPDATE coverage_items
            SET execution_status = 'testing', status = 'testing', updated_at = ?
            WHERE project_id = ?
              AND id IN (
                  SELECT coverage_id FROM coverage_intents
                  WHERE project_id = ? AND intent_id = ?
              )
              AND execution_status IN ('untested', 'queued', 'testing')
            """,
            (now, project_id, project_id, intent_id),
        )
        conn.execute(
            "UPDATE hypotheses SET status = 'testing', updated_at = ? "
            "WHERE project_id = ? AND intent_id = ? AND status IN ('candidate', 'planned', 'testing')",
            (now, project_id, intent_id),
        )

        updated = conn.execute(
            "SELECT * FROM intents WHERE id = ? AND project_id = ?",
            (intent_id, project_id),
        ).fetchone()
        return intent_to_model(conn, updated, project_id)


@router.post(
    "/projects/{project_id}/intents/{intent_id}/release",
    response_model=Intent,
)
def release(project_id: str, intent_id: str, body: HeartbeatRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        row = get_releasable_open_intent_or_404(conn, project_id, intent_id, body.worker)

        if row["worker"] == body.worker:
            conn.execute(
                "UPDATE intents SET worker = NULL WHERE id = ? AND project_id = ?",
                (intent_id, project_id),
            )
            conn.execute(
                """
                UPDATE coverage_items
                SET execution_status = 'queued', status = 'untested', updated_at = ?
                WHERE project_id = ?
                  AND id IN (
                      SELECT coverage_id FROM coverage_intents
                      WHERE project_id = ? AND intent_id = ?
                  )
                  AND execution_status = 'testing'
                """,
                (utcnow(), project_id, project_id, intent_id),
            )
            row = conn.execute(
                "SELECT * FROM intents WHERE id = ? AND project_id = ?",
                (intent_id, project_id),
            ).fetchone()

        return intent_to_model(conn, row, project_id)


@router.post(
    "/projects/{project_id}/intents/{intent_id}/execution-success",
    response_model=Intent,
)
def record_execution_success(
    project_id: str,
    intent_id: str,
    body: RecordIntentExecutionRequest,
):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        intent = get_claimable_open_intent_or_404(
            conn, project_id, intent_id, body.worker
        )
        task_log = conn.execute(
            """SELECT id FROM task_logs
            WHERE project_id = ? AND id = ? AND intent_id = ?""",
            (project_id, body.task_log_id, intent_id),
        ).fetchone()
        if task_log is None:
            raise HTTPException(404, "Execution task log not found for Intent")
        now = utcnow()
        conn.execute(
            """UPDATE intents SET execution_status = 'succeeded',
               execution_artifact_ref = ?, execution_completed_at = ?,
               conclusion_last_error = NULL
               WHERE project_id = ? AND id = ?""",
            (f"task_log:{body.task_log_id}", now, project_id, intent_id),
        )
        updated = conn.execute(
            "SELECT * FROM intents WHERE project_id = ? AND id = ?",
            (project_id, intent_id),
        ).fetchone()
        return intent_to_model(conn, updated or intent, project_id)


@router.post(
    "/projects/{project_id}/intents/{intent_id}/conclusion-failure",
    response_model=Intent,
)
def record_conclusion_failure(
    project_id: str,
    intent_id: str,
    body: RecordIntentConclusionFailureRequest,
):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        row = get_claimable_open_intent_or_404(conn, project_id, intent_id, body.worker)
        attempts = int(row["conclusion_attempt_count"] or 0) + 1
        now = utcnow()
        if attempts >= 3:
            conn.execute(
                """UPDATE intents SET conclusion_attempt_count = ?, conclusion_last_error = ?,
                   worker = NULL, last_heartbeat_at = NULL, next_retry_at = NULL,
                   failed_at = ?, dead_lettered_at = ?, status = 'dead_lettered'
                   WHERE project_id = ? AND id = ? AND execution_status = 'succeeded'""",
                (attempts, body.error[:2000], now, now, project_id, intent_id),
            )
            conn.execute(
                """UPDATE hypotheses SET status = 'inconclusive', last_error = ?, updated_at = ?
                   WHERE project_id = ? AND intent_id = ?
                     AND status NOT IN ('supported', 'refuted', 'waived')""",
                (body.error[:2000], now, project_id, intent_id),
            )
            conn.execute(
                """UPDATE coverage_items SET execution_status = 'blocked', status = 'failed',
                   outcome = NULL, updated_at = ? WHERE project_id = ? AND id IN (
                       SELECT coverage_id FROM coverage_intents
                       WHERE project_id = ? AND intent_id = ?
                   ) AND execution_status <> 'completed'""",
                (now, project_id, project_id, intent_id),
            )
            conclude_intent_with_failure_fact(
                conn,
                project_id,
                intent_id,
                worker=body.worker,
                error=body.error,
                attempt_count=attempts,
                failure_stage="conclusion_failed",
                execution_status="succeeded",
                now=now,
            )
        else:
            conn.execute(
                """UPDATE intents SET conclusion_attempt_count = ?, conclusion_last_error = ?,
                   worker = NULL, last_heartbeat_at = NULL, next_retry_at = ?
                   WHERE project_id = ? AND id = ? AND execution_status = 'succeeded'""",
                (attempts, body.error[:2000], now, project_id, intent_id),
            )
        updated = conn.execute(
            "SELECT * FROM intents WHERE project_id = ? AND id = ?",
            (project_id, intent_id),
        ).fetchone()
        return intent_to_model(conn, updated, project_id)


@router.post(
    "/projects/{project_id}/intents/{intent_id}/failure",
    response_model=Intent,
)
def record_failure(project_id: str, intent_id: str, body: TaskFailureRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        row = mark_intent_failure(
            conn,
            project_id,
            intent_id,
            worker=body.worker,
            error=body.error,
            max_attempts=body.max_attempts,
            backoff_seconds=body.backoff_seconds,
        )
        return intent_to_model(conn, row, project_id)


@router.post(
    "/projects/{project_id}/intents/{intent_id}/conclude",
    response_model=ConcludeResponse,
)
def conclude(project_id: str, intent_id: str, body: ConcludeRequest):
    with get_conn() as conn:
        project = project_meta_from_row(check_project_active(conn, project_id))
        if project.mode == "real_website" and body.coverage_refs:
            bound_rows = conn.execute(
                """
                SELECT coverage_id FROM coverage_intents
                WHERE project_id = ? AND intent_id = ?
                UNION
                SELECT id FROM coverage_items
                WHERE project_id = ? AND intent_id = ?
                """,
                (project_id, intent_id, project_id, intent_id),
            ).fetchall()
            bound_refs = {row["coverage_id"] for row in bound_rows}
            requested_refs = set(body.coverage_refs)
            if len(requested_refs) > 1 or requested_refs != bound_refs:
                raise HTTPException(
                    409, "Fact coverage_refs must match the real_website Intent Coverage binding"
                )
        intent_row = get_claimable_open_intent_or_404(conn, project_id, intent_id, body.worker)
        if body.verification_of:
            validate_facts_exist(conn, project_id, [body.verification_of])
        intent_variant = str(intent_row["test_variant"] or "").strip()
        if intent_variant and body.vuln_type and intent_variant.casefold() != body.vuln_type.casefold():
            raise HTTPException(409, "Fact vuln_type must match the Intent test_variant")
        vuln_type = intent_variant or body.vuln_type
        recon_category, recon_executed, recon_found_results = derive_recon_fact_fields(
            intent_row,
            supplied_category=body.recon_category,
            supplied_executed=body.recon_executed,
            supplied_found_results=body.recon_found_results,
            observed_surface_count=len(body.observed_surfaces),
        )

        validate_verification_reference(
            conn,
            project_id,
            body.verification_of,
            candidate_variant=vuln_type,
            candidate_status=body.status,
            candidate_intent_id=intent_id,
        )
        parent_fact_ids = list(body.parent_fact_ids)
        if body.parent_fact and body.parent_fact not in parent_fact_ids:
            parent_fact_ids.append(body.parent_fact)
        if parent_fact_ids:
            validate_facts_exist(conn, project_id, parent_fact_ids)
        evidence_refs = list(body.evidence_refs)
        if body.recon_evidence_ref and body.recon_evidence_ref not in evidence_refs:
            evidence_refs.append(body.recon_evidence_ref)
        now = utcnow()
        fid = next_fact_id(conn, project_id)

        conn.execute(
            """
            INSERT INTO facts (
                id, project_id, description, scope, vuln_type, severity, parent_fact, verification_of, goal_type, status,
                recon_category, recon_executed, recon_found_results, recon_tool, recon_target, recon_evidence_ref
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                fid,
                project_id,
                body.description,
                body.scope,
                vuln_type,
                body.severity,
                body.parent_fact,
                body.verification_of,
                body.goal_type,
                body.status,
                recon_category,
                _bool_to_db(recon_executed),
                _bool_to_db(recon_found_results),
                body.recon_tool,
                body.recon_target,
                body.recon_evidence_ref,
            ),
        )
        conn.execute(
            """UPDATE facts SET schema_version = ?, kind = ?, summary = ?,
               subject = ?, data = ?, parent_fact_ids = ?, evidence_refs = ?,
               confidence = ?, created_by = ?, created_at = ?
               WHERE project_id = ? AND id = ?""",
            (
                body.schema_version,
                body.kind,
                body.summary or body.description[:320],
                json.dumps(body.subject, ensure_ascii=False),
                json.dumps(body.data, ensure_ascii=False),
                json.dumps(parent_fact_ids, ensure_ascii=False),
                json.dumps(evidence_refs, ensure_ascii=False),
                body.confidence,
                body.created_by or body.worker,
                now, project_id, fid,
            ),
        )
        for surface in body.observed_surfaces:
            validate_intent_scope(
                project.scope_policy,
                target=surface.target,
                port=surface.port,
                path=surface.path_template,
                action_kind="surface_observation",
            )
            upsert_surface_inventory_record(conn, project_id, surface, source_fact_id=fid)
        conn.execute(
            """
            UPDATE intents
            SET to_fact_id = ?,
                worker = ?,
                last_heartbeat_at = ?,
                concluded_at = ?,
                next_retry_at = NULL,
                dead_lettered_at = NULL,
                status = 'concluded',
                execution_status = 'succeeded',
                commit_status = 'committed'
            WHERE id = ? AND project_id = ?
            """,
            (fid, body.worker, now, now, intent_id, project_id),
        )
        reconcile_fact_coverage(
            conn,
            project_id,
            fid,
            intent_id=intent_id,
            explicit_coverage_refs=body.coverage_refs,
        )
        hypothesis_id = intent_row["hypothesis_id"] if "hypothesis_id" in intent_row.keys() else None
        if hypothesis_id:
            result_status = str(body.status or "").casefold()
            if result_status in {"confirmed", "verified", "vulnerable"}:
                hypothesis_status = "supported"
            elif result_status == "blocked_by_precondition":
                hypothesis_status = "blocked_by_precondition"
            elif result_status in {"not_vulnerable", "refuted", "false_positive"}:
                hypothesis_status = "refuted"
            else:
                hypothesis_status = "inconclusive"
            conn.execute(
                """UPDATE hypotheses SET status = ?, last_error = NULL,
                   coverage_id = COALESCE(coverage_id, ?), intent_id = ?, updated_at = ?
                   WHERE project_id = ? AND id = ?""",
                (
                    hypothesis_status, body.coverage_refs[0] if body.coverage_refs else None,
                    intent_id, now, project_id, hypothesis_id,
                ),
            )
        clear_completion_blocked(conn, project_id)
        reconcile_project_attack_paths(conn, project_id)

        updated = conn.execute(
            "SELECT * FROM intents WHERE id = ? AND project_id = ?",
            (intent_id, project_id),
        ).fetchone()

        created_fact = conn.execute(
            "SELECT * FROM facts WHERE id = ? AND project_id = ?",
            (fid, project_id),
        ).fetchone()
        assert created_fact is not None
        return ConcludeResponse(
            fact=fact_to_model(conn, created_fact, project_id),
            intent=intent_to_model(conn, updated, project_id),
        )


def _bool_to_db(value: bool | None) -> int | None:
    if value is None:
        return None
    return int(value)

def _resolve_test_variant(
    conn,
    project_id: str,
    mode: str,
    coverage_refs: list[str],
    requested: str | None,
) -> str | None:
    if mode != "real_website":
        return requested
    if len(coverage_refs) > 1:
        raise HTTPException(422, "A real_website Intent may bind at most one Coverage item")
    if not coverage_refs:
        return requested
    row = conn.execute(
        "SELECT test_variants FROM coverage_items WHERE project_id = ? AND id = ?",
        (project_id, coverage_refs[0]),
    ).fetchone()
    try:
        raw_variants = json.loads(row["test_variants"] or "[]")
    except (TypeError, json.JSONDecodeError):
        raw_variants = []
    if not isinstance(raw_variants, list):
        raw_variants = []
    variants = [str(value).strip() for value in raw_variants if str(value).strip()]
    if requested:
        if variants:
            matched = next((value for value in variants if requested.casefold() == value.casefold()), None)
            if matched is None:
                raise HTTPException(422, "Intent test_variant is not declared by the bound Coverage item")
            return matched
        return requested
    if len(variants) == 1:
        return variants[0]
    if len(variants) > 1:
        raise HTTPException(422, "test_variant is required when Coverage declares multiple variants")
    return None

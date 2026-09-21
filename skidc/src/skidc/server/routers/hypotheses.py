from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Query

from skidc.planning import behavior_identity

from skidc.server.db import get_conn
from skidc.server.models import (
    CreateHypothesisRequest,
    Hypothesis,
    MaterializeHypothesisWorkRequest,
    MaterializeHypothesisWorkResponse,
    UpdateHypothesisRequest,
)
from skidc.server.services import (
    bind_coverage_intent,
    check_project_active,
    clear_completion_blocked,
    coverage_item_to_model,
    coverage_work_key,
    get_project_or_404,
    hypothesis_to_model,
    intent_to_model,
    next_coverage_id,
    next_hypothesis_id,
    next_intent_id,
    project_meta_from_row,
    surface_inventory_to_model,
    utcnow,
    validate_facts_exist,
    validate_goal_not_in_sources,
    validate_intent_creator_worker,
    validate_intent_scope,
)

router = APIRouter(tags=["hypotheses"])


@router.get("/projects/{project_id}/hypotheses", response_model=list[Hypothesis])
def list_hypotheses(
    project_id: str,
    status: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        params: list[object] = [project_id]
        where = "project_id = ?"
        if status:
            where += " AND status = ?"
            params.append(status)
        params.extend((limit, offset))
        rows = conn.execute(
            f"SELECT * FROM hypotheses WHERE {where} "
            "ORDER BY score DESC, created_at, id LIMIT ? OFFSET ?",
            params,
        ).fetchall()
        return [hypothesis_to_model(row) for row in rows]


@router.post("/projects/{project_id}/hypotheses", response_model=Hypothesis, status_code=201)
def create_hypothesis(project_id: str, body: CreateHypothesisRequest):
    with get_conn() as conn:
        project = check_project_active(conn, project_id)
        if int(project["planning_version"] or 1) < 2:
            raise HTTPException(409, "Hypotheses require planning_version 2")
        validate_facts_exist(conn, project_id, body.trigger_fact_ids)
        if body.coverage_id:
            _validate_ref(conn, project_id, "coverage_items", body.coverage_id, "Coverage")
        if body.intent_id:
            _validate_ref(conn, project_id, "intents", body.intent_id, "Intent")

        existing = conn.execute(
            """SELECT * FROM hypotheses
            WHERE project_id = ? AND behavior_key = ? AND test_family = ?
              AND test_variant = ? AND basis_fingerprint = ?""",
            (
                project_id, body.behavior_key, body.test_family,
                body.test_variant, body.basis_fingerprint,
            ),
        ).fetchone()
        if existing is not None:
            return hypothesis_to_model(existing)

        now = utcnow()
        hypothesis_id = next_hypothesis_id(conn, project_id)
        conn.execute(
            """INSERT INTO hypotheses (
                id, project_id, behavior_key, coverage_id, test_family, test_variant,
                rationale, trigger_fact_ids, confidence, impact, goal_value, novelty,
                estimated_cost, score, required, status, intent_id, basis_fingerprint,
                last_error, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                hypothesis_id, project_id, body.behavior_key, body.coverage_id,
                body.test_family, body.test_variant, body.rationale,
                json.dumps(body.trigger_fact_ids), body.confidence, body.impact,
                body.goal_value, body.novelty, body.estimated_cost, body.score,
                int(body.required), body.status, body.intent_id, body.basis_fingerprint,
                body.last_error, now, now,
            ),
        )
        row = conn.execute(
            "SELECT * FROM hypotheses WHERE project_id = ? AND id = ?",
            (project_id, hypothesis_id),
        ).fetchone()
        return hypothesis_to_model(row)


def _coverage_variant_list(row) -> list[str]:
    try:
        parsed = json.loads(row["test_variants"] or "[]")
    except (json.JSONDecodeError, TypeError):
        return []
    return [str(item).strip() for item in parsed if str(item).strip()]


@router.post(
    "/projects/{project_id}/hypothesis-work",
    response_model=MaterializeHypothesisWorkResponse,
    status_code=201,
)
def materialize_hypothesis_work(
    project_id: str,
    body: MaterializeHypothesisWorkRequest,
):
    """Atomically materialize Hypothesis -> Coverage -> Intent and assess its Behavior."""
    with get_conn() as conn:
        project_row = check_project_active(conn, project_id)
        project = project_meta_from_row(project_row)
        if project.planning_version < 2:
            raise HTTPException(409, "Hypothesis work requires planning_version 2")
        hypothesis = body.hypothesis
        coverage = body.coverage
        intent = body.intent
        validate_facts_exist(conn, project_id, hypothesis.trigger_fact_ids)
        validate_facts_exist(conn, project_id, intent.from_)
        validate_goal_not_in_sources(intent.from_)
        validate_intent_creator_worker(intent.creator, intent.worker)
        validate_intent_scope(
            project.scope_policy,
            target=intent.target,
            port=intent.port,
            path=intent.path,
            action_kind=intent.action_kind,
        )
        if set(intent.from_) != set(hypothesis.trigger_fact_ids):
            raise HTTPException(409, "Intent and Hypothesis must use the same Fact basis")
        if intent.coverage_refs or intent.hypothesis_id:
            raise HTTPException(409, "Atomic materialization assigns Coverage and Hypothesis links")
        variants = [item.casefold() for item in coverage.test_variants]
        if (
            variants != [hypothesis.test_variant.casefold()]
            or str(intent.test_variant or "").casefold() != hypothesis.test_variant.casefold()
            or str(coverage.test_family or "").casefold() != hypothesis.test_family.casefold()
        ):
            raise HTTPException(409, "Hypothesis, Coverage, and Intent must declare one identical Variant")
        if (
            coverage.status != "untested"
            or coverage.execution_status not in (None, "untested")
            or coverage.outcome is not None
            or not coverage.required
            or coverage.disposition != "required"
        ):
            raise HTTPException(409, "Atomic hypothesis Coverage must start as required and untested")
        if coverage.source_fact_id:
            validate_facts_exist(conn, project_id, [coverage.source_fact_id])

        surface_rows = []
        for surface_id in body.surface_ids:
            surface_row = conn.execute(
                "SELECT * FROM surface_inventory WHERE project_id = ? AND id = ?",
                (project_id, surface_id),
            ).fetchone()
            if surface_row is None:
                raise HTTPException(404, f"Surface {surface_id} not found")
            if behavior_identity(surface_inventory_to_model(surface_row))[0] != hypothesis.behavior_key:
                raise HTTPException(409, f"Surface {surface_id} does not belong to the Hypothesis Behavior")
            surface_rows.append(surface_row)

        hypothesis_row = conn.execute(
            """SELECT * FROM hypotheses
               WHERE project_id = ? AND behavior_key = ? AND test_family = ?
                 AND test_variant = ? AND basis_fingerprint = ?""",
            (
                project_id,
                hypothesis.behavior_key,
                hypothesis.test_family,
                hypothesis.test_variant,
                hypothesis.basis_fingerprint,
            ),
        ).fetchone()
        created = hypothesis_row is None
        now = utcnow()
        if hypothesis_row is None:
            hypothesis_id = next_hypothesis_id(conn, project_id)
            conn.execute(
                """INSERT INTO hypotheses (
                    id, project_id, behavior_key, coverage_id, test_family, test_variant,
                    rationale, trigger_fact_ids, confidence, impact, goal_value, novelty,
                    estimated_cost, score, required, status, intent_id, basis_fingerprint,
                    last_error, created_at, updated_at
                ) VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'candidate',
                          NULL, ?, NULL, ?, ?)""",
                (
                    hypothesis_id,
                    project_id,
                    hypothesis.behavior_key,
                    hypothesis.test_family,
                    hypothesis.test_variant,
                    hypothesis.rationale,
                    json.dumps(hypothesis.trigger_fact_ids),
                    hypothesis.confidence,
                    hypothesis.impact,
                    hypothesis.goal_value,
                    hypothesis.novelty,
                    hypothesis.estimated_cost,
                    hypothesis.score,
                    int(hypothesis.required),
                    hypothesis.basis_fingerprint,
                    now,
                    now,
                ),
            )
        else:
            hypothesis_id = hypothesis_row["id"]
            if hypothesis_row["intent_id"] and hypothesis_row["coverage_id"]:
                existing_intent = conn.execute(
                    "SELECT * FROM intents WHERE project_id = ? AND id = ?",
                    (project_id, hypothesis_row["intent_id"]),
                ).fetchone()
                existing_coverage = conn.execute(
                    "SELECT * FROM coverage_items WHERE project_id = ? AND id = ?",
                    (project_id, hypothesis_row["coverage_id"]),
                ).fetchone()
                if existing_intent is not None and existing_coverage is not None:
                    for surface_row in surface_rows:
                        conn.execute(
                            """UPDATE surface_inventory
                               SET planning_status = 'assessed', updated_at = ?
                               WHERE project_id = ? AND id = ?""",
                            (now, project_id, surface_row["id"]),
                        )
                    return MaterializeHypothesisWorkResponse(
                        hypothesis=hypothesis_to_model(hypothesis_row),
                        coverage=coverage_item_to_model(conn, existing_coverage, project_id),
                        intent=intent_to_model(conn, existing_intent, project_id),
                        created=False,
                    )

        created = True
        coverage_row = None
        candidates = conn.execute(
            """SELECT * FROM coverage_items
               WHERE project_id = ?
                 AND COALESCE(surface_fingerprint, '') = COALESCE(?, '')
                 AND COALESCE(test_family, '') = COALESCE(?, '')
                 AND COALESCE(target, '') = COALESCE(?, '')
                 AND port IS ?
                 AND UPPER(COALESCE(method, '')) = UPPER(COALESCE(?, ''))
                 AND COALESCE(path, '') = COALESCE(?, '')
                 AND COALESCE(auth_context, 'anonymous') = COALESCE(?, 'anonymous')
               ORDER BY created_at, id""",
            (
                project_id,
                coverage.surface_fingerprint,
                coverage.test_family,
                coverage.target,
                coverage.port,
                coverage.method,
                coverage.path,
                coverage.auth_context,
            ),
        ).fetchall()
        for candidate in candidates:
            if hypothesis.test_variant.casefold() in {
                value.casefold() for value in _coverage_variant_list(candidate)
            }:
                coverage_row = candidate
                break
        if coverage_row is None:
            coverage_id = next_coverage_id(conn, project_id)
            conn.execute(
                """INSERT INTO coverage_items (
                    id, project_id, item_type, target, port, method, path, param,
                    description, status, priority, evidence_ref, source_fact_id, intent_id,
                    surface_group, surface_fingerprint, test_family, test_variants,
                    auth_context, roles, applicability_reason, required, disposition,
                    disposition_reason, standard_refs, execution_status, outcome,
                    applicability_status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'untested', ?, ?, ?, NULL, ?, ?, ?,
                          ?, ?, ?, ?, 1, 'required', NULL, ?, 'untested', NULL, ?, ?, ?)""",
                (
                    coverage_id,
                    project_id,
                    coverage.item_type,
                    coverage.target,
                    coverage.port,
                    coverage.method,
                    coverage.path,
                    coverage.param,
                    coverage.description,
                    coverage.priority,
                    coverage.evidence_ref,
                    coverage.source_fact_id,
                    coverage.surface_group,
                    coverage.surface_fingerprint,
                    coverage.test_family,
                    json.dumps(coverage.test_variants),
                    coverage.auth_context,
                    json.dumps(coverage.roles),
                    coverage.applicability_reason,
                    json.dumps(coverage.standard_refs),
                    coverage.applicability_status,
                    now,
                    now,
                ),
            )
            coverage_row = conn.execute(
                "SELECT * FROM coverage_items WHERE project_id = ? AND id = ?",
                (project_id, coverage_id),
            ).fetchone()
        assert coverage_row is not None
        coverage_id = coverage_row["id"]
        work_key = coverage_work_key(
            coverage_row,
            hypothesis.test_variant,
            intent.action_kind,
        )
        intent_row = conn.execute(
            """SELECT * FROM intents
               WHERE project_id = ? AND work_key = ?
               ORDER BY created_at, id LIMIT 1""",
            (project_id, work_key),
        ).fetchone()
        if intent_row is not None and intent_row["hypothesis_id"] not in (None, hypothesis_id):
            raise HTTPException(409, "Intent work identity belongs to a different Hypothesis")
        if intent_row is None:
            intent_id = next_intent_id(conn, project_id)
            claimed = intent.worker is not None
            conn.execute(
                """INSERT INTO intents (
                    id, project_id, to_fact_id, description, creator, worker,
                    last_heartbeat_at, created_at, concluded_at, target, port, path,
                    surface_type, action_kind, test_variant, priority, suggested_tools,
                    status, work_key, hypothesis_id
                ) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?,
                          'open', ?, ?)""",
                (
                    intent_id,
                    project_id,
                    intent.description,
                    intent.creator,
                    intent.worker,
                    now if claimed else None,
                    now,
                    intent.target,
                    intent.port,
                    intent.path,
                    intent.surface_type,
                    intent.action_kind,
                    hypothesis.test_variant,
                    intent.priority,
                    json.dumps(intent.suggested_tools),
                    work_key,
                    hypothesis_id,
                ),
            )
            for fact_id in intent.from_:
                conn.execute(
                    """INSERT INTO intent_sources (intent_id, project_id, fact_id)
                       VALUES (?, ?, ?)""",
                    (intent_id, project_id, fact_id),
                )
            intent_row = conn.execute(
                "SELECT * FROM intents WHERE project_id = ? AND id = ?",
                (project_id, intent_id),
            ).fetchone()
        assert intent_row is not None
        intent_id = intent_row["id"]
        bind_coverage_intent(conn, project_id, coverage_id, intent_id, created_at=now)
        conn.execute(
            """UPDATE intents SET hypothesis_id = COALESCE(hypothesis_id, ?)
               WHERE project_id = ? AND id = ?""",
            (hypothesis_id, project_id, intent_id),
        )
        conn.execute(
            """UPDATE hypotheses
               SET status = 'planned', coverage_id = ?, intent_id = ?,
                   last_error = NULL, updated_at = ?
               WHERE project_id = ? AND id = ?""",
            (coverage_id, intent_id, now, project_id, hypothesis_id),
        )
        for surface_row in surface_rows:
            conn.execute(
                """UPDATE surface_inventory
                   SET planning_status = 'assessed', updated_at = ?
                   WHERE project_id = ? AND id = ?""",
                (now, project_id, surface_row["id"]),
            )
        clear_completion_blocked(conn, project_id)
        hypothesis_row = conn.execute(
            "SELECT * FROM hypotheses WHERE project_id = ? AND id = ?",
            (project_id, hypothesis_id),
        ).fetchone()
        coverage_row = conn.execute(
            "SELECT * FROM coverage_items WHERE project_id = ? AND id = ?",
            (project_id, coverage_id),
        ).fetchone()
        intent_row = conn.execute(
            "SELECT * FROM intents WHERE project_id = ? AND id = ?",
            (project_id, intent_id),
        ).fetchone()
        assert hypothesis_row is not None and coverage_row is not None and intent_row is not None
        return MaterializeHypothesisWorkResponse(
            hypothesis=hypothesis_to_model(hypothesis_row),
            coverage=coverage_item_to_model(conn, coverage_row, project_id),
            intent=intent_to_model(conn, intent_row, project_id),
            created=created,
        )

@router.put(
    "/projects/{project_id}/hypotheses/{hypothesis_id}",
    response_model=Hypothesis,
)
def update_hypothesis(
    project_id: str,
    hypothesis_id: str,
    body: UpdateHypothesisRequest,
):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        row = conn.execute(
            "SELECT * FROM hypotheses WHERE project_id = ? AND id = ?",
            (project_id, hypothesis_id),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Hypothesis not found")
        coverage_id = body.coverage_id if body.coverage_id is not None else row["coverage_id"]
        intent_id = body.intent_id if body.intent_id is not None else row["intent_id"]
        if coverage_id:
            _validate_ref(conn, project_id, "coverage_items", coverage_id, "Coverage")
        if intent_id:
            _validate_ref(conn, project_id, "intents", intent_id, "Intent")
        conn.execute(
            """UPDATE hypotheses SET status = ?, coverage_id = ?, intent_id = ?,
               last_error = ?, updated_at = ? WHERE project_id = ? AND id = ?""",
            (
                body.status or row["status"], coverage_id, intent_id,
                body.last_error if body.last_error is not None else row["last_error"],
                utcnow(), project_id, hypothesis_id,
            ),
        )
        updated = conn.execute(
            "SELECT * FROM hypotheses WHERE project_id = ? AND id = ?",
            (project_id, hypothesis_id),
        ).fetchone()
        return hypothesis_to_model(updated)


def _validate_ref(conn, project_id: str, table: str, ref: str, label: str) -> None:
    row = conn.execute(
        f"SELECT 1 FROM {table} WHERE project_id = ? AND id = ?",
        (project_id, ref),
    ).fetchone()
    if row is None:
        raise HTTPException(404, f"{label} {ref} not found")

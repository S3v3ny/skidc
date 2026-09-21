from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException

from skidc.server.db import get_conn
from skidc.server.models import (
    BindCoverageIntentRequest,
    CoverageItem,
    CreateCoverageItemRequest,
    ExcludeCoverageRequest,
    SurfaceInventoryItem,
    UpsertSurfaceInventoryRequest,
    UpdateCoverageItemRequest,
)
from skidc.server.services import (
    bind_coverage_intent,
    check_project_active,
    clear_completion_blocked,
    clear_project_reason,
    clear_reason_failure,
    coverage_item_to_model,
    coverage_state_fields,
    get_project_or_404,
    next_coverage_id,
    next_hint_id,
    reconcile_fact_coverage,
    project_meta_from_row,
    reconcile_project_coverage,
    utcnow,
    validate_facts_exist,
    surface_inventory_to_model,
    upsert_surface_inventory_record,
    validate_intent_scope,
)

router = APIRouter(tags=["coverage"])


def _row_to_model(conn, row, project_id: str) -> CoverageItem:
    return coverage_item_to_model(conn, row, project_id)


@router.get("/projects/{project_id}/coverage", response_model=list[CoverageItem])
def list_coverage_items(project_id: str):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        rows = conn.execute(
            "SELECT * FROM coverage_items WHERE project_id = ? ORDER BY created_at",
            (project_id,),
        ).fetchall()
        return [_row_to_model(conn, r, project_id) for r in rows]


@router.post("/projects/{project_id}/coverage", response_model=CoverageItem, status_code=201)
def create_coverage_item(project_id: str, body: CreateCoverageItemRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        disposition = body.disposition
        if not body.required and "disposition" not in body.model_fields_set:
            disposition = "excluded"
        required = body.required and disposition != "excluded"
        if disposition == "excluded" and body.required and not body.disposition_reason:
            raise HTTPException(400, "Excluded required Coverage needs a waiver reason")
        if body.source_fact_id:
            validate_facts_exist(conn, project_id, [body.source_fact_id])
        if body.intent_id:
            _validate_intent_exists(conn, project_id, body.intent_id)

        now = utcnow()
        existing = _find_profile_coverage(conn, project_id, body)
        if existing is not None:
            cid = existing["id"]
            _merge_profile_coverage(conn, project_id, existing, body, now=now)
            if body.intent_id:
                bind_coverage_intent(conn, project_id, cid, body.intent_id, created_at=now)
            if body.source_fact_id and body.status != "untested":
                reconcile_fact_coverage(
                    conn,
                    project_id,
                    body.source_fact_id,
                    intent_id=body.intent_id,
                    explicit_coverage_refs=[cid],
                )
            reconcile_project_coverage(conn, project_id)
            merged = conn.execute(
                "SELECT * FROM coverage_items WHERE id = ? AND project_id = ?",
                (cid, project_id),
            ).fetchone()
            assert merged is not None
            return _row_to_model(conn, merged, project_id)

        cid = next_coverage_id(conn, project_id)
        execution_status, outcome, status = coverage_state_fields(
            body.status,
            body.execution_status,
            body.outcome,
        )
        conn.execute(
            """
            INSERT INTO coverage_items (
                id, project_id, item_type, target, port, method, path, param,
                description, status, priority, evidence_ref, source_fact_id, intent_id,
                surface_group, surface_fingerprint, test_family, test_variants, auth_context, roles,
                applicability_reason, required, disposition, disposition_reason, standard_refs, execution_status, outcome, applicability_status,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cid,
                project_id,
                body.item_type,
                body.target,
                body.port,
                body.method,
                body.path,
                body.param,
                body.description,
                status,
                body.priority,
                body.evidence_ref,
                body.source_fact_id,
                body.intent_id,
                body.surface_group,
                body.surface_fingerprint,
                body.test_family,
                json.dumps(body.test_variants),
                body.auth_context,
                json.dumps(body.roles),
                body.applicability_reason,
                int(required),
                disposition,
                body.disposition_reason,
                json.dumps(body.standard_refs),
                execution_status,
                outcome,
                body.applicability_status,
                now,
                now,
            ),
        )
        if body.intent_id:
            bind_coverage_intent(conn, project_id, cid, body.intent_id, created_at=now)
        if body.source_fact_id and body.status != "untested":
            reconcile_fact_coverage(
                conn,
                project_id,
                body.source_fact_id,
                intent_id=body.intent_id,
                explicit_coverage_refs=[cid],
            )
        reconcile_project_coverage(conn, project_id)
        row = conn.execute(
            "SELECT * FROM coverage_items WHERE id = ? AND project_id = ?",
            (cid, project_id),
        ).fetchone()
        assert row is not None
        return _row_to_model(conn, row, project_id)


@router.put("/projects/{project_id}/coverage/{coverage_id}", response_model=CoverageItem)
def update_coverage_item(project_id: str, coverage_id: str, body: UpdateCoverageItemRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        row = conn.execute(
            "SELECT * FROM coverage_items WHERE id = ? AND project_id = ?",
            (coverage_id, project_id),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Coverage item not found")
        if body.intent_id:
            _validate_intent_exists(conn, project_id, body.intent_id)

        requested_status = body.status if body.status is not None else row["status"]
        requested_execution = body.execution_status
        requested_outcome = body.outcome if body.outcome is not None else row["outcome"]
        if body.status is not None and body.execution_status is None and body.outcome is None:
            requested_outcome = None
        elif requested_execution is None:
            requested_execution = row["execution_status"]
        execution_status, outcome, status = coverage_state_fields(
            requested_status,
            requested_execution,
            requested_outcome,
        )
        evidence_ref = body.evidence_ref if body.evidence_ref is not None else row["evidence_ref"]
        intent_id = body.intent_id if body.intent_id is not None else row["intent_id"]
        disposition = body.disposition if body.disposition is not None else row["disposition"]
        disposition_reason = (
            None if disposition == "required"
            else body.disposition_reason if body.disposition_reason is not None
            else row["disposition_reason"]
        )
        if body.disposition == "excluded":
            if not disposition_reason:
                raise HTTPException(400, "Excluded Coverage needs a waiver reason")
            status = "not_vulnerable"
            execution_status = "completed"
            outcome = "not_applicable"
        now = utcnow()
        conn.execute(
            """
            UPDATE coverage_items
            SET status = ?, execution_status = ?, outcome = ?, evidence_ref = ?, intent_id = ?,
                required = ?, disposition = ?, disposition_reason = ?, updated_at = ?
            WHERE id = ? AND project_id = ?
            """,
            (status, execution_status, outcome, evidence_ref, intent_id,
             int(disposition != "excluded"), disposition, disposition_reason, now, coverage_id, project_id),
        )
        if body.intent_id:
            bind_coverage_intent(conn, project_id, coverage_id, body.intent_id, created_at=now)
        updated = conn.execute(
            "SELECT * FROM coverage_items WHERE id = ? AND project_id = ?",
            (coverage_id, project_id),
        ).fetchone()
        assert updated is not None
        return _row_to_model(conn, updated, project_id)


@router.post(
    "/projects/{project_id}/coverage/{coverage_id}/intents",
    response_model=CoverageItem,
)
def bind_intent(project_id: str, coverage_id: str, body: BindCoverageIntentRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        row = conn.execute(
            "SELECT * FROM coverage_items WHERE id = ? AND project_id = ?",
            (coverage_id, project_id),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Coverage item not found")
        _validate_intent_exists(conn, project_id, body.intent_id)
        bind_coverage_intent(conn, project_id, coverage_id, body.intent_id)
        updated = conn.execute(
            "SELECT * FROM coverage_items WHERE id = ? AND project_id = ?",
            (coverage_id, project_id),
        ).fetchone()
        assert updated is not None
        return _row_to_model(conn, updated, project_id)


@router.post(
    "/projects/{project_id}/coverage/{coverage_id}/exclude",
    response_model=CoverageItem,
)
def exclude_coverage_item(project_id: str, coverage_id: str, body: ExcludeCoverageRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        row = conn.execute(
            "SELECT * FROM coverage_items WHERE id = ? AND project_id = ?",
            (coverage_id, project_id),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Coverage item not found")

        now = utcnow()
        conn.execute(
            """
            UPDATE coverage_items
            SET required = 0, disposition = 'excluded', disposition_reason = ?,
                applicability_reason = ?, execution_status = 'completed',
                outcome = 'not_applicable', status = 'not_vulnerable',
                updated_at = ?
            WHERE id = ? AND project_id = ?
            """,
            (body.reason, f"Excluded from required scope: {body.reason}",
             now, coverage_id, project_id),
        )
        clear_project_reason(conn, project_id)
        clear_reason_failure(conn, project_id)
        clear_completion_blocked(conn, project_id)
        hint_id = next_hint_id(conn, project_id)
        conn.execute(
            "INSERT INTO hints (id, project_id, content, creator, created_at) VALUES (?, ?, ?, ?, ?)",
            (
                hint_id,
                project_id,
                f"Coverage {coverage_id} is outside the required test scope: {body.reason}",
                body.creator,
                now,
            ),
        )
        updated = conn.execute(
            "SELECT * FROM coverage_items WHERE id = ? AND project_id = ?",
            (coverage_id, project_id),
        ).fetchone()
        assert updated is not None
        return _row_to_model(conn, updated, project_id)


@router.post("/projects/{project_id}/coverage/reconcile", response_model=list[CoverageItem])
def reconcile_coverage(project_id: str):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        reconcile_project_coverage(conn, project_id)
        rows = conn.execute(
            "SELECT * FROM coverage_items WHERE project_id = ? ORDER BY created_at",
            (project_id,),
        ).fetchall()
        return [_row_to_model(conn, row, project_id) for row in rows]


@router.get("/projects/{project_id}/surfaces", response_model=list[SurfaceInventoryItem])
def list_surface_inventory(project_id: str):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        rows = conn.execute(
            "SELECT * FROM surface_inventory WHERE project_id = ? ORDER BY created_at, id",
            (project_id,),
        ).fetchall()
        return [surface_inventory_to_model(row) for row in rows]


@router.post("/projects/{project_id}/surfaces", response_model=SurfaceInventoryItem)
def upsert_surface_inventory(project_id: str, body: UpsertSurfaceInventoryRequest):
    with get_conn() as conn:
        project = project_meta_from_row(check_project_active(conn, project_id))
        validate_intent_scope(
            project.scope_policy,
            target=body.target,
            port=body.port,
            path=body.path_template,
            action_kind="surface_observation",
        )
        if body.source_fact_id:
            validate_facts_exist(conn, project_id, [body.source_fact_id])
        row = upsert_surface_inventory_record(conn, project_id, body)
        return surface_inventory_to_model(row)


def _find_profile_coverage(conn, project_id: str, body: CreateCoverageItemRequest):
    if not body.surface_group or not body.test_family:
        return None
    return conn.execute(
        """
        SELECT * FROM coverage_items
        WHERE project_id = ?
          AND COALESCE(surface_fingerprint, '') = COALESCE(?, '')
          AND LOWER(COALESCE(target, '')) = LOWER(COALESCE(?, ''))
          AND COALESCE(port, -1) = COALESCE(?, -1)
          AND UPPER(COALESCE(method, '')) = UPPER(COALESCE(?, ''))
          AND COALESCE(path, '') = COALESCE(?, '')
          AND LOWER(surface_group) = LOWER(?)
          AND LOWER(test_family) = LOWER(?)
          AND LOWER(COALESCE(auth_context, 'anonymous')) =
              LOWER(COALESCE(?, 'anonymous'))
        ORDER BY created_at, id
        LIMIT 1
        """,
        (
            project_id,
            body.surface_fingerprint,
            body.target,
            body.port,
            body.method,
            body.path,
            body.surface_group,
            body.test_family,
            body.auth_context,
        ),
    ).fetchone()


def _merge_profile_coverage(
    conn,
    project_id: str,
    existing,
    body: CreateCoverageItemRequest,
    *,
    now: str,
) -> None:
    variants = sorted(set(_json_values(existing["test_variants"])) | set(body.test_variants))
    roles = sorted(set(_json_values(existing["roles"])) | set(body.roles))
    standard_refs = sorted(set(_json_values(existing["standard_refs"])) | set(body.standard_refs))
    priorities = [value for value in (existing["priority"], body.priority) if value is not None]
    priority = max(priorities) if priorities else None
    existing_disposition = existing["disposition"] or (
        "required" if existing["required"] else "excluded"
    )
    disposition = existing_disposition if existing_disposition != "required" else body.disposition
    disposition_reason = existing["disposition_reason"] or body.disposition_reason
    required = disposition != "excluded" and (bool(existing["required"]) or body.required)
    conn.execute(
        """
        UPDATE coverage_items
        SET priority = ?,
            test_variants = ?,
            roles = ?,
            standard_refs = ?,
            required = ?,
            disposition = ?,
            disposition_reason = ?,
            surface_fingerprint = COALESCE(surface_fingerprint, ?),
            source_fact_id = COALESCE(source_fact_id, ?),
            intent_id = COALESCE(intent_id, ?),
            evidence_ref = COALESCE(evidence_ref, ?),
            applicability_reason = CASE
                WHEN applicability_reason LIKE 'Excluded from required scope:%'
                    THEN applicability_reason
                ELSE COALESCE(?, applicability_reason)
            END,
            applicability_status = ?,
            updated_at = ?
        WHERE id = ? AND project_id = ?
        """,
        (
            priority,
            json.dumps(variants),
            json.dumps(roles),
            json.dumps(standard_refs),
            int(required),
            disposition,
            disposition_reason,
            body.surface_fingerprint,
            body.source_fact_id,
            body.intent_id,
            body.evidence_ref,
            body.applicability_reason,
            body.applicability_status,
            now,
            existing["id"],
            project_id,
        ),
    )


def _json_values(value: str | None) -> list[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return []
    return [str(item) for item in parsed] if isinstance(parsed, list) else []


def _validate_intent_exists(conn, project_id: str, intent_id: str) -> None:
    row = conn.execute(
        "SELECT 1 FROM intents WHERE id = ? AND project_id = ?",
        (intent_id, project_id),
    ).fetchone()
    if row is None:
        raise HTTPException(404, f"Intent {intent_id} not found")

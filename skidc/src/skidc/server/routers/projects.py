from typing import Literal

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

import ipaddress
from urllib.parse import urlparse
import json
import sqlite3

from skidc.server.db import get_conn
from skidc.server.models import (
    CompleteRequest,
    ContinueBlockedProjectRequest,
    CoverageItem,
    CreateFactDirectRequest,
    CreateProjectRequest,
    Fact,
    Hint,
    HeartbeatRequest,
    Intent,
    NeedsAttentionRequest,
    PhaseAdvanceResponse,
    ProjectDetail,
    ProjectMeta,
    ProjectSummary,
    ReconProfile,
    ScopePolicy,
    ReopenRequest,
    ReopenResponse,
    ReasonClaimRequest,
    TaskFailureRequest,
    UpdateFactStatusRequest,
    UpdateProjectTitleRequest,
    UpdateProjectStatusRequest,
    UpdateProjectPhaseRequest,
    UpdateProjectModeRequest,
)
from skidc.server.services import (
    backfill_legacy_recon_facts,
    build_completed_attack_paths,
    build_intents,
    check_project_completed,
    check_project_active,
    clear_completion_blocked,
    clear_project_reason,
    clear_reason_failure,
    build_coverage_items,
    build_hypotheses,
    expire_reason_leases,
    expire_workers,
    fact_to_dispatch_model,
    fact_to_model,
    get_completion_intent_or_409,
    get_project_or_404,
    intent_to_model,
    mark_reason_failure,
    mark_reason_success,
    next_fact_id,
    next_hint_id,
    next_intent_id,
    next_project_id,
    project_meta_from_row,
    project_reason_from_row,
    reconcile_fact_coverage,
    reconcile_project_coverage,
    reason_state_fingerprint,
    recon_gate_result,
    validate_verification_reference,
    surface_inventory_to_model,
    utcnow,
    validate_project_completion_allowed,
    validate_completion_source_integrity,
    validate_facts_exist,
    validate_goal_not_in_sources,
)

router = APIRouter(tags=["projects"])

def _target_aware_recon_profile(origin: str, policy: ScopePolicy) -> ReconProfile:
    parsed = urlparse(origin if "://" in origin else f"//{origin}")
    host = parsed.hostname
    if not host:
        host = origin.split("/", 1)[0].split(":", 1)[0].strip()
    target_type = "domain"
    try:
        ipaddress.ip_address(host)
    except ValueError:
        target_type = "domain"
    else:
        target_type = "ip"
    if target_type == "domain" and (
        str(host or "").casefold().startswith("api.")
        or any(part.casefold() == "api" for part in parsed.path.split("/"))
    ):
        target_type = "api"

    active_categories = ["port_scan", "subdomain", "directory", "asset"]
    if policy.passive_only:
        return ReconProfile(
            target_type=target_type,
            required_categories=[],
            disabled_categories=active_categories,
        )

    required = ["port_scan", "directory", "asset"]
    if target_type == "domain" and policy.allow_domain_scan and policy.allow_subdomains:
        required.insert(1, "subdomain")
    disabled = [category for category in active_categories if category not in required]
    return ReconProfile(
        target_type=target_type, required_categories=required, disabled_categories=disabled
    )


def _expire_leases_for_read(conn, project_id: str | None = None) -> None:
    """Run lease maintenance without turning a read endpoint into a 500."""
    try:
        expire_workers(conn, project_id)
        expire_reason_leases(conn, project_id)
    except sqlite3.OperationalError as exc:
        if "locked" not in str(exc).casefold():
            raise
        conn.rollback()


@router.get("/projects", response_model=list[ProjectSummary])
def list_projects():
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT p.*,
                (SELECT COUNT(*) FROM facts WHERE project_id = p.id) AS fact_count,
                (SELECT COUNT(*) FROM intents WHERE project_id = p.id) AS intent_count,
                (SELECT COUNT(*) FROM intents WHERE project_id = p.id AND concluded_at IS NULL AND status = 'open' AND worker IS NOT NULL) AS working_intent_count,
                (SELECT COUNT(*) FROM intents WHERE project_id = p.id AND concluded_at IS NULL AND status = 'open' AND worker IS NULL) AS unclaimed_intent_count,
                (SELECT COUNT(*) FROM hints WHERE project_id = p.id) AS hint_count
            FROM projects p
            ORDER BY p.created_at
        """).fetchall()
        summaries = []
        for row in rows:
            meta = project_meta_from_row(row)
            summaries.append(
                ProjectSummary(
                    **meta.model_dump(),
                    fact_count=row["fact_count"],
                    intent_count=row["intent_count"],
                    working_intent_count=row["working_intent_count"],
                    unclaimed_intent_count=row["unclaimed_intent_count"],
                    hint_count=row["hint_count"],
                )
            )
        return summaries


@router.post("/projects", response_model=ProjectDetail, status_code=201)
def create_project(body: CreateProjectRequest):
    with get_conn() as conn:
        pid = next_project_id(conn)
        now = utcnow()

        mode = body.mode or ("ctf" if body.bootstrap_enabled else "real_website")
        bootstrap_enabled = mode == "ctf"
        phase = "explore" if mode == "ctf" else "recon"
        recon_profile = body.recon_profile or _target_aware_recon_profile(body.origin, body.scope_policy)
        conn.execute(
            """
            INSERT INTO projects (id, title, status, bootstrap_enabled, phase, mode, planning_version, scope_policy, recon_profile, created_at)
            VALUES (?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                pid,
                body.title,
                int(bootstrap_enabled),
                phase,
                mode,
                3 if mode == "real_website" else 1,
                json.dumps(body.scope_policy.model_dump()),
                json.dumps(recon_profile.model_dump()),
                now,
            ),
        )
        conn.execute(
            """INSERT INTO facts (
                id, project_id, description, kind, summary, subject, created_by, created_at
            ) VALUES (?, ?, ?, 'target', ?, ?, 'project_create', ?)""",
            ("origin", pid, body.origin, body.origin[:320], json.dumps({"origin": body.origin}), now),
        )
        conn.execute(
            """INSERT INTO facts (
                id, project_id, description, kind, summary, data, created_by, created_at
            ) VALUES (?, ?, ?, 'goal', ?, ?, 'project_create', ?)""",
            ("goal", pid, body.goal, body.goal[:320], json.dumps({"goal": body.goal}), now),
        )

        hints = []
        if body.hints:
            for h in body.hints:
                hid = next_hint_id(conn, pid)
                conn.execute(
                    "INSERT INTO hints (id, project_id, content, creator, created_at) VALUES (?, ?, ?, ?, ?)",
                    (hid, pid, h.content, h.creator, now),
                )
                hints.append(Hint(id=hid, content=h.content, creator=h.creator, created_at=now))

        return ProjectDetail(
            project=ProjectMeta(
                id=pid,
                title=body.title,
                status="active",
                bootstrap_enabled=bootstrap_enabled,
                phase=phase,
                mode=mode,
                planning_version=3 if mode == "real_website" else 1,
                scope_policy=body.scope_policy,
                recon_profile=recon_profile,
                created_at=now,
                reason=None,
            ),
            facts=[
                Fact(id="origin", description=body.origin),
                Fact(id="goal", description=body.goal),
            ],
            intents=[],
            hints=hints,
        )


@router.get("/projects/{project_id}", response_model=ProjectDetail)
def get_project(project_id: str, view: Literal["full", "dispatch"] = "full"):
    with get_conn() as conn:
        row = get_project_or_404(conn, project_id)

        facts = conn.execute(
            "SELECT * FROM facts WHERE project_id = ?", (project_id,)
        ).fetchall()
        dispatch_detail_ids = {"origin", "goal"}
        if view == "dispatch":
            dispatch_detail_ids.update(fact["id"] for fact in facts[-12:])
            dispatch_detail_ids.update(
                source["fact_id"]
                for source in conn.execute(
                    """SELECT DISTINCT source.fact_id
                    FROM intent_sources source
                    JOIN intents intent
                      ON intent.project_id = source.project_id AND intent.id = source.intent_id
                    WHERE source.project_id = ? AND intent.status = 'open'""",
                    (project_id,),
                ).fetchall()
            )
            dispatch_detail_ids.update(
                fact["id"] for fact in facts
                if str(fact["severity"] or "").casefold() in {"critical", "high"}
            )
        hints = conn.execute(
            "SELECT * FROM hints WHERE project_id = ? ORDER BY created_at",
            (project_id,),
        ).fetchall()
        coverage_rows = conn.execute(
            "SELECT * FROM coverage_items WHERE project_id = ? ORDER BY created_at",
            (project_id,),
        ).fetchall()
        surface_rows = conn.execute(
            "SELECT * FROM surface_inventory WHERE project_id = ? ORDER BY created_at, id",
            (project_id,),
        ).fetchall()
        attack_paths = (
            build_completed_attack_paths(conn, project_id)
            if view == "full"
            else []
        )

        return ProjectDetail(
            project=project_meta_from_row(
                row,
                conn,
                include_completion_blockers=view == "full",
            ),
            facts=[
                fact_to_model(conn, fact, project_id)
                if view == "full"
                else fact_to_dispatch_model(fact, include_detail=fact["id"] in dispatch_detail_ids)
                for fact in facts
            ],
            intents=build_intents(conn, project_id),
            hints=[Hint(**dict(hint)) for hint in hints],
            attack_paths=attack_paths,
            coverage_items=build_coverage_items(conn, project_id, coverage_rows),
            surface_inventory=[
                surface_inventory_to_model(surface) for surface in surface_rows
            ],
            hypotheses=build_hypotheses(conn, project_id),
        )


@router.delete("/projects/{project_id}", status_code=204)
def delete_project(project_id: str):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))


@router.put("/projects/{project_id}/title", response_model=ProjectMeta)
def update_project_title(project_id: str, body: UpdateProjectTitleRequest):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        conn.execute(
            "UPDATE projects SET title = ? WHERE id = ?",
            (body.title, project_id),
        )
        updated = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        return project_meta_from_row(updated)


@router.put("/projects/{project_id}/status", response_model=ProjectMeta)
def update_project_status(project_id: str, body: UpdateProjectStatusRequest):
    with get_conn() as conn:
        expire_reason_leases(conn, project_id)
        row = get_project_or_404(conn, project_id)
        current_status = row["status"]
        if current_status == "completed":
            raise HTTPException(409, "Completed projects cannot change status")
        if current_status == body.status:
            return project_meta_from_row(row)

        if body.status == "active":
            conn.execute(
                """UPDATE projects SET status = 'active', completion_outcome = NULL,
                stop_reason_code = NULL, stop_reason_detail = NULL WHERE id = ?""",
                (project_id,),
            )
            clear_reason_failure(conn, project_id)
            clear_completion_blocked(conn, project_id)
        else:
            conn.execute(
                """UPDATE projects SET status = 'stopped', completion_outcome = 'stopped',
                stop_reason_code = 'manual_stop', stop_reason_detail = 'Stopped by project status update.',
                reason_last_outcome = CASE
                    WHEN reason_last_outcome = 'running' THEN 'cancelled'
                    ELSE reason_last_outcome
                END,
                reason_next_retry_at = NULL
                WHERE id = ?""",
                (project_id,),
            )
        if body.status == "stopped":
            conn.execute(
                "UPDATE intents SET worker = NULL WHERE project_id = ? AND concluded_at IS NULL",
                (project_id,),
            )
            clear_project_reason(conn, project_id)
        updated = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        return project_meta_from_row(updated)


def _advance_project_phase(conn, project_id: str) -> PhaseAdvanceResponse:
    row = check_project_active(conn, project_id)
    if row["phase"] == "explore":
        return PhaseAdvanceResponse(
            advanced=False, from_phase="explore", to_phase="explore",
            code="already_explore", message="Project is already in explore.",
        )
    if row["mode"] != "real_website":
        conn.execute("UPDATE projects SET phase = 'explore' WHERE id = ?", (project_id,))
        return PhaseAdvanceResponse(
            advanced=True, from_phase="recon", to_phase="explore",
            code="advanced", message="Non-real-website project advanced to explore.",
        )
    backfill_legacy_recon_facts(conn, project_id)
    gate = recon_gate_result(conn, project_id, project_meta_from_row(row).recon_profile)
    attempted_at = utcnow()
    if not gate.ready:
        detail = {
            "code": "recon_incomplete",
            "missing_categories": gate.missing_categories,
            "open_recon_intents": gate.open_recon_intents,
        }
        conn.execute(
            """UPDATE projects
            SET phase_transition_last_error = ?, phase_transition_attempted_at = ?
            WHERE id = ?""",
            (json.dumps(detail, sort_keys=True), attempted_at, project_id),
        )
        return PhaseAdvanceResponse(
            advanced=False, from_phase="recon", to_phase="recon",
            code="recon_incomplete", message="Structured Recon gate is not ready.",
            missing_categories=gate.missing_categories,
            open_recon_intents=gate.open_recon_intents,
        )
    conn.execute(
        """UPDATE projects
        SET phase = 'explore', phase_transition_last_error = NULL,
            phase_transition_attempted_at = ?, completion_blocked_at = NULL
        WHERE id = ?""",
        (attempted_at, project_id),
    )
    return PhaseAdvanceResponse(
        advanced=True, from_phase="recon", to_phase="explore",
        code="advanced", message="Structured Recon gate passed; project advanced to explore.",
    )


@router.post("/projects/{project_id}/phase/advance", response_model=PhaseAdvanceResponse)
def advance_project_phase(project_id: str):
    with get_conn() as conn:
        return _advance_project_phase(conn, project_id)


@router.put("/projects/{project_id}/phase", response_model=ProjectMeta)
def update_project_phase(project_id: str, body: UpdateProjectPhaseRequest):
    with get_conn() as conn:
        row = check_project_active(conn, project_id)
        if row["phase"] == "explore" and body.phase == "recon":
            raise HTTPException(
                409, "Project phase is monotonic; explore cannot return to recon"
            )
        if body.phase == "explore" and row["phase"] == "recon":
            result = _advance_project_phase(conn, project_id)
            if not result.advanced:
                return JSONResponse(
                    status_code=409,
                    content={"detail": result.model_dump(mode="json")},
                )
            updated = get_project_or_404(conn, project_id)
            return project_meta_from_row(updated, conn)
        conn.execute("UPDATE projects SET phase = ? WHERE id = ?", (body.phase, project_id))
        updated = get_project_or_404(conn, project_id)
        return project_meta_from_row(updated, conn)


@router.put("/projects/{project_id}/mode", response_model=ProjectMeta)
def update_project_mode(project_id: str, body: UpdateProjectModeRequest):
    with get_conn() as conn:
        row = get_project_or_404(conn, project_id)
        current_status = row["status"]
        if current_status == "completed":
            raise HTTPException(409, "Completed projects cannot change mode")

        bootstrap_enabled = body.mode == "ctf"
        phase = "explore" if body.mode == "ctf" else "recon"
        recon_profile_json = row["recon_profile"]
        if body.mode == "real_website":
            origin = conn.execute(
                "SELECT description FROM facts WHERE project_id = ? AND id = 'origin'",
                (project_id,),
            ).fetchone()
            policy = project_meta_from_row(row).scope_policy
            profile = _target_aware_recon_profile(
                origin["description"] if origin else "", policy
            )
            recon_profile_json = json.dumps(profile.model_dump())

        conn.execute(
            "UPDATE projects SET bootstrap_enabled = ?, phase = ?, mode = ?, recon_profile = ? WHERE id = ?",
            (int(bootstrap_enabled), phase, body.mode, recon_profile_json, project_id),
        )
        updated = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        return project_meta_from_row(updated)


@router.post("/projects/{project_id}/reason/claim", response_model=ProjectMeta)
def claim_project_reason(project_id: str, body: ReasonClaimRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        expire_reason_leases(conn, project_id)
        row = get_project_or_404(conn, project_id)
        fingerprint = reason_state_fingerprint(conn, project_id)
        stored_fingerprint = row["reason_state_fingerprint"]
        if stored_fingerprint and stored_fingerprint != fingerprint:
            conn.execute(
                """UPDATE projects
                SET reason_attempt_count = 0, reason_last_error = NULL,
                    reason_next_retry_at = NULL, reason_dead_lettered_at = NULL,
                    reason_state_fingerprint = ?, reason_last_outcome = NULL
                WHERE id = ?""",
                (fingerprint, project_id),
            )
            row = get_project_or_404(conn, project_id)
        elif stored_fingerprint == fingerprint and row["reason_last_outcome"] == "success":
            return JSONResponse(
                status_code=409,
                content={"detail": {"code": "reason_state_unchanged", "fingerprint": fingerprint}},
            )
        elif not stored_fingerprint:
            conn.execute(
                "UPDATE projects SET reason_state_fingerprint = ? WHERE id = ?",
                (fingerprint, project_id),
            )
            row = get_project_or_404(conn, project_id)
        current_worker = row["reason_worker"]
        if row["reason_dead_lettered_at"] is not None:
            return JSONResponse(
                status_code=409,
                content={"detail": {
                    "code": "reason_dead_lettered",
                    "fingerprint": fingerprint,
                    "message": "Reason retries are exhausted for the current graph state.",
                }},
            )
        if row["reason_next_retry_at"] is not None and row["reason_next_retry_at"] > utcnow():
            raise HTTPException(409, f"Project reason retry is delayed until {row['reason_next_retry_at']}")
        if current_worker is not None and current_worker != body.worker:
            raise HTTPException(409, f"Project reason is currently claimed by {current_worker}")
        if current_worker == body.worker:
            return project_meta_from_row(row)

        now = utcnow()
        conn.execute(
            """
            UPDATE projects
            SET reason_worker = ?,
                reason_trigger = ?,
                reason_started_at = ?,
                reason_last_heartbeat_at = ?,
                reason_last_outcome = 'running'
            WHERE id = ?
            """,
            (body.worker, body.trigger, now, now, project_id),
        )
        updated = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        return project_meta_from_row(updated)


@router.post("/projects/{project_id}/reason/heartbeat", response_model=ProjectMeta)
def heartbeat_project_reason(project_id: str, body: HeartbeatRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        expire_reason_leases(conn, project_id)
        row = get_project_or_404(conn, project_id)
        current_worker = row["reason_worker"]
        if current_worker is None:
            raise HTTPException(409, "Project reason is not currently claimed")
        if current_worker != body.worker:
            raise HTTPException(409, f"Project reason is currently claimed by {current_worker}")

        now = utcnow()
        conn.execute(
            "UPDATE projects SET reason_last_heartbeat_at = ? WHERE id = ?",
            (now, project_id),
        )
        updated = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        return project_meta_from_row(updated)


@router.post("/projects/{project_id}/reason/release", response_model=ProjectMeta)
def release_project_reason(project_id: str, body: HeartbeatRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        expire_reason_leases(conn, project_id)
        row = get_project_or_404(conn, project_id)
        current_worker = row["reason_worker"]
        if current_worker is None:
            return project_meta_from_row(row)
        if current_worker != body.worker:
            raise HTTPException(409, f"Project reason is currently claimed by {current_worker}")

        clear_project_reason(conn, project_id)
        updated = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        return project_meta_from_row(updated)


@router.post("/projects/{project_id}/reason/failure", response_model=ProjectMeta)
def record_project_reason_failure(project_id: str, body: TaskFailureRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        updated = mark_reason_failure(
            conn,
            project_id,
            worker=body.worker,
            error=body.error,
            max_attempts=body.max_attempts,
            backoff_seconds=body.backoff_seconds,
        )
        return project_meta_from_row(updated)


@router.post("/projects/{project_id}/reason/success", response_model=ProjectMeta)
def record_project_reason_success(project_id: str, body: HeartbeatRequest):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        updated = mark_reason_success(conn, project_id)
        return project_meta_from_row(updated)


@router.post("/projects/{project_id}/blockers/continue", response_model=ProjectMeta)
def continue_blocked_project(project_id: str, body: ContinueBlockedProjectRequest):
    with get_conn() as conn:
        row = get_project_or_404(conn, project_id)
        if row["status"] == "completed":
            raise HTTPException(409, "Completed projects cannot be resumed")
        if row["status"] == "stopped":
            conn.execute(
                """UPDATE projects
                SET status = 'active', completion_outcome = NULL,
                    stop_reason_code = NULL, stop_reason_detail = NULL
                WHERE id = ?""",
                (project_id,),
            )
        clear_project_reason(conn, project_id)
        clear_reason_failure(conn, project_id)
        clear_completion_blocked(conn, project_id)
        now = utcnow()
        hint_id = next_hint_id(conn, project_id)
        conn.execute(
            "INSERT INTO hints (id, project_id, content, creator, created_at) VALUES (?, ?, ?, ?, ?)",
            (hint_id, project_id, body.note, body.creator, now),
        )
        updated = get_project_or_404(conn, project_id)
        return project_meta_from_row(updated, conn)


@router.post("/projects/{project_id}/needs-attention", response_model=ProjectMeta)
def stop_project_needs_attention(project_id: str, body: NeedsAttentionRequest):
    with get_conn() as conn:
        row = get_project_or_404(conn, project_id)
        if row["status"] == "completed":
            raise HTTPException(409, "Completed projects cannot be stopped as needs_attention")
        conn.execute(
            """UPDATE projects
            SET status = 'stopped', completion_outcome = 'needs_attention',
                stop_reason_code = ?, stop_reason_detail = ?,
                reason_worker = NULL, reason_trigger = NULL,
                reason_started_at = NULL, reason_last_heartbeat_at = NULL
            WHERE id = ?""",
            (body.reason_code, body.detail, project_id),
        )
        conn.execute(
            """UPDATE intents SET worker = NULL, last_heartbeat_at = NULL
            WHERE project_id = ? AND to_fact_id IS NULL AND status = 'open'""",
            (project_id,),
        )
        updated = get_project_or_404(conn, project_id)
        return project_meta_from_row(updated, conn)



@router.post("/projects/{project_id}/complete", response_model=Intent)
def complete_project(project_id: str, body: CompleteRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        expire_workers(conn, project_id)
        expire_reason_leases(conn, project_id)
        validate_facts_exist(conn, project_id, body.from_)
        validate_goal_not_in_sources(body.from_)
        validate_completion_source_integrity(conn, project_id, body.from_)
        reconcile_project_coverage(conn, project_id)
        try:
            validate_project_completion_allowed(conn, project_id)
        except HTTPException as exc:
            if exc.status_code != 409 or not isinstance(exc.detail, dict) or exc.detail.get("code") != "completion_blocked":
                raise
            conn.execute(
                "UPDATE projects SET completion_blocked_at = ? WHERE id = ?",
                (utcnow(), project_id),
            )
            return JSONResponse(status_code=409, content={"detail": exc.detail})

        now = utcnow()
        iid = next_intent_id(conn, project_id)

        conn.execute(
            """
            INSERT INTO intents (
                id, project_id, to_fact_id, description, creator, worker, last_heartbeat_at, created_at, concluded_at, status
            ) VALUES (?, ?, 'goal', ?, ?, ?, ?, ?, ?, 'concluded')
            """,
            (iid, project_id, body.description, body.worker, body.worker, now, now, now),
        )
        for fid in body.from_:
            conn.execute(
                "INSERT INTO intent_sources (intent_id, project_id, fact_id) VALUES (?, ?, ?)",
                (iid, project_id, fid),
            )
        conn.execute(
            """
            UPDATE projects
            SET status = 'completed',
                completion_outcome = 'complete',
                stop_reason_code = NULL,
                stop_reason_detail = NULL,
                completion_blocked_at = NULL,
                reason_attempt_count = 0,
                reason_last_error = NULL,
                reason_next_retry_at = NULL,
                reason_dead_lettered_at = NULL,
                reason_worker = NULL,
                reason_trigger = NULL,
                reason_started_at = NULL,
                reason_last_heartbeat_at = NULL
            WHERE id = ?
            """,
            (project_id,),
        )

        return Intent(
            id=iid,
            **{"from": body.from_},
            to="goal",
            description=body.description,
            creator=body.worker,
            worker=body.worker,
            last_heartbeat_at=now,
            created_at=now,
            concluded_at=now,
            status="concluded",
        )


@router.post("/projects/{project_id}/reopen", response_model=ReopenResponse)
def reopen_project(project_id: str, body: ReopenRequest):
    with get_conn() as conn:
        expire_reason_leases(conn, project_id)
        check_project_completed(conn, project_id)
        completion = get_completion_intent_or_409(conn, project_id)

        source_rows = conn.execute(
            "SELECT fact_id FROM intent_sources WHERE intent_id = ? AND project_id = ? ORDER BY rowid",
            (completion["id"], project_id),
        ).fetchall()
        source_ids = [row["fact_id"] for row in source_rows]
        if not source_ids:
            raise HTTPException(409, "Completion intent is missing its source facts")

        now = utcnow()
        fact_id = next_fact_id(conn, project_id)
        intent_id = next_intent_id(conn, project_id)
        description = body.description
        creator = body.creator

        conn.execute(
            "DELETE FROM intents WHERE id = ? AND project_id = ?",
            (completion["id"], project_id),
        )
        conn.execute(
            "INSERT INTO facts (id, project_id, description) VALUES (?, ?, ?)",
            (fact_id, project_id, description),
        )
        conn.execute(
            """
            INSERT INTO intents (
                id, project_id, to_fact_id, description, creator, worker, last_heartbeat_at, created_at, concluded_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'concluded')
            """,
            (intent_id, project_id, fact_id, "external_feedback", creator, creator, now, now, now),
        )
        for source_id in source_ids:
            conn.execute(
                "INSERT INTO intent_sources (intent_id, project_id, fact_id) VALUES (?, ?, ?)",
                (intent_id, project_id, source_id),
            )
        clear_project_reason(conn, project_id)
        conn.execute(
            "UPDATE projects SET status = 'active' WHERE id = ?",
            (project_id,),
        )

        updated_project = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        updated_intent = conn.execute(
            "SELECT * FROM intents WHERE id = ? AND project_id = ?",
            (intent_id, project_id),
        ).fetchone()
        assert updated_project is not None
        assert updated_intent is not None
        return ReopenResponse(
            project=project_meta_from_row(updated_project),
            fact=Fact(id=fact_id, description=description),
            intent=intent_to_model(conn, updated_intent, project_id),
        )


@router.post("/projects/{project_id}/facts", response_model=Fact, status_code=201)
def create_fact_direct(project_id: str, body: CreateFactDirectRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        get_project_or_404(conn, project_id)
        if body.verification_of:
            validate_facts_exist(conn, project_id, [body.verification_of])
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
        validate_verification_reference(
            conn,
            project_id,
            body.verification_of,
            candidate_variant=body.vuln_type,
            candidate_status=body.status,
        )
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
                body.vuln_type,
                body.severity,
                body.parent_fact,
                body.verification_of,
                body.goal_type,
                body.status,
                body.recon_category,
                _bool_to_db(body.recon_executed),
                _bool_to_db(body.recon_found_results),
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
                body.created_by,
                now, project_id, fid,
            ),
        )
        reconcile_fact_coverage(
            conn,
            project_id,
            fid,
            explicit_coverage_refs=body.coverage_refs,
        )

        clear_completion_blocked(conn, project_id)
        created = conn.execute(
            "SELECT * FROM facts WHERE id = ? AND project_id = ?",
            (fid, project_id),
        ).fetchone()
        assert created is not None
        return fact_to_model(conn, created, project_id)


@router.put("/projects/{project_id}/facts/{fact_id}", response_model=Fact)
def update_fact_status(project_id: str, fact_id: str, body: UpdateFactStatusRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        row = conn.execute(
            "SELECT * FROM facts WHERE id = ? AND project_id = ?",
            (fact_id, project_id),
        ).fetchone()
        if row is None:
            raise HTTPException(404, f"Fact {fact_id} not found")

        if body.verification_of:
            if body.verification_of == fact_id:
                raise HTTPException(400, "A Fact cannot verify itself")
            validate_facts_exist(conn, project_id, [body.verification_of])
        status = body.status if body.status is not None else row["status"]
        evidence_ref = (
            body.recon_evidence_ref
            if body.recon_evidence_ref is not None
            else row["recon_evidence_ref"]
        )
        verification_of = (
            body.verification_of
            if body.verification_of is not None
            else row["verification_of"]
        )
        validate_verification_reference(
            conn,
            project_id,
            verification_of,
            candidate_variant=row["vuln_type"],
            candidate_status=status,
        )
        conn.execute(
            """
            UPDATE facts
            SET status = ?, recon_evidence_ref = ?, verification_of = ?
            WHERE id = ? AND project_id = ?
            """,
            (status, evidence_ref, verification_of, fact_id, project_id),
        )
        reconcile_fact_coverage(conn, project_id, fact_id)

        clear_completion_blocked(conn, project_id)
        updated = conn.execute(
            "SELECT * FROM facts WHERE id = ? AND project_id = ?",
            (fact_id, project_id),
        ).fetchone()
        assert updated is not None
        return fact_to_model(conn, updated, project_id)


def _bool_to_db(value: bool | None) -> int | None:
    if value is None:
        return None
    return int(value)

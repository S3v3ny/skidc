from fastapi import APIRouter, HTTPException, Query

from skidc.server.db import get_conn
from skidc.server.models import CreateTaskLogRequest, TaskLog, TaskLogSummary
from skidc.server.services import (
    expire_reason_leases,
    expire_workers,
    get_project_or_404,
    next_log_id,
    utcnow,
)

router = APIRouter(tags=["logs"])

LOG_PREVIEW_LIMIT = 500
LOG_FIELD_LIMIT = 64 * 1024


def _bounded(value: str | None) -> tuple[str | None, bool]:
    if value is None or len(value) <= LOG_FIELD_LIMIT:
        return value, False
    marker = "\n\n... output truncated by server ...\n\n"
    remaining = LOG_FIELD_LIMIT - len(marker)
    head = remaining * 3 // 4
    tail = remaining - head
    return value[:head] + marker + value[-tail:], True


@router.post("/projects/{project_id}/logs", response_model=TaskLog, status_code=201)
def create_task_log(project_id: str, body: CreateTaskLogRequest):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        log_id = next_log_id(conn, project_id)
        now = utcnow()
        stdout, stdout_truncated = _bounded(body.stdout)
        stderr, stderr_truncated = _bounded(body.stderr)

        conn.execute(
            """
            INSERT INTO task_logs (id, project_id, task_type, intent_id, worker_name, phase, stdin, stdout, stderr, return_code, timed_out, duration_ms, stdout_truncated, stderr_truncated, artifact_ref, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                log_id,
                project_id,
                body.task_type,
                body.intent_id,
                body.worker_name,
                body.phase,
                body.stdin,
                stdout,
                stderr,
                body.return_code,
                int(body.timed_out),
                body.duration_ms,
                int(stdout_truncated),
                int(stderr_truncated),
                None,
                now,
            ),
        )

        return TaskLog(
            id=log_id,
            project_id=project_id,
            task_type=body.task_type,
            intent_id=body.intent_id,
            worker_name=body.worker_name,
            phase=body.phase,
            stdin=body.stdin,
            stdout=stdout,
            stderr=stderr,
            return_code=body.return_code,
            timed_out=body.timed_out,
            duration_ms=body.duration_ms,
            created_at=now,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
        )


@router.get("/projects/{project_id}/logs", response_model=list[TaskLogSummary])
def list_task_logs(
    project_id: str,
    task_type: str | None = Query(None),
    intent_id: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)

        query = """
            SELECT id, task_type, intent_id, worker_name, phase, return_code,
                   timed_out, duration_ms, stdout_truncated, stderr_truncated, artifact_ref, created_at,
                   SUBSTR(COALESCE(stdin, ''), 1, ?) AS stdin_preview,
                   SUBSTR(COALESCE(stdout, ''), 1, ?) AS stdout_preview
            FROM task_logs
            WHERE project_id = ?
        """
        params: list = [LOG_PREVIEW_LIMIT, LOG_PREVIEW_LIMIT, project_id]

        if task_type:
            query += " AND task_type = ?"
            params.append(task_type)
        if intent_id:
            query += " AND intent_id = ?"
            params.append(intent_id)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()

        return [
            TaskLogSummary(
                id=row["id"],
                task_type=row["task_type"],
                intent_id=row["intent_id"],
                worker_name=row["worker_name"],
                phase=row["phase"],
                return_code=row["return_code"],
                timed_out=bool(row["timed_out"]),
                duration_ms=row["duration_ms"],
                stdin_preview=row["stdin_preview"],
                stdout_preview=row["stdout_preview"],
                stdout_truncated=bool(row["stdout_truncated"]),
                stderr_truncated=bool(row["stderr_truncated"]),
                artifact_ref=row["artifact_ref"],
                created_at=row["created_at"],
            )
            for row in rows
        ]


@router.get("/projects/{project_id}/logs/{log_id}", response_model=TaskLog)
def get_task_log(project_id: str, log_id: str):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        row = conn.execute(
            "SELECT * FROM task_logs WHERE id = ? AND project_id = ?",
            (log_id, project_id),
        ).fetchone()

        if not row:
            raise HTTPException(404, f"Task log {log_id} not found")

        return TaskLog(
            id=row["id"],
            project_id=row["project_id"],
            task_type=row["task_type"],
            intent_id=row["intent_id"],
            worker_name=row["worker_name"],
            phase=row["phase"],
            stdin=row["stdin"],
            stdout=row["stdout"],
            stderr=row["stderr"],
            return_code=row["return_code"],
            timed_out=bool(row["timed_out"]),
            duration_ms=row["duration_ms"],
            created_at=row["created_at"],
            stdout_truncated=bool(row["stdout_truncated"]),
            stderr_truncated=bool(row["stderr_truncated"]),
            artifact_ref=row["artifact_ref"],
        )

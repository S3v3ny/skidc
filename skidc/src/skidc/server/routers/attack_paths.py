from __future__ import annotations

from fastapi import APIRouter, HTTPException

from skidc.server.db import get_conn
from skidc.server.models import AttackPath, CreateAttackPathRequest, UpdateAttackPathStatusRequest
from skidc.server.services import build_completed_attack_paths, get_project_or_404

router = APIRouter(tags=["attack_paths"])


def _read_only_error() -> HTTPException:
    return HTTPException(
        409,
        detail={
            "code": "attack_paths_read_only",
            "message": (
                "Attack paths are derived from concluded Fact–Intent edges after a goal "
                "completion edge exists; they cannot be created or edited directly."
            ),
        },
    )


@router.get("/projects/{project_id}/attack-paths", response_model=list[AttackPath])
def list_attack_paths(project_id: str):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        return build_completed_attack_paths(conn, project_id)


@router.post(
    "/projects/{project_id}/attack-paths",
    response_model=AttackPath,
    status_code=201,
)
def create_attack_path(project_id: str, body: CreateAttackPathRequest):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
    raise _read_only_error()


@router.put("/projects/{project_id}/attack-paths/{path_id}/status", response_model=AttackPath)
def update_attack_path_status(project_id: str, path_id: str, body: UpdateAttackPathStatusRequest):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
    raise _read_only_error()


@router.delete("/projects/{project_id}/attack-paths/{path_id}", status_code=204)
def delete_attack_path(project_id: str, path_id: str):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
    raise _read_only_error()
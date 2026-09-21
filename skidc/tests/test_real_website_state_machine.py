from __future__ import annotations

from fastapi.testclient import TestClient


def _real_project(http: TestClient, required: list[str]) -> str:
    response = http.post(
        "/projects",
        json={
            "title": "state machine",
            "origin": "https://example.test/",
            "goal": "assess",
            "mode": "real_website",
            "bootstrap_enabled": False,
            "recon_profile": {
                "required_categories": required,
                "disabled_categories": [],
            },
        },
    )
    assert response.status_code == 201
    return response.json()["project"]["id"]


def _conclude(
    http: TestClient,
    project_id: str,
    *,
    description: str,
    action_kind: str | None = None,
) -> dict:
    body = {
        "from": ["origin"],
        "description": description,
        "creator": "reasoner",
    }
    if action_kind is not None:
        body["action_kind"] = action_kind
    intent = http.post(f"/projects/{project_id}/intents", json=body)
    assert intent.status_code == 201
    intent_id = intent.json()["id"]
    heartbeat = http.post(
        f"/projects/{project_id}/intents/{intent_id}/heartbeat",
        json={"worker": "worker"},
    )
    assert heartbeat.status_code == 200
    result = http.post(
        f"/projects/{project_id}/intents/{intent_id}/conclude",
        json={"worker": "worker", "description": f"finished: {description}"},
    )
    assert result.status_code == 200
    return result.json()["fact"]


def test_conclusion_derives_structured_recon_and_server_advances_phase(
    http_client: TestClient,
) -> None:
    project_id = _real_project(http_client, ["port_scan"])
    fact = _conclude(
        http_client,
        project_id,
        description="collect service inventory",
        action_kind="port_scan",
    )

    assert fact["recon_category"] == "port_scan"
    assert fact["recon_executed"] is True
    transition = http_client.post(f"/projects/{project_id}/phase/advance", json={})
    assert transition.status_code == 200
    assert transition.json()["advanced"] is True
    assert http_client.get(f"/projects/{project_id}").json()["project"]["phase"] == "explore"


def test_legacy_recon_prose_is_backfilled_once_before_structured_gate(
    http_client: TestClient,
) -> None:
    project_id = _real_project(http_client, ["port_scan"])
    fact = _conclude(
        http_client,
        project_id,
        description="Run an nmap port scan and record service enumeration.",
    )
    assert fact["recon_category"] is None

    transition = http_client.post(f"/projects/{project_id}/phase/advance", json={})
    assert transition.status_code == 200
    assert transition.json()["advanced"] is True
    facts = {
        item["id"]: item
        for item in http_client.get(f"/projects/{project_id}").json()["facts"]
    }
    assert facts[fact["id"]]["recon_category"] == "port_scan"
    assert facts[fact["id"]]["recon_executed"] is True


def test_dispatch_view_skips_full_completion_enrichment(
    http_client: TestClient,
) -> None:
    project_id = _real_project(http_client, [])
    assert http_client.post(f"/projects/{project_id}/phase/advance", json={}).json()["advanced"]
    coverage = http_client.post(
        f"/projects/{project_id}/coverage",
        json={
            "item_type": "param",
            "description": "required SQL check",
            "test_family": "injection",
            "test_variants": ["sql"],
            "priority": 8,
        },
    )
    assert coverage.status_code == 201

    dispatch = http_client.get(f"/projects/{project_id}?view=dispatch")
    full = http_client.get(f"/projects/{project_id}?view=full")
    assert dispatch.status_code == full.status_code == 200
    assert dispatch.json()["project"]["completion_blockers"] == []
    assert full.json()["project"]["completion_blockers"] == []


def test_reason_success_is_not_reclaimed_until_semantic_state_changes(
    http_client: TestClient,
) -> None:
    project_id = _real_project(http_client, [])
    claimed = http_client.post(
        f"/projects/{project_id}/reason/claim",
        json={"worker": "reasoner", "trigger": "initial"},
    )
    assert claimed.status_code == 200
    success = http_client.post(
        f"/projects/{project_id}/reason/success",
        json={"worker": "reasoner"},
    )
    assert success.status_code == 200

    duplicate = http_client.post(
        f"/projects/{project_id}/reason/claim",
        json={"worker": "reasoner", "trigger": "initial"},
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"]["code"] == "reason_state_unchanged"

    hint = http_client.post(
        f"/projects/{project_id}/hints",
        json={"content": "new authorized context", "creator": "operator"},
    )
    assert hint.status_code == 201
    changed = http_client.post(
        f"/projects/{project_id}/reason/claim",
        json={"worker": "reasoner", "trigger": "hint"},
    )
    assert changed.status_code == 200

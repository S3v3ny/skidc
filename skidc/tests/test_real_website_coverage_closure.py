from __future__ import annotations

import json

from fastapi.testclient import TestClient

from skidc.planning import behavior_identity, cluster_behaviors, derive_candidates
from skidc.dispatcher.prompting import format_dispatch_graph
from skidc.dispatcher.protocol.client import ApiResult
from skidc.dispatcher.tasks.reason import (
    _create_agent_hypothesis_work,
    _ensure_pending_surface_mapping_work,
    _select_v3_frontier,
    ensure_coverage_work,
)
from skidc.server.db import get_conn
from tests.conftest import InProcessClient


def _create_real_project(
    http: TestClient,
    *,
    origin: str = "https://example.test/",
    max_intents: int = 20,
    batch_size: int = 20,
    enter_explore: bool = True,
    planning_version: int = 2,
) -> str:
    response = http.post(
        "/projects",
        json={
            "title": "coverage closure",
            "origin": origin,
            "goal": "assess the authorized target",
            "mode": "real_website",
            "bootstrap_enabled": False,
            "scope_policy": {
                "allowed_targets": ["example.test"],
                "allowed_ports": [80, 443],
            },
            "recon_profile": {
                "target_type": "domain",
                "required_categories": [],
                "optional_categories": [],
                "disabled_categories": ["port_scan", "subdomain", "directory", "asset"],
                "max_coverage_intents": max_intents,
                "coverage_batch_size": batch_size,
            },
        },
    )
    project_id = response.json()["project"]["id"]
    assert response.status_code == 201
    if planning_version != 3:
        with get_conn() as conn:
            conn.execute(
                "UPDATE projects SET planning_version = ? WHERE id = ?", (planning_version, project_id)
            )
    if enter_explore:
        phase = http.put(f"/projects/{project_id}/phase", json={"phase": "explore"})
        assert phase.status_code == 200
    return project_id


def _create_injection_coverage(http: TestClient, project_id: str, variants: list[str]):
    response = http.post(
        f"/projects/{project_id}/coverage",
        json={
            "item_type": "param",
            "target": "example.test",
            "port": 443,
            "method": "GET",
            "path": "/search",
            "param": "q",
            "description": "Test the search input across all declared injection variants.",
            "surface_group": "search input",
            "surface_fingerprint": "surface-search-get-anonymous",
            "test_family": "injection",
            "test_variants": variants,
            "auth_context": "anonymous",
            "priority": 8,
        },
    )
    assert response.status_code == 201
    return response.json()


def test_real_project_cannot_complete_before_recon_transition(http_client: TestClient) -> None:
    project_id = _create_real_project(http_client, enter_explore=False)

    completed = http_client.post(
        f"/projects/{project_id}/complete",
        json={"from": ["origin"], "description": "premature", "worker": "reasoner"},
    )

    assert completed.status_code == 409
    blockers = completed.json()["detail"]["blockers"]
    assert any(item["ref"] == "project-phase" for item in blockers)


def test_v2_planner_records_limitations_without_blocking_completion(
    http_client: TestClient,
) -> None:
    project_id = _create_real_project(http_client)
    surface = http_client.post(
        f"/projects/{project_id}/surfaces",
        json={
            "fingerprint": "account-update-post",
            "surface_group": "account update",
            "target": "example.test",
            "port": 443,
            "method": "POST",
            "path_template": "/account/{id}",
            "params": ["id", "callback_url"],
            "auth_context": "session",
            "source_fact_id": "origin",
        },
    )
    assert surface.status_code == 200
    client = InProcessClient(http_client)

    before = client.get_project(project_id)
    assert before.project.planning_version == 2
    assert ensure_coverage_work(client, before, "reasoner") == 3
    planned = client.get_project(project_id)
    assert ensure_coverage_work(client, planned, "reasoner") == 0
    assert len(planned.hypotheses) == 3
    assert {item.test_variant for item in planned.hypotheses} == {
        "object_boundary", "ssrf", "csrf_state_change",
    }
    assert len(planned.coverage_items) == 3
    assert all(len(item.test_variants) == 1 for item in planned.coverage_items)
    assert all(intent.hypothesis_id for intent in planned.intents)

    report = http_client.get(f"/projects/{project_id}/export?format=report")
    assert report.status_code == 200
    assert "## Hypothesis Plan" in report.text
    assert "## Assessment Limitations" in report.text
    assert all(item.id in report.text for item in planned.hypotheses)

    for failed_intent in planned.intents:
        failed = http_client.post(
            f"/projects/{project_id}/intents/{failed_intent.id}/failure",
            json={"worker": "worker", "error": "bounded execution failed", "max_attempts": 1},
        )
        assert failed.status_code == 200
        assert failed.json()["status"] == "concluded"
        assert failed.json()["to"] is not None
    failed_intent = planned.intents[0]

    detail = client.get_project(project_id)
    failed_hypothesis = next(
        item for item in detail.hypotheses if item.id == failed_intent.hypothesis_id
    )
    assert failed_hypothesis.status == "inconclusive"
    completed = client.complete(
        project_id, ["origin"], "completed with explicit execution limitations", "reasoner",
    )
    assert completed.status_code == 200


def test_work_identity_deduplicates_primary_but_allows_explicit_verification(
    http_client: TestClient,
) -> None:
    project_id = _create_real_project(http_client)
    coverage = _create_injection_coverage(http_client, project_id, ["sql"])
    payload = {
        "from": ["origin"],
        "description": "primary SQL probe",
        "creator": "reasoner",
        "coverage_refs": [coverage["id"]],
        "test_variant": "sql",
        "action_kind": "injection_probe",
    }
    first = http_client.post(f"/projects/{project_id}/intents", json=payload)
    second = http_client.post(f"/projects/{project_id}/intents", json={**payload, "description": "replacement"})
    verification = http_client.post(
        f"/projects/{project_id}/intents",
        json={**payload, "description": "independent verification", "action_kind": "verification_probe"},
    )

    assert first.status_code == second.status_code == verification.status_code == 201
    assert first.json()["id"] == second.json()["id"]
    assert verification.json()["id"] != first.json()["id"]


def test_conclusion_surfaces_become_inventory_without_completion_deadlock(
    http_client: TestClient,
) -> None:
    project_id = _create_real_project(http_client)
    intent = http_client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "discover routes", "creator": "reasoner"},
    ).json()
    http_client.post(
        f"/projects/{project_id}/intents/{intent['id']}/heartbeat", json={"worker": "worker"}
    )
    concluded = http_client.post(
        f"/projects/{project_id}/intents/{intent['id']}/conclude",
        json={
            "worker": "worker",
            "description": "A POST upload surface was observed.",
            "status": "informational",
            "observed_surfaces": [{
                "fingerprint": "upload-post-authenticated",
                "surface_group": "authenticated upload",
                "target": "example.test",
                "port": 443,
                "method": "POST",
                "path_template": "/v1/upload",
                "params": ["file"],
                "auth_context": "authenticated",
                "surface_type": "upload_point",
            }],
        },
    )
    assert concluded.status_code == 200
    surfaces = http_client.get(f"/projects/{project_id}/surfaces").json()
    assert [(item["method"], item["path_template"]) for item in surfaces] == [("POST", "/v1/upload")]

    completed = http_client.post(
        f"/projects/{project_id}/complete",
        json={"from": [concluded.json()["fact"]["id"]], "description": "complete with pending surface recorded", "worker": "reasoner"},
    )
    assert completed.status_code == 200
    report = http_client.get(f"/projects/{project_id}/export?format=report").text
    assert "## Assessment Limitations" in report


def test_v3_pending_function_gets_one_mapping_intent_and_result_fact(
    http_client: TestClient,
) -> None:
    project_id = _create_real_project(http_client, planning_version=3)
    surface = http_client.post(
        f"/projects/{project_id}/surfaces",
        json={
            "fingerprint": "admin-edit-post",
            "surface_group": "admin edit",
            "target": "example.test",
            "port": 443,
            "method": "POST",
            "path_template": "/admin.php?r=edit",
            "params": ["id", "title"],
            "auth_context": "admin",
            "surface_type": "admin_route",
            "source_fact_id": "origin",
        },
    )
    assert surface.status_code == 200
    client = InProcessClient(http_client)
    project = client.get_project(project_id)

    assert _ensure_pending_surface_mapping_work(
        client, project, "reasoner", max_items=1,
    ) == 1
    mapped = client.get_project(project_id)
    assert mapped.surface_inventory[0].planning_status == "assessed"
    assert len(mapped.intents) == 1
    intent = mapped.intents[0]
    assert intent.action_kind == "surface_discovery"
    assert intent.test_variant == "function_mapping"

    failed = http_client.post(
        f"/projects/{project_id}/intents/{intent.id}/failure",
        json={
            "worker": "worker",
            "error": "mapping worker timed out",
            "max_attempts": 1,
            "backoff_seconds": 0,
        },
    )
    assert failed.status_code == 200
    assert failed.json()["status"] == "concluded"
    detail = client.get_project(project_id)
    result = next(fact for fact in detail.facts if fact.id == failed.json()["to"])
    assert result.kind == "execution_result"
    assert result.status == "failed"
    assert result.data["failure_stage"] == "execution_failed"


def test_failed_high_priority_behavior_does_not_block_next_breadth_slot(
    http_client: TestClient,
) -> None:
    project_id = _create_real_project(http_client, planning_version=3)
    endpoint = f"/projects/{project_id}/surfaces"
    for payload in (
        {
            "fingerprint": "admin-post",
            "surface_group": "admin update",
            "target": "example.test",
            "port": 443,
            "method": "POST",
            "path_template": "/admin/update",
            "params": ["id"],
            "auth_context": "admin",
            "surface_type": "admin_route",
            "source_fact_id": "origin",
        },
        {
            "fingerprint": "public-search",
            "surface_group": "public search",
            "target": "example.test",
            "port": 443,
            "method": "GET",
            "path_template": "/search",
            "params": ["q"],
            "auth_context": "anonymous",
            "surface_type": "route",
            "source_fact_id": "origin",
        },
    ):
        assert http_client.post(endpoint, json=payload).status_code == 200

    delegate = InProcessClient(http_client)

    class FailFirstClient:
        def __init__(self):
            self.failed = False

        def __getattr__(self, name):
            return getattr(delegate, name)

        def materialize_hypothesis_work(self, project_id: str, **payload):
            if not self.failed:
                self.failed = True
                return ApiResult(status_code=500, text="synthetic first behavior failure")
            return delegate.materialize_hypothesis_work(project_id, **payload)

    client = FailFirstClient()
    created = _ensure_pending_surface_mapping_work(
        client,
        delegate.get_project(project_id),
        "reasoner",
        max_items=1,
    )
    assert created == 1
    refreshed = delegate.get_project(project_id)
    statuses = {
        item.path_template: item.planning_status
        for item in refreshed.surface_inventory
    }
    assert statuses["/admin/update"] == "pending"
    assert statuses["/search"] == "assessed"
    assert len(refreshed.intents) == 1

def test_surface_assessment_is_monotonic_until_behavior_gains_new_semantics(
    http_client: TestClient,
) -> None:
    project_id = _create_real_project(http_client, planning_version=3)
    endpoint = f"/projects/{project_id}/surfaces"
    base = {
        "fingerprint": "stable-search",
        "surface_group": "search",
        "target": "example.test",
        "port": 443,
        "method": "GET",
        "path_template": "/search",
        "params": ["q"],
        "auth_context": "anonymous",
        "source_fact_id": "origin",
    }

    assert http_client.post(endpoint, json={**base, "planning_status": "assessed"}).status_code == 200
    duplicate = http_client.post(endpoint, json=base)
    assert duplicate.status_code == 200
    assert duplicate.json()["planning_status"] == "assessed"

    changed = http_client.post(endpoint, json={**base, "params": ["q", "callback_url"]})
    assert changed.status_code == 200
    assert changed.json()["planning_status"] == "pending"
    assert changed.json()["params"] == ["callback_url", "q"]


def test_v3_mapping_groups_duplicate_surface_observations_by_behavior(
    http_client: TestClient,
) -> None:
    project_id = _create_real_project(http_client, planning_version=3)
    endpoint = f"/projects/{project_id}/surfaces"
    common = {
        "surface_group": "article detail",
        "target": "example.test",
        "port": 443,
        "method": "GET",
        "auth_context": "session",
        "source_fact_id": "origin",
    }
    first = http_client.post(
        endpoint,
        json={
            **common,
            "fingerprint": "article-100",
            "path_template": "/article/100",
            "params": ["id"],
        },
    )
    second = http_client.post(
        endpoint,
        json={
            **common,
            "fingerprint": "article-200",
            "path_template": "/article/200",
            "params": ["id", "view"],
        },
    )
    assert first.status_code == second.status_code == 200
    client = InProcessClient(http_client)

    assert _ensure_pending_surface_mapping_work(
        client, client.get_project(project_id), "reasoner", max_items=3,
    ) == 1
    refreshed = client.get_project(project_id)
    assert len(refreshed.intents) == 1
    assert len(refreshed.hypotheses) == 1
    assert {item.planning_status for item in refreshed.surface_inventory} == {"assessed"}


def test_v3_dispatch_graph_uses_compact_behavior_view(
    http_client: TestClient,
) -> None:
    project_id = _create_real_project(http_client, planning_version=3)
    endpoint = f"/projects/{project_id}/surfaces"
    common = {
        "surface_group": "article detail",
        "target": "example.test",
        "port": 443,
        "method": "GET",
        "auth_context": "anonymous",
        "source_fact_id": "origin",
    }
    for fingerprint, path, params in (
        ("article-a", "/article/100", ["id"]),
        ("article-b", "/article/200", ["id", "q"]),
    ):
        response = http_client.post(
            endpoint,
            json={
                **common,
                "fingerprint": fingerprint,
                "path_template": path,
                "params": params,
            },
        )
        assert response.status_code == 200

    payload = json.loads(format_dispatch_graph(InProcessClient(http_client).get_project(project_id)))
    assert "surfaces" not in payload
    assert len(payload["behaviors"]) == 1
    assert payload["behaviors"][0]["observation_count"] == 2
    assert payload["behaviors"][0]["params"] == ["id", "q"]


def test_v2_assesses_non_security_behavior_without_creating_matrix(http_client: TestClient) -> None:
    project_id = _create_real_project(http_client)
    surface = http_client.post(
        f"/projects/{project_id}/surfaces",
        json={
            "fingerprint": "about-page",
            "surface_group": "public about page",
            "target": "example.test",
            "port": 443,
            "method": "GET",
            "path_template": "/about",
            "params": [],
            "auth_context": "anonymous",
            "source_fact_id": "origin",
        },
    )
    assert surface.status_code == 200
    client = InProcessClient(http_client)
    assert ensure_coverage_work(client, client.get_project(project_id), "reasoner") == 0
    detail = client.get_project(project_id)
    assert detail.surface_inventory[0].planning_status == "assessed"
    assert detail.hypotheses == []
    assert detail.coverage_items == []
    assert detail.intents == []
    completed = client.complete(
        project_id, ["origin"], "no evidence-supported security hypothesis remained", "reasoner"
    )
    assert completed.status_code == 200


def test_target_aware_default_recon_profiles(http_client: TestClient) -> None:
    ip = http_client.post(
        "/projects",
        json={"title": "ip", "origin": "http://192.0.2.10", "goal": "assess", "mode": "real_website"},
    ).json()["project"]
    api = http_client.post(
        "/projects",
        json={"title": "api", "origin": "https://api.example.test", "goal": "assess", "mode": "real_website"},
    ).json()["project"]
    passive = http_client.post(
        "/projects",
        json={
            "title": "passive",
            "origin": "https://example.test",
            "goal": "assess",
            "mode": "real_website",
            "scope_policy": {"passive_only": True},
        },
    ).json()["project"]

    assert ip["recon_profile"]["target_type"] == "ip"
    assert "subdomain" not in ip["recon_profile"]["required_categories"]
    assert api["recon_profile"]["target_type"] == "api"
    assert "subdomain" not in api["recon_profile"]["required_categories"]

    assert passive["recon_profile"]["required_categories"] == []

def test_behavior_clustering_merges_parameters_but_preserves_auth_boundaries() -> None:
    surfaces = [
        {
            "fingerprint": "search-a", "target": "example.test", "port": 443,
            "method": "GET", "path_template": "/search/123", "params": ["q"],
            "auth_context": "anonymous", "source_fact_id": "f001",
        },
        {
            "fingerprint": "search-b", "target": "example.test", "port": 443,
            "method": "GET", "path_template": "/search/456", "params": ["callback_url"],
            "auth_context": "anonymous", "source_fact_id": "f002",
        },
        {
            "fingerprint": "search-session", "target": "example.test", "port": 443,
            "method": "GET", "path_template": "/search/789", "params": ["account_id"],
            "auth_context": "session", "source_fact_id": "f003",
        },
    ]

    clustered = cluster_behaviors(surfaces)

    assert len(clustered) == 2
    anonymous = next(item for item in clustered if item["auth_context"] == "anonymous")
    assert anonymous["params"] == ["callback_url", "q"]
    assert anonymous["evidence_fact_ids"] == ["f001", "f002"]
    candidates = derive_candidates(surfaces)
    anonymous_candidates = [
        item for item in candidates if item.behavior_key == anonymous["behavior_key"]
    ]
    assert len({item.test_variant for item in anonymous_candidates}) == len(anonymous_candidates)
    assert "ssrf" in {item.test_variant for item in anonymous_candidates}


def test_v3_agent_materializes_only_exact_evidence_backed_hypothesis(http_client: TestClient) -> None:
    project_id = _create_real_project(http_client, planning_version=3)
    created_surface = http_client.post(
        f"/projects/{project_id}/surfaces",
        json={
            "fingerprint": "search-route",
            "surface_group": "search",
            "target": "example.test",
            "port": 443,
            "method": "GET",
            "path_template": "/index.php?r=search",
            "params": ["q"],
            "auth_context": "anonymous",
            "source_fact_id": "origin",
        },
    )
    assert created_surface.status_code == 200
    client = InProcessClient(http_client)
    project = client.get_project(project_id)
    assert project.project.planning_version == 3
    behavior_key = behavior_identity(project.surface_inventory[0])[0]
    decision = {
        "from": ["origin"],
        "description": "Check the observed rendered search input for XSS",
        "behavior_key": behavior_key,
        "hypothesis": "The observed q input may reach a rendered response sink.",
        "test_family": "client_side",
        "test_variant": "xss",
        "expected_evidence": ["controlled marker reflection with executable context"],
        "risk_level": "low",
        "confidence": 0.7,
        "impact": 3,
    }

    assert _create_agent_hypothesis_work(client, project, "reasoner", decision) is True
    refreshed = client.get_project(project_id)
    assert len(refreshed.hypotheses) == 1
    assert len(refreshed.coverage_items) == 1
    assert len(refreshed.intents) == 1
    assert refreshed.hypotheses[0].test_variant == "xss"
    assert refreshed.surface_inventory[0].planning_status == "assessed"
    assert _create_agent_hypothesis_work(client, refreshed, "reasoner", decision) is False
    assert len(client.get_project(project_id).hypotheses) == 1
    intent = refreshed.intents[0]
    coverage_id = refreshed.coverage_items[0].id
    claimed = http_client.post(
        f"/projects/{project_id}/intents/{intent.id}/heartbeat", json={"worker": "executor"}
    )
    assert claimed.status_code == 200
    concluded = http_client.post(
        f"/projects/{project_id}/intents/{intent.id}/conclude",
        json={
            "worker": "executor",
            "description": "The test cannot run while the authorized fixture lacks the required role.",
            "status": "blocked_by_precondition",
            "vuln_type": "xss",
            "coverage_refs": [coverage_id],
            "kind": "precondition",
            "summary": "Required role is unavailable",
            "subject": {"behavior_key": behavior_key},
            "data": {"precondition": "authenticated test role"},
            "parent_fact_ids": ["origin"],
            "confidence": 1.0,
        },
    )
    assert concluded.status_code == 200
    assert client.get_project(project_id).hypotheses[0].status == "blocked_by_precondition"


def test_v3_frontier_prunes_stalled_evidence_basis_and_reopens_for_new_fact(
    http_client: TestClient,
) -> None:
    project_id = _create_real_project(http_client, planning_version=3)
    surface_response = http_client.post(
        f"/projects/{project_id}/surfaces",
        json={
            "fingerprint": "search-stall",
            "surface_group": "search",
            "target": "example.test",
            "port": 443,
            "method": "GET",
            "path_template": "/search",
            "params": ["q"],
            "auth_context": "anonymous",
            "source_fact_id": "origin",
            "planning_status": "assessed",
        },
    )
    assert surface_response.status_code == 200
    project = InProcessClient(http_client).get_project(project_id)
    behavior_key = behavior_identity(project.surface_inventory[0])[0]
    for index, variant in enumerate(("xss_reflected", "xss_stored"), start=1):
        response = http_client.post(
            f"/projects/{project_id}/hypotheses",
            json={
                "behavior_key": behavior_key,
                "test_family": "client_side",
                "test_variant": variant,
                "rationale": "No conclusive signal on the current evidence basis.",
                "trigger_fact_ids": ["origin"],
                "confidence": 0.6,
                "impact": 3,
                "goal_value": 1,
                "novelty": 1,
                "estimated_cost": 2,
                "score": 0.9,
                "required": False,
                "status": "inconclusive",
                "basis_fingerprint": f"stalled-{index}",
            },
        )
        assert response.status_code == 201

    candidate = {
        "from": ["origin"],
        "description": "Check one additional reflected rendering variant.",
        "behavior_key": behavior_key,
        "hypothesis": "The query may reach a rendered response sink.",
        "test_family": "client_side",
        "test_variant": "xss_context",
        "expected_evidence": ["controlled marker in an executable context"],
        "risk_level": "medium",
        "confidence": 0.8,
        "impact": 4,
        "estimated_cost": 1,
    }
    stalled = InProcessClient(http_client).get_project(project_id)
    assert _select_v3_frontier(stalled, [candidate], max_items=3) == []

    new_fact = http_client.post(
        f"/projects/{project_id}/facts",
        json={
            "description": "A controlled marker is reflected inside an HTML attribute.",
            "kind": "observation",
            "summary": "New reflected HTML attribute sink",
            "subject": {"behavior_key": behavior_key},
            "data": {"sink": "html_attribute", "marker_reflected": True},
            "parent_fact_ids": ["origin"],
            "confidence": 0.9,
        },
    )
    assert new_fact.status_code == 201
    reopened = InProcessClient(http_client).get_project(project_id)
    selected = _select_v3_frontier(
        reopened,
        [{**candidate, "from": [new_fact.json()["id"]]}],
        max_items=3,
    )
    assert len(selected) == 1


def test_route_selector_values_are_distinct_behaviors() -> None:
    base = {
        "target": "example.test", "port": 443, "method": "GET",
        "params": [], "auth_context": "session", "traits": {},
    }
    manage = behavior_identity({**base, "path_template": "/admin.php?r=manageinfo"})[0]
    create = behavior_identity({**base, "path_template": "/admin.php?r=newwz"})[0]

    assert manage != create
    assert "r=manageinfo" in manage
    assert "r=newwz" in create


def test_destructive_intent_requires_explicit_scope_authorization(http_client: TestClient) -> None:
    project_id = _create_real_project(http_client, planning_version=3)
    response = http_client.post(
        f"/projects/{project_id}/intents",
        json={
            "from": ["origin"],
            "description": "Delete a record",
            "creator": "reasoner",
            "target": "example.test",
            "port": 443,
            "path": "/admin/delete",
            "action_kind": "delete_record",
        },
    )

    assert response.status_code == 400
    assert "destructive" in response.json()["detail"]

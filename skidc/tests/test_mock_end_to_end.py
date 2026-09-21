from __future__ import annotations

import json

from fastapi.testclient import TestClient

from skidc.dispatcher.contracts import extract_reason_handoff, validate_reason_payload
from skidc.dispatcher.models import ReasonCheckpoint
from skidc.dispatcher.prompting import format_coverage_summary
from skidc.dispatcher.tasks.reason import (
    _coverage_from_seed_deck,
    _coverage_key,
    _create_coverage_items,
    ensure_coverage_work,
    _persist_reason_handoff,
    _profile_coverage_from_seed,
)
from tests.conftest import (
    InProcessClient,
    LocalContainerManager,
    create_project,
    dispatch_and_wait,
    make_loop,
    mock_config,
    phase,
)


def test_bootstrap_completes_project_end_to_end(http_client: TestClient) -> None:
    client = InProcessClient(http_client)
    containers = LocalContainerManager()
    loop = make_loop(
        mock_config(
            bootstrap=phase("complete"),
            reason=phase("complete", zero_outcomes=["intent"]),
            explore=phase("fact"),
        ),
        client,
        containers,
    )
    project_id = create_project(http_client)
    try:
        dispatch_and_wait(loop)
        project = client.get_project(project_id)
    finally:
        loop.close()

    assert project.project.status == "completed"
    # bootstrap conclude wrote f001, then completion intent points at goal
    assert [fact.id for fact in project.facts] == ["origin", "goal", "f001"]
    assert [(i.id, i.to) for i in project.intents] == [("i001", "f001"), ("i002", "goal")]


def test_reason_explore_reason_complete_chain(http_client: TestClient) -> None:
    client = InProcessClient(http_client)
    containers = LocalContainerManager()
    loop = make_loop(
        mock_config(
            bootstrap=phase("complete"),
            # propose intents until there are >=3 facts, then declare complete
            reason=phase("intent", rules=[{"fact_ids_gte": 3, "force": "complete"}]),
            explore=phase("fact"),
        ),
        client,
        containers,
    )
    project_id = create_project(http_client)
    # seed one concluded fact so the project is past its initial state
    assert client.create_intent(project_id, ["origin"], "seed", "seed-worker").ok
    assert client.heartbeat(project_id, "i001", "seed-worker").ok
    assert client.conclude(project_id, "i001", "seed-worker", "seed fact").ok

    try:
        dispatch_and_wait(loop)  # reason -> creates intent i002
        assert loop.reason_checkpoints[project_id] == ReasonCheckpoint(3, 0, 1)
        dispatch_and_wait(loop)  # explore i002 -> fact f002
        dispatch_and_wait(loop)  # reason sees 4 facts -> complete
        project = client.get_project(project_id)
    finally:
        loop.close()

    assert project.project.status == "completed"
    assert [fact.id for fact in project.facts] == ["origin", "goal", "f001", "f002"]
    assert [(i.id, i.to) for i in project.intents] == [("i001", "f001"), ("i002", "f002"), ("i003", "goal")]
    # the graph snapshot really was injected into the (mock) container for each phase
    assert any("/reason_execute-" in path and "f002" in content for _, path, content in containers.writes)
    assert any("/explore_execute-" in path and "f001" in content for _, path, content in containers.writes)


def test_reason_can_complete_with_unresolved_coverage_as_a_limitation(http_client: TestClient) -> None:
    client = InProcessClient(http_client)
    containers = LocalContainerManager()
    loop = make_loop(
        mock_config(
            bootstrap=phase("complete"),
            reason=phase("complete"),
            explore=phase("fact"),
        ),
        client,
        containers,
    )
    project_id = create_project(
        http_client, bootstrap_enabled=False, required_recon_categories=[]
    )
    advanced = http_client.post(f"/projects/{project_id}/phase/advance", json={})
    assert advanced.status_code == 200 and advanced.json()["advanced"]
    coverage = http_client.post(
        f"/projects/{project_id}/coverage",
        json={
            "item_type": "admin_route",
            "path": "/admin.php",
            "description": "Admin login has an unresolved advisory coverage entry.",
            "priority": 9,
        },
    )
    assert coverage.status_code == 201

    try:
        dispatch_and_wait(loop)
        project = http_client.get(f"/projects/{project_id}?view=full").json()
    finally:
        loop.close()

    assert project["project"]["status"] == "completed"
    assert project["project"]["run_state"] == "completed"
    assert project["project"]["completion_outcome"] == "complete"
    assert project["project"]["stop_reason_code"] is None
    assert project["project"]["reason_attempt_count"] == 0
    assert project["project"]["reason_last_error"] is None
    assert project["project"]["completion_blockers"] == []
    assert project["coverage_items"][0]["status"] == "untested"


def test_failed_attempt_fact_can_be_followed_by_alternate_work_with_full_trace(
    http_client: TestClient,
) -> None:
    project_id = http_client.post(
        "/projects",
        json={
            "title": "alternate attempt",
            "origin": "http://example.test/login",
            "goal": "verify the authorized login surface",
            "mode": "real_website",
            "recon_profile": {"required_categories": []},
        },
    ).json()["project"]["id"]
    advanced = http_client.post(f"/projects/{project_id}/phase/advance", json={})
    assert advanced.status_code == 200 and advanced.json()["advanced"]
    coverage = http_client.post(
        f"/projects/{project_id}/coverage",
        json={
            "item_type": "vuln_class",
            "description": "Verify login authentication controls.",
            "surface_group": "auth:/login",
            "test_family": "identity_auth",
            "priority": 8,
        },
    ).json()
    first = http_client.post(
        f"/projects/{project_id}/intents",
        json={
            "from": ["origin"],
            "description": "try the first login verification method",
            "creator": "reasoner",
            "priority": 8,
            "coverage_refs": [coverage["id"]],
        },
    ).json()
    http_client.post(
        f"/projects/{project_id}/intents/{first['id']}/heartbeat",
        json={"worker": "worker-1"},
    )
    first_log = http_client.post(
        f"/projects/{project_id}/logs",
        json={
            "task_type": "explore",
            "intent_id": first["id"],
            "worker_name": "worker-1",
            "phase": "explore_execute",
            "stdin": "first verification method",
            "stdout": "",
            "stderr": "timed out",
            "return_code": 124,
            "timed_out": True,
            "duration_ms": 1000,
        },
    ).json()
    dead = http_client.post(
        f"/projects/{project_id}/intents/{first['id']}/failure",
        json={
            "worker": "worker-1",
            "error": "first method timed out",
            "max_attempts": 1,
            "backoff_seconds": 0,
        },
    )
    assert dead.status_code == 200
    assert dead.json()["status"] == "concluded"

    after_failure = http_client.get(f"/projects/{project_id}").json()
    assert after_failure["project"]["status"] == "active"
    assert after_failure["project"]["completion_blockers"] == []
    failed_intent = next(item for item in after_failure["intents"] if item["id"] == first["id"])
    assert failed_intent["status"] == "concluded"
    assert next(fact for fact in after_failure["facts"] if fact["id"] == failed_intent["to"])["status"] == "failed"

    replacement = http_client.post(
        f"/projects/{project_id}/intents",
        json={
            "from": ["origin"],
            "description": "retry login verification with an alternate method",
            "creator": "reasoner",
            "priority": 8,
            "coverage_refs": [coverage["id"]],
        },
    ).json()
    http_client.post(
        f"/projects/{project_id}/intents/{replacement['id']}/heartbeat",
        json={"worker": "worker-2"},
    )
    replacement_log = http_client.post(
        f"/projects/{project_id}/logs",
        json={
            "task_type": "explore",
            "intent_id": replacement["id"],
            "worker_name": "worker-2",
            "phase": "explore_execute",
            "stdin": "alternate verification method",
            "stdout": "control weakness reproduced",
            "stderr": "",
            "return_code": 0,
            "duration_ms": 200,
        },
    ).json()
    fact = http_client.post(
        f"/projects/{project_id}/intents/{replacement['id']}/conclude",
        json={
            "worker": "worker-2",
            "description": "Login authentication weakness was confirmed by the alternate method.",
            "vuln_type": "authentication_bypass",
            "severity": "high",
            "status": "confirmed",
            "coverage_refs": [coverage["id"]],
        },
    ).json()["fact"]

    coverage_after = http_client.get(f"/projects/{project_id}/coverage").json()[0]
    assert coverage_after["intent_ids"] == [first["id"], replacement["id"]]
    assert coverage_after["outcome"] == "vulnerable"
    assert coverage_after["execution_status"] == "completed"
    assert set(coverage_after["task_log_refs"]) == {first_log["id"], replacement_log["id"]}


    verifier = http_client.post(
        f"/projects/{project_id}/intents",
        json={
            "from": [fact["id"]],
            "description": "independently reproduce the confirmed authentication bypass",
            "creator": "reasoner",
            "priority": 9,
            "coverage_refs": [coverage["id"]],
            "test_variant": "authentication_bypass",
        },
    ).json()
    http_client.post(
        f"/projects/{project_id}/intents/{verifier['id']}/heartbeat",
        json={"worker": "worker-3"},
    )
    verifier_log = http_client.post(
        f"/projects/{project_id}/logs",
        json={
            "task_type": "explore",
            "intent_id": verifier["id"],
            "worker_name": "worker-3",
            "phase": "explore_execute",
            "stdin": "independent verification method",
            "stdout": "authentication bypass independently reproduced",
            "stderr": "",
            "return_code": 0,
            "duration_ms": 180,
        },
    ).json()
    verified_fact = http_client.post(
        f"/projects/{project_id}/intents/{verifier['id']}/conclude",
        json={
            "worker": "worker-3",
            "description": "An independent request sequence reproduced the authentication bypass.",
            "vuln_type": "authentication_bypass",
            "severity": "high",
            "status": "verified",
            "verification_of": fact["id"],
            "coverage_refs": [coverage["id"]],
        },
    ).json()["fact"]

    verified_coverage = http_client.get(f"/projects/{project_id}/coverage").json()[0]
    assert verified_coverage["intent_ids"] == [first["id"], replacement["id"], verifier["id"]]
    assert set(verified_coverage["task_log_refs"]) == {
        first_log["id"], replacement_log["id"], verifier_log["id"]
    }
    verified_variant = next(item for item in verified_coverage["variant_results"] if item["variant"] == "authentication_bypass")
    assert verified_variant["verification"] == "verified"

    completed = http_client.post(
        f"/projects/{project_id}/complete",
        json={
            "from": [fact["id"], verified_fact["id"]],
            "description": "all required coverage has a terminal independently verified result",
            "worker": "reasoner",
        },
    )
    assert completed.status_code == 200
    detail = http_client.get(f"/projects/{project_id}").json()
    assert detail["project"]["status"] == "completed"
    assert detail["project"]["completion_blockers"] == []

    report = http_client.get(f"/projects/{project_id}/export?format=report").text
    assert first_log["id"] in report
    assert replacement_log["id"] in report
    assert verifier_log["id"] in report


def test_enabled_project_skips_bootstrap_when_worker_lacks_capability(http_client: TestClient) -> None:
    client = InProcessClient(http_client)
    containers = LocalContainerManager()
    loop = make_loop(
        mock_config(
            bootstrap=phase("complete"),
            reason=phase("complete", zero_outcomes=["intent"]),
            explore=phase("fact"),
            task_types=["reason", "explore"],  # no bootstrap capability
        ),
        client,
        containers,
    )
    project_id = create_project(http_client)
    try:
        dispatch_and_wait(loop)  # should go straight to reason -> complete
        project = client.get_project(project_id)
    finally:
        loop.close()

    assert project.project.status == "completed"
    assert [(i.description, i.to) for i in project.intents] == [("mock complete from origin", "goal")]


def test_explore_conclude_fallback_on_timeout(http_client: TestClient) -> None:
    client = InProcessClient(http_client)
    containers = LocalContainerManager()
    # explore_execute is invalid_json -> forces the two-phase conclude fallback,
    # which (default mock behavior) returns a fact and concludes the intent.
    loop = make_loop(
        mock_config(
            bootstrap=phase("complete"),
            reason=phase("intent"),
            explore=phase("invalid_json", zero_outcomes=["fact"]),
        ),
        client,
        containers,
    )
    project_id = create_project(http_client, bootstrap_enabled=False)
    try:
        dispatch_and_wait(loop)  # reason proposes an intent
        dispatch_and_wait(loop)  # explore execute returns junk -> conclude fallback writes a fact
        project = client.get_project(project_id)
    finally:
        loop.close()

    fact_ids = [f.id for f in project.facts]
    assert "f001" in fact_ids  # the conclude fallback still produced a fact
    assert any("/explore_conclude-" in path for _, path, _ in containers.writes)


def test_reason_handoff_persists_seed_deck_without_using_it_as_a_second_planner(http_client: TestClient) -> None:
    client = InProcessClient(http_client)
    project_id = create_project(http_client, bootstrap_enabled=False)
    payload = {"accepted": True, "data": {
        "recon_complete": True,
        "attack_surface_map": {
            "summary": "Recon found an HTTPS API surface",
            "surfaces": [{"name": "api", "target": "example.test", "port": 443, "surface_type": "web", "evidence": ["origin"]}],
            "admin_routes": ["/admin.php"],
            "upload_points": [{"path": "/upload.php", "description": "Potential file upload endpoint"}],
            "params": [{"path": "/news.php?id=1", "param": "id", "description": "News id parameter"}],
        },
        "explore_seed_deck": {
            "seeds": [
                {
                    "from": ["origin"],
                    "description": "Check API authorization boundaries",
                    "target": "example.test",
                    "port": 443,
                    "surface_type": "web",
                    "action_kind": "authz_probe",
                    "priority": 10,
                    "suggested_tools": ["curl"],
                }
            ],
        },
    }}
    kind, data, _recon_complete = validate_reason_payload(payload, open_intents_empty=True, max_intents=3)

    handoff_fact_ids = _persist_reason_handoff(client, project_id, "reasoner", extract_reason_handoff(payload))
    assert kind == "noop"
    assert data is None

    project = client.get_project(project_id)

    handoff_facts = {fact.goal_type: fact for fact in project.facts if fact.goal_type in {"attack_surface_map", "explore_seed_deck"}}
    assert set(handoff_facts) == {"attack_surface_map", "explore_seed_deck"}
    assert "HTTPS API surface" in handoff_facts["attack_surface_map"].description
    assert project.intents == []

    coverage = {(item.item_type, item.path, item.param): item for item in project.coverage_items}
    assert coverage[("service", None, None)].target == "example.test"
    assert coverage[("service", None, None)].priority == 5
    assert coverage[("admin_route", "/admin.php", None)].priority == 9
    assert coverage[("upload_point", "/upload.php", None)].priority == 10
    assert coverage[("param", "/news.php?id=1", "id")].priority == 7


def test_reason_binds_duplicate_coverage_to_new_intent(http_client: TestClient) -> None:
    client = InProcessClient(http_client)
    project_id = create_project(http_client, bootstrap_enabled=False)
    coverage_payload = {
        "item_type": "admin_route",
        "path": "/admin.php",
        "description": "Admin login panel",
        "priority": 9,
    }
    created_coverage = client.create_coverage_item(project_id, **coverage_payload)
    assert created_coverage.ok
    coverage_id = created_coverage.data["id"]
    created_intent = client.create_intent(
        project_id,
        ["origin"],
        "verify admin login",
        "reasoner",
    )
    assert created_intent.ok
    intent_id = created_intent.data["id"]

    _create_coverage_items(
        client,
        project_id,
        "reasoner",
        [{**coverage_payload, "intent_id": intent_id}],
        {_coverage_key(coverage_payload): coverage_id},
    )

    project = client.get_project(project_id)
    assert len(project.coverage_items) == 1
    assert project.coverage_items[0].intent_ids == [intent_id]
    assert project.intents[0].coverage_refs == [coverage_id]


def test_explore_handoff_does_not_expand_coverage_or_handoff_facts(http_client: TestClient) -> None:
    client = InProcessClient(http_client)
    project_id = create_project(http_client, bootstrap_enabled=False)
    handoff = {
        "attack_surface_map": {
            "routes": [{"url": "http://example.test/admin.php", "params": ["id"]}],
        },
        "explore_seed_deck": [
            {"from": ["origin"], "description": "duplicate explore handoff"},
        ],
    }

    result = _persist_reason_handoff(
        client,
        project_id,
        "reasoner",
        handoff,
        {},
        real_website=True,
        materialize_coverage=False,
    )
    project = client.get_project(project_id)

    assert result == {}
    assert [fact.id for fact in project.facts] == ["origin", "goal"]
    assert project.coverage_items == []
    assert project.surface_inventory == []

def test_real_website_handoff_builds_medium_grain_coverage_profile(http_client: TestClient) -> None:
    client = InProcessClient(http_client)
    project_id = create_project(http_client, bootstrap_enabled=False)
    handoff = {
        "attack_surface_map": {
            "routes": [
                {"url": "http://al.xhcms/xhcms/index.php?id=1"},
                {"url": "http://al.xhcms/xhcms/admin/login.php", "method": "POST", "params": ["username", "password"]},
            ],
            "forms": [
                {"url": "http://al.xhcms/xhcms/contact.php", "method": "POST", "fields": ["name", "mail", "message"]},
            ],
            "upload_points": [
                {"url": "http://al.xhcms/xhcms/admin/upload.php", "method": "POST", "params": ["file"]},
            ],
            "services": [{"target": "al.xhcms", "port": 3306, "type": "database"}],
        },
        "explore_seed_deck": [],
    }
    coverage_index: dict[tuple, str] = {}

    _persist_reason_handoff(
        client,
        project_id,
        "reasoner",
        handoff,
        coverage_index,
        real_website=True,
        support_ports=[3306],
    )
    first = client.get_project(project_id)
    _persist_reason_handoff(
        client,
        project_id,
        "reasoner",
        handoff,
        coverage_index,
        real_website=True,
        support_ports=[3306],
    )
    second = client.get_project(project_id)

    assert len(first.surface_inventory) == 5
    assert 15 <= len(first.coverage_items) <= 35
    config_items = [item for item in first.coverage_items if item.test_family == "surface_config"]
    assert len(config_items) == 4
    assert config_items[0].required is False
    assert len(second.surface_inventory) == len(first.surface_inventory)
    assert len(second.coverage_items) == len(first.coverage_items)
    families = {item.test_family for item in first.coverage_items}
    assert {"surface_config", "identity_auth", "injection", "file_path", "client_side", "support_service"} <= families
    assert "crypto_transport" not in families
    support = [item for item in first.coverage_items if item.test_family == "support_service"]
    assert len(support) == 1
    assert support[0].required is False
    assert support[0].port == 3306
    assert any(item.test_family == "file_path" and item.priority == 10 for item in first.coverage_items)
    summary = json.loads(format_coverage_summary(first))
    assert len(summary["top_unresolved"]) <= 10
    assert "support_service" in summary["by_test_family"]

    intent = client.create_intent(
        project_id,
        ["origin"],
        "Test authentication bypass and SQL injection on the admin login.",
        "reasoner",
        target="al.xhcms",
        port=80,
        surface_type="form",
        action_kind="auth and sqli probe",
    ).data
    assert isinstance(intent, dict)
    seed_items = _profile_coverage_from_seed(
        client,
        project_id,
        {
            "description": "Test authentication bypass and SQL injection on the admin login.",
            "target": "al.xhcms",
            "port": 80,
            "path": "/xhcms/admin/login.php",
            "method": "POST",
            "params": ["username", "password"],
            "surface_type": "form",
            "action_kind": "auth and sqli probe",
        },
        support_ports=[3306],
        source_fact_id=None,
        intent_id=intent["id"],
    )
    _create_coverage_items(client, project_id, "reasoner", seed_items, coverage_index)
    refreshed = client.get_project(project_id)
    bound_families = {
        item.test_family for item in refreshed.coverage_items if intent["id"] in item.intent_ids
    }
    assert bound_families == {"identity_auth"}


def test_v2_does_not_expand_manual_coverage_variants(http_client: TestClient) -> None:
    client = InProcessClient(http_client)
    response = http_client.post(
        "/projects",
        json={
            "title": "finite baseline",
            "origin": "https://example.test/",
            "goal": "assess",
            "mode": "real_website",
        },
    )
    project_id = response.json()["project"]["id"]
    coverage = http_client.post(
        f"/projects/{project_id}/coverage",
        json={
            "item_type": "vuln_class",
            "target": "example.test",
            "port": 443,
            "method": "GET",
            "path": "/search",
            "description": "Search input checks",
            "surface_group": "web:/search",
            "test_family": "injection",
            "test_variants": ["sql", "command"],
            "priority": 7,
            "execution_status": "completed",
            "outcome": "vulnerable",
        },
    ).json()

    before = client.get_project(project_id)
    variants = {item.variant: item.status for item in before.coverage_items[0].variant_results}
    assert variants == {"sql": "untested", "command": "untested"}

    assert ensure_coverage_work(client, before, "reasoner") == 0
    after = client.get_project(project_id)
    assert after.intents == []
    assert after.coverage_items[0].id == coverage["id"]
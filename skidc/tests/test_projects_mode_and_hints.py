from __future__ import annotations

from fastapi.testclient import TestClient

from skidc.dispatcher.prompting import format_scope_constraints
from skidc.dispatcher.scheduler.loop import DispatcherLoop
from skidc.server.models import ProjectDetail


def test_create_project_persists_mode_scope_policy_and_recon_profile(http_client: TestClient) -> None:
    response = http_client.post(
        "/projects",
        json={
            "title": "real target",
            "origin": "https://example.test",
            "goal": "authorized assessment",
            "mode": "real_website",
            "bootstrap_enabled": False,
            "scope_policy": {
                "allowed_targets": ["example.test"],
                "blocked_targets": ["admin.other.test"],
                "allowed_ports": [80, 443],
                "blocked_ports": [22],
                "allowed_paths": ["/app/"],
                "blocked_paths": ["/private/"],
                "support_ports": [3306],
                "allow_subdomains": False,
                "allow_domain_scan": False,
                "rate_limits": {"requests_per_second": 2},
                "passive_only": False,
            },
            "recon_profile": {
                "target_type": "domain",
                "required_categories": ["port_scan", "subdomain", "directory", "asset"],
                "optional_categories": [],
                "disabled_categories": [],
            },
        },
    )

    assert response.status_code == 201
    project = response.json()["project"]
    assert project["mode"] == "real_website"
    assert project["phase"] == "recon"
    assert project["scope_policy"]["blocked_ports"] == [22]
    assert project["scope_policy"]["allowed_paths"] == ["/app/"]
    assert project["scope_policy"]["support_ports"] == [3306]
    assert project["scope_policy"]["allow_subdomains"] is False
    assert project["scope_policy"]["allow_domain_scan"] is False
    assert project["recon_profile"]["target_type"] == "domain"

    detail = http_client.get(f"/projects/{project['id']}").json()["project"]
    assert detail["mode"] == "real_website"
    assert detail["scope_policy"]["allowed_targets"] == ["example.test"]
    assert detail["scope_policy"]["blocked_paths"] == ["/private/"]
    assert detail["recon_profile"]["required_categories"] == ["port_scan", "subdomain", "directory", "asset"]


def test_mode_roundtrip_uses_canonical_mode_field(http_client: TestClient) -> None:
    project_id = http_client.post(
        "/projects",
        json={"title": "t", "origin": "o", "goal": "g"},
    ).json()["project"]["id"]

    response = http_client.put(f"/projects/{project_id}/mode", json={"mode": "real_website"})

    assert response.status_code == 200
    assert response.json()["mode"] == "real_website"
    assert response.json()["phase"] == "recon"
    detail = http_client.get(f"/projects/{project_id}").json()["project"]
    assert detail["mode"] == "real_website"


def test_export_includes_phase_mode_scope_and_fact_status(http_client: TestClient) -> None:
    project_id = http_client.post(
        "/projects",
        json={
            "title": "t",
            "origin": "https://example.test",
            "goal": "g",
            "mode": "real_website",
            "bootstrap_enabled": False,
            "scope_policy": {"blocked_ports": [3306]},
            "recon_profile": {"target_type": "domain", "required_categories": ["port_scan"]},
        },
    ).json()["project"]["id"]
    fact_response = http_client.post(
        f"/projects/{project_id}/facts",
        json={
            "description": "candidate target",
            "goal_type": "potential_target",
            "status": "pending",
            "recon_category": "port_scan",
            "recon_executed": True,
            "recon_found_results": True,
        },
    )
    assert fact_response.status_code == 201

    yaml_text = http_client.get(f"/projects/{project_id}/export?format=yaml").text

    assert "mode: real_website" in yaml_text
    assert "phase: recon" in yaml_text
    assert "scope_policy:" in yaml_text
    assert "blocked_ports:" in yaml_text
    assert "goal_type: potential_target" in yaml_text
    assert "status: pending" in yaml_text
    assert "recon_category: port_scan" in yaml_text


def test_intent_metadata_roundtrip_for_scope_enforcement(http_client: TestClient) -> None:
    project_id = http_client.post(
        "/projects",
        json={"title": "t", "origin": "https://example.test", "goal": "g", "bootstrap_enabled": False},
    ).json()["project"]["id"]

    response = http_client.post(
        f"/projects/{project_id}/intents",
        json={
            "from": ["origin"],
            "description": "probe HTTPS login flow",
            "creator": "reasoner",
            "target": "example.test",
            "port": 443,
            "surface_type": "web",
            "action_kind": "http_probe",
            "priority": 10,
            "suggested_tools": ["curl"],
        },
    )

    assert response.status_code == 201
    intent = response.json()
    assert intent["target"] == "example.test"
    assert intent["port"] == 443
    assert intent["surface_type"] == "web"
    assert intent["action_kind"] == "http_probe"
    assert intent["priority"] == 10
    assert intent["suggested_tools"] == ["curl"]

    detail_intent = http_client.get(f"/projects/{project_id}").json()["intents"][0]
    assert detail_intent["target"] == "example.test"


def test_scope_policy_rejects_structured_out_of_scope_intents(http_client: TestClient) -> None:
    project_id = http_client.post(
        "/projects",
        json={
            "title": "bounded target",
            "origin": "http://127.0.0.1:8080",
            "goal": "authorized local assessment",
            "mode": "real_website",
            "bootstrap_enabled": False,
            "scope_policy": {
                "allowed_targets": ["127.0.0.1"],
                "blocked_targets": ["127.0.0.2"],
                "allowed_ports": [8080],
                "blocked_ports": [3306],
                "allowed_paths": ["/xhcms/"],
                "blocked_paths": ["/xhcms/private/"],
                "support_ports": [3307],
                "allow_subdomains": False,
                "allow_domain_scan": False,
                "passive_only": True,
            },
        },
    ).json()["project"]["id"]

    allowed = http_client.post(
        f"/projects/{project_id}/intents",
        json={
            "from": ["origin"],
            "description": "probe the authorized local web service",
            "creator": "reasoner",
            "target": "http://127.0.0.1:8080/xhcms/",
            "port": 8080,
            "action_kind": "http_probe",
        },
    )
    blocked_target = http_client.post(
        f"/projects/{project_id}/intents",
        json={
            "from": ["origin"],
            "description": "probe another local service",
            "creator": "reasoner",
            "target": "127.0.0.2",
            "port": 8080,
            "action_kind": "http_probe",
        },
    )
    blocked_port = http_client.post(
        f"/projects/{project_id}/intents",
        json={
            "from": ["origin"],
            "description": "probe blocked database port",
            "creator": "reasoner",
            "target": "127.0.0.1",
            "port": 3306,
            "action_kind": "http_probe",
        },
    )
    blocked_path = http_client.post(
        f"/projects/{project_id}/intents",
        json={
            "from": ["origin"],
            "description": "probe out-of-app path",
            "creator": "reasoner",
            "target": "127.0.0.1",
            "port": 8080,
            "path": "/admin/",
            "action_kind": "http_probe",
        },
    )
    blocked_domain_scan = http_client.post(
        f"/projects/{project_id}/intents",
        json={
            "from": ["origin"],
            "description": "enumerate subdomains",
            "creator": "reasoner",
            "target": "127.0.0.1",
            "port": 8080,
            "action_kind": "subdomain_scan",
        },
    )
    active_action = http_client.post(
        f"/projects/{project_id}/intents",
        json={
            "from": ["origin"],
            "description": "try an active exploit",
            "creator": "reasoner",
            "target": "127.0.0.1",
            "port": 8080,
            "action_kind": "exploit_check",
        },
    )

    assert allowed.status_code == 201
    assert blocked_target.status_code == 400
    assert "target" in blocked_target.json()["detail"]
    assert blocked_port.status_code == 400
    assert "port 3306" in blocked_port.json()["detail"]
    assert blocked_path.status_code == 400
    assert "allowed_paths" in blocked_path.json()["detail"]
    assert blocked_domain_scan.status_code == 400
    assert "domain/subdomain" in blocked_domain_scan.json()["detail"]
    assert active_action.status_code == 400
    assert "passive_only" in active_action.json()["detail"]


def test_support_ports_do_not_become_the_only_allowed_ports(http_client: TestClient) -> None:
    project_id = http_client.post(
        "/projects",
        json={
            "title": "web with database",
            "origin": "http://al.xhcms/xhcms/",
            "goal": "authorized assessment",
            "mode": "real_website",
            "bootstrap_enabled": False,
            "scope_policy": {
                "allowed_targets": ["al.xhcms"],
                "support_ports": [3306],
            },
        },
    ).json()["project"]["id"]

    web_probe = http_client.post(
        f"/projects/{project_id}/intents",
        json={
            "from": ["origin"],
            "description": "probe web app",
            "creator": "reasoner",
            "target": "al.xhcms",
            "port": 80,
            "action_kind": "http_probe",
        },
    )
    db_active = http_client.post(
        f"/projects/{project_id}/intents",
        json={
            "from": ["origin"],
            "description": "try database login",
            "creator": "reasoner",
            "target": "al.xhcms",
            "port": 3306,
            "action_kind": "login_probe",
        },
    )

    assert web_probe.status_code == 201
    assert db_active.status_code == 400
    assert "support service port" in db_active.json()["detail"]


def test_scope_policy_is_visible_in_prompt_context(http_client: TestClient) -> None:
    project = http_client.post(
        "/projects",
        json={
            "title": "bounded prompt",
            "origin": "https://example.test",
            "goal": "authorized assessment",
            "mode": "real_website",
            "bootstrap_enabled": False,
            "scope_policy": {
                "allowed_targets": ["example.test"],
                "allowed_ports": [443],
                "allowed_paths": ["/xhcms/"],
                "support_ports": [3306],
                "allow_subdomains": False,
                "allow_domain_scan": False,
                "blocked_ports": [22],
                "rate_limits": {"requests_per_second": 2},
            },
            "recon_profile": {
                "target_type": "domain",
                "required_categories": ["port_scan"],
                "disabled_categories": ["subdomain"],
            },
            "hints": [{"content": "Do not scan admin.other.test", "creator": "operator"}],
        },
    ).json()
    detail = ProjectDetail.model_validate(http_client.get(f"/projects/{project['project']['id']}").json())

    context = format_scope_constraints(detail)

    assert '"allowed_targets": [' in context
    assert '"example.test"' in context
    assert '"allowed_ports": [' in context
    assert "443" in context
    assert '"allowed_paths": [' in context
    assert '"/xhcms/"' in context
    assert '"support_ports": [' in context
    assert "3306" in context
    assert '"allow_subdomains": false' in context
    assert '"allow_domain_scan": false' in context
    assert '"disabled_categories": [' in context
    assert '"subdomain"' in context
    assert "Do not scan admin.other.test" in context


def test_dispatcher_skips_historical_out_of_scope_intents() -> None:
    project = ProjectDetail.model_validate(
        {
            "project": {
                "id": "proj_001",
                "title": "bounded dispatch",
                "status": "active",
                "bootstrap_enabled": False,
                "phase": "recon",
                "mode": "real_website",
                "scope_policy": {
                    "allowed_targets": ["127.0.0.1"],
                    "allowed_ports": [8080],
                    "blocked_ports": [3306],
                },
                "created_at": "2026-07-12T00:00:00Z",
            },
            "facts": [],
            "intents": [
                {
                    "id": "i001",
                    "from": ["origin"],
                    "to": None,
                    "description": "allowed local web probe",
                    "creator": "reasoner",
                    "worker": None,
                    "created_at": "2026-07-12T00:00:01Z",
                    "target": "127.0.0.1",
                    "port": 8080,
                    "action_kind": "http_probe",
                },
                {
                    "id": "i002",
                    "from": ["origin"],
                    "to": None,
                    "description": "legacy blocked database probe",
                    "creator": "reasoner",
                    "worker": None,
                    "created_at": "2026-07-12T00:00:02Z",
                    "target": "127.0.0.1",
                    "port": 3306,
                    "action_kind": "http_probe",
                },
            ],
            "hints": [],
            "attack_paths": [],
        }
    )
    loop = DispatcherLoop.__new__(DispatcherLoop)

    allowed = loop._scope_allowed_intents(project, project.intents)

    assert [intent.id for intent in allowed] == ["i001"]

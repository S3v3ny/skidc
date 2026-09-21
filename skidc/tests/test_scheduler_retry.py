from __future__ import annotations

from fastapi.testclient import TestClient

import skidc.dispatcher.scheduler.loop as scheduler_loop
from skidc.dispatcher.models import ReasonCheckpoint
from tests.conftest import (
    InProcessClient,
    LocalContainerManager,
    create_project,
    dispatch_and_wait,
    make_loop,
    mock_config,
    phase,
)


def _run_dispatch_cycle(loop) -> None:
    loop._reap_futures()
    summaries = loop.client.list_projects()
    loop._initialize_reason_checkpoints(summaries)
    loop._refresh_runtime_projects(summaries)
    loop._cancel_inactive_tasks(summaries)
    loop._queue_container_cleanups(summaries)
    loop._dispatch_available(summaries)
    for future in list(loop.futures):
        future.result(timeout=10)
    loop._reap_futures()


def test_intents_expose_retry_and_dead_letter_state(http_client: TestClient) -> None:
    project_id = http_client.post(
        "/projects",
        json={"title": "t", "origin": "o", "goal": "g"},
    ).json()["project"]["id"]

    response = http_client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "probe", "creator": "reasoner"},
    )

    assert response.status_code == 201
    intent = response.json()
    assert intent["status"] == "open"
    assert intent["attempt_count"] == 0
    assert intent["last_error"] is None
    assert intent["next_retry_at"] is None
    assert intent["dead_lettered_at"] is None


def test_intent_failure_records_retry_then_result_fact(http_client: TestClient) -> None:
    project_id = http_client.post(
        "/projects",
        json={"title": "t", "origin": "o", "goal": "g"},
    ).json()["project"]["id"]
    intent_id = http_client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "probe", "creator": "reasoner"},
    ).json()["id"]

    first = http_client.post(
        f"/projects/{project_id}/intents/{intent_id}/failure",
        json={"worker": "w1", "error": "invalid_json", "max_attempts": 3, "backoff_seconds": 30},
    )
    second = http_client.post(
        f"/projects/{project_id}/intents/{intent_id}/failure",
        json={"worker": "w1", "error": "invalid_json", "max_attempts": 3, "backoff_seconds": 0},
    )
    third = http_client.post(
        f"/projects/{project_id}/intents/{intent_id}/failure",
        json={"worker": "w1", "error": "invalid_json", "max_attempts": 3, "backoff_seconds": 0},
    )

    assert first.status_code == 200
    assert first.json()["attempt_count"] == 1
    assert first.json()["status"] == "open"
    assert first.json()["next_retry_at"]
    assert first.json()["last_worker"] == "w1"
    assert second.status_code == 200
    assert second.json()["attempt_count"] == 2
    assert second.json()["status"] == "open"
    assert third.status_code == 200
    assert third.json()["attempt_count"] == 3
    assert third.json()["status"] == "concluded"
    assert third.json()["execution_status"] == "failed"
    assert third.json()["to"] is not None
    assert http_client.get(f"/projects/{project_id}").json()["facts"][-1]["status"] == "failed"
    assert third.json()["dead_lettered_at"]
    assert third.json()["next_retry_at"] is None


def test_conclusion_failure_also_produces_result_fact(http_client: TestClient) -> None:
    project_id = http_client.post(
        "/projects", json={"title": "t", "origin": "o", "goal": "g"},
    ).json()["project"]["id"]
    intent = http_client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "probe", "creator": "reasoner"},
    ).json()
    http_client.post(
        f"/projects/{project_id}/intents/{intent['id']}/heartbeat",
        json={"worker": "w1"},
    )
    task_log = http_client.post(
        f"/projects/{project_id}/logs",
        json={
            "task_type": "explore",
            "intent_id": intent["id"],
            "worker_name": "w1",
            "phase": "explore_execute",
            "stdin": "probe",
            "stdout": "unparseable result",
            "stderr": "",
            "return_code": 0,
            "duration_ms": 10,
        },
    ).json()
    executed = http_client.post(
        f"/projects/{project_id}/intents/{intent['id']}/execution-success",
        json={"worker": "w1", "task_log_id": task_log["id"]},
    )
    assert executed.status_code == 200

    result = None
    for _ in range(3):
        result = http_client.post(
            f"/projects/{project_id}/intents/{intent['id']}/conclusion-failure",
            json={"worker": "w1", "error": "invalid conclusion JSON"},
        )
        assert result.status_code == 200
    assert result is not None
    terminal = result.json()
    assert terminal["status"] == "concluded"
    assert terminal["execution_status"] == "succeeded"
    assert terminal["to"] is not None

    detail = http_client.get(f"/projects/{project_id}").json()
    fact = next(item for item in detail["facts"] if item["id"] == terminal["to"])
    assert fact["kind"] == "execution_result"
    assert fact["status"] == "failed"
    assert fact["data"]["failure_stage"] == "conclusion_failed"
    assert fact["task_log_refs"] == [task_log["id"]]


def test_intent_failure_updates_bound_coverage_lifecycle(http_client: TestClient) -> None:
    project_id = http_client.post(
        "/projects",
        json={"title": "t", "origin": "o", "goal": "g", "mode": "real_website"},
    ).json()["project"]["id"]
    coverage_id = http_client.post(
        f"/projects/{project_id}/coverage",
        json={
            "item_type": "vuln_class",
            "description": "Test login authentication behavior.",
            "test_family": "identity_auth",
            "surface_group": "auth:/login",
            "priority": 8,
        },
    ).json()["id"]
    intent_id = http_client.post(
        f"/projects/{project_id}/intents",
        json={
            "from": ["origin"],
            "description": "Test login.",
            "creator": "reasoner",
            "coverage_refs": [coverage_id],
        },
    ).json()["id"]

    http_client.post(
        f"/projects/{project_id}/intents/{intent_id}/heartbeat",
        json={"worker": "w1"},
    )
    retry = http_client.post(
        f"/projects/{project_id}/intents/{intent_id}/failure",
        json={"worker": "w1", "error": "timeout", "max_attempts": 2, "backoff_seconds": 0},
    )
    assert retry.status_code == 200
    queued = http_client.get(f"/projects/{project_id}/coverage").json()[0]
    assert queued["execution_status"] == "queued"
    assert queued["outcome"] is None

    dead = http_client.post(
        f"/projects/{project_id}/intents/{intent_id}/failure",
        json={"worker": "w1", "error": "timeout", "max_attempts": 2, "backoff_seconds": 0},
    )
    assert dead.status_code == 200
    inconclusive = http_client.get(f"/projects/{project_id}/coverage").json()[0]
    assert inconclusive["execution_status"] == "completed"
    assert inconclusive["outcome"] == "inconclusive"
    assert inconclusive["status"] == "inconclusive"

    replacement = http_client.post(
        f"/projects/{project_id}/intents",
        json={
            "from": ["origin"],
            "description": "Retry login with an alternate method.",
            "creator": "reasoner",
            "coverage_refs": [coverage_id],
        },
    )
    assert replacement.status_code == 201
    requeued = http_client.get(f"/projects/{project_id}/coverage").json()[0]
    assert requeued["execution_status"] == "queued"
    assert requeued["status"] == "untested"


def test_scheduler_skips_intents_until_next_retry_at(http_client: TestClient) -> None:
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
    project_id = create_project(http_client, bootstrap_enabled=False)
    try:
        intent = client.create_intent(project_id, ["origin"], "delayed probe", "test").data
        assert isinstance(intent, dict)
        assert client.record_intent_failure(
            project_id,
            intent["id"],
            "test-worker",
            "transient failure",
            max_attempts=3,
            backoff_seconds=60,
        ).ok
        loop.reason_checkpoints[project_id] = ReasonCheckpoint(fact_count=2, hint_count=0, open_intent_count=1)

        _run_dispatch_cycle(loop)

        assert not loop.futures
        delayed = http_client.get(f"/projects/{project_id}").json()["intents"][0]
        assert delayed["status"] == "open"
        assert delayed["attempt_count"] == 1
        assert delayed["next_retry_at"]
        assert delayed["to"] is None
    finally:
        loop.close()


def test_failed_result_fact_does_not_block_other_explore_paths(http_client: TestClient) -> None:
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
    try:
        dead = client.create_intent(project_id, ["origin"], "failing direction", "test").data
        live = client.create_intent(project_id, ["origin"], "alternative direction", "test").data
        assert isinstance(dead, dict)
        assert isinstance(live, dict)
        assert client.record_intent_failure(
            project_id,
            dead["id"],
            "test-worker",
            "repeated failure",
            max_attempts=1,
            backoff_seconds=0,
        ).ok
        loop.reason_checkpoints[project_id] = ReasonCheckpoint(fact_count=2, hint_count=0, open_intent_count=2)

        _run_dispatch_cycle(loop)
        _run_dispatch_cycle(loop)  # terminal failure + successful alternate path can now be summarized

        project = http_client.get(f"/projects/{project_id}").json()
        intents = {intent["id"]: intent for intent in project["intents"]}
        assert intents[dead["id"]]["status"] == "concluded"
        assert intents[dead["id"]]["to"] is not None
        assert next(fact for fact in project["facts"] if fact["id"] == intents[dead["id"]]["to"])["status"] == "failed"
        assert intents[live["id"]]["status"] == "concluded"
        assert intents[live["id"]]["to"] is not None
        assert project["project"]["status"] == "completed"
    finally:
        loop.close()


def test_bootstrap_failure_is_terminal_and_project_can_complete(http_client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(scheduler_loop, "RETRY_BACKOFF_SECONDS", (0, 0, 0))
    client = InProcessClient(http_client)
    containers = LocalContainerManager()
    loop = make_loop(
        mock_config(
            bootstrap=phase("command_fail"),
            reason=phase("complete"),
            explore=phase("fact"),
        ),
        client,
        containers,
    )
    project_id = create_project(http_client, bootstrap_enabled=True)
    try:
        for _ in range(4):
            _run_dispatch_cycle(loop)

        project = http_client.get(f"/projects/{project_id}").json()
    finally:
        loop.close()

    bootstrap_intents = [
        intent for intent in project["intents"]
        if intent["description"] == "bootstrap"
    ]
    assert len(bootstrap_intents) == 1
    assert bootstrap_intents[0]["status"] == "concluded"
    assert bootstrap_intents[0]["to"] is not None
    assert project["project"]["status"] == "completed"

def test_explore_failure_produces_result_after_repeated_attempts(http_client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(scheduler_loop, "RETRY_BACKOFF_SECONDS", (0, 0, 0))
    client = InProcessClient(http_client)
    containers = LocalContainerManager()
    loop = make_loop(
        mock_config(
            bootstrap=phase("complete"),
            reason=phase("complete"),
            explore=phase("command_fail"),
        ),
        client,
        containers,
    )
    project_id = create_project(
        http_client, bootstrap_enabled=False, required_recon_categories=[]
    )
    advanced = http_client.post(f"/projects/{project_id}/phase/advance", json={})
    assert advanced.status_code == 200 and advanced.json()["advanced"]
    try:
        assert client.create_intent(project_id, ["origin"], "deterministic failing probe", "test").ok
        loop.reason_checkpoints[project_id] = ReasonCheckpoint(fact_count=2, hint_count=0, open_intent_count=1)

        for _ in range(4):
            _run_dispatch_cycle(loop)

        project = http_client.get(f"/projects/{project_id}").json()
    finally:
        loop.close()

    intent = project["intents"][0]
    assert intent["status"] == "concluded"
    assert intent["execution_status"] == "failed"
    assert next(fact for fact in project["facts"] if fact["id"] == intent["to"])["status"] == "failed"
    assert intent["attempt_count"] >= 3
    assert intent["last_error"]
    assert intent["dead_lettered_at"]
    assert project["project"]["status"] == "completed"


def test_reason_failures_are_visible_on_project(http_client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(scheduler_loop, "RETRY_BACKOFF_SECONDS", (0, 0, 0))
    client = InProcessClient(http_client)
    containers = LocalContainerManager()
    loop = make_loop(
        mock_config(
            bootstrap=phase("complete"),
            reason=phase("invalid_json"),
            explore=phase("fact"),
        ),
        client,
        containers,
    )
    project_id = create_project(http_client, bootstrap_enabled=False)
    try:
        for _ in range(3):
            dispatch_and_wait(loop)

        project = http_client.get(f"/projects/{project_id}").json()["project"]
    finally:
        loop.close()

    assert project["status"] == "stopped"
    assert project["run_state"] == "needs_attention"
    assert project["completion_outcome"] == "needs_attention"
    assert project["stop_reason_code"] == "reason_retry_exhausted"
    assert project["reason_attempt_count"] == 3
    assert project["reason_dead_lettered_at"] is not None
    assert project["reason_next_retry_at"] is None
    report = http_client.get(f"/projects/{project_id}/export?format=report").text
    assert "reason_retry_exhausted" in report


def test_reason_complete_finishes_terminal_explore_project(http_client: TestClient) -> None:
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
    try:
        dispatch_and_wait(loop)
        project = client.get_project(project_id)
    finally:
        loop.close()

    assert project.project.status == "completed"
    assert all(intent.status == "concluded" for intent in project.intents)
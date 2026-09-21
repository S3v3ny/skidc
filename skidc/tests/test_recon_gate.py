"""Regression tests for recon-gate defects in real-website mode.

Defect 1 — Scheduler ordering deadlock (sked-deadlock-001):
  _try_dispatch_project() returns early on recon gate failure *before*
  checking for existing unclaimed explore intents.  When the gate blocks
  reason re-dispatch, it also blocks explore dispatch for intents that are
  already waiting.

Defect 2 — Keyword-only gate fragility (kw-gate-001):
  check_recon_executed() classifies facts purely by substring keywords in
  their descriptions.  The desired behavior is structured metadata first
  (recon_category + recon_executed), with keyword matching kept only as a
  compatibility fallback for old facts.

Defect 3 — Hard-coded category profile (profile-gate-001):
  check_recon_executed() always requires port_scan, subdomain, directory, and
  asset.  The desired behavior is profile-aware: IP, API, Android, and mixed
  targets must be able to define required/optional/disabled categories.

All regression tests assert the CORRECT (post-fix) behavior.  They should
FAIL on current code because the defects prevent that behavior.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from skidc.dispatcher.recon_extractor import check_recon_executed
from skidc.dispatcher.scheduler.loop import DispatcherLoop
from skidc.server.models import Fact
from tests.conftest import (
    InProcessClient,
    LocalContainerManager,
    create_project,
    dispatch_and_wait,
    make_loop,
    mock_config,
    phase,
)


# ---------------------------------------------------------------------------
# Helper — dispatch cycle without the futures assertion
# ---------------------------------------------------------------------------


def _run_one_dispatch_cycle(loop: DispatcherLoop) -> None:
    """Run a single dispatch cycle WITHOUT asserting that futures exist.

    ``dispatch_and_wait()`` asserts ``loop.futures`` is non-empty, which
    makes it impossible to observe the deadlock where nothing is dispatched.
    This helper does the bookkeeping minus that assertion.
    """
    loop._reap_futures()
    summaries = loop.client.list_projects()
    loop._initialize_reason_checkpoints(summaries)
    loop._refresh_runtime_projects(summaries)
    loop._cancel_inactive_tasks(summaries)
    loop._queue_container_cleanups(summaries)
    loop._dispatch_available(summaries)


# ---------------------------------------------------------------------------
# Defect 1 — scheduler ordering deadlock
# ---------------------------------------------------------------------------


def test_recon_gate_allows_dispatch_of_unclaimed_explore_intents(
    http_client: TestClient,
) -> None:
    """Unclaimed explore intents MUST be dispatched even when the recon gate
    blocks reason re-dispatch.

    Setup:
      1. Create project with bootstrap_enabled=False → phase='recon'
      2. Reason runs (initial), creates explore intent i002
      3. Explore consumes i002, produces fact f001
      4. Seed extra unclaimed intent + new fact so that _reason_trigger
         fires AND unclaimed intents exist simultaneously.

    Post-fix behavior:
      The dispatcher should dispatch the unclaimed intent even though the
      recon gate blocks reason.

    Current (buggy) behavior:
      _try_dispatch_project returns False at the recon-gate check (line 192)
      before reaching the unclaimed-intents branch.  The intent is stranded.
    """
    client = InProcessClient(http_client)
    containers = LocalContainerManager()
    loop = make_loop(
        mock_config(
            bootstrap=phase("complete"),
            reason=phase("intent"),
            explore=phase("fact"),
        ),
        client,
        containers,
    )
    project_id = create_project(http_client, bootstrap_enabled=False)
    try:
        # 1) Initial reason dispatch — creates explore intent i002
        dispatch_and_wait(loop)

        # 2) Explore dispatch — i002 produces fact f001
        dispatch_and_wait(loop)

        # 3) Seed extra unclaimed intent + new fact.
        client.create_intent(project_id, ["origin"], "extra explore task", "test")
        client.create_fact_direct(project_id, "additional recon progress")

        # Preconditions
        project = client.get_project(project_id)
        unclaimed = [i for i in project.intents if i.to is None and i.worker is None]
        assert len(unclaimed) >= 1, "precondition: should have unclaimed intents"
        trigger = loop._reason_trigger(project)
        assert trigger is not None, "precondition: reason should be triggered"

        # 4) Attempt dispatch — post-fix should dispatch the unclaimed intent
        _run_one_dispatch_cycle(loop)

        # POST-FIX: the dispatcher should have dispatched the unclaimed intent
        assert loop.futures, (
            "dispatcher should dispatch unclaimed explore intents even when "
            f"recon gate blocks reason (trigger={trigger!r})"
        )
    finally:
        loop.close()


def test_recon_gate_allows_reason_to_plan_remaining_work(
    http_client: TestClient,
) -> None:
    """After partial recon facts arrive, reason MUST be re-triggered to plan
    the remaining recon work, even when the recon gate is incomplete.

    Setup:
      1. Create project with bootstrap_enabled=False → phase='recon'
      2. Reason runs (initial), creates explore intent
      3. Explore produces a fact (partial recon progress)
      4. No unclaimed intents — only reason can create new work.

    Post-fix behavior:
      Reason should be dispatched so it can plan the missing recon categories.

    Current (buggy) behavior:
      _reason_trigger fires, but the recon gate blocks reason dispatch.
      The system is stuck — no work can proceed.
    """
    client = InProcessClient(http_client)
    containers = LocalContainerManager()
    loop = make_loop(
        mock_config(
            bootstrap=phase("complete"),
            reason=phase("intent"),
            explore=phase("fact"),
        ),
        client,
        containers,
    )
    project_id = create_project(http_client, bootstrap_enabled=False)
    try:
        # 1) Initial reason → creates intent i002
        dispatch_and_wait(loop)

        # 2) Explore i002 → fact f001
        dispatch_and_wait(loop)

        # Preconditions: reason trigger fires, no unclaimed intents
        project = client.get_project(project_id)
        unclaimed = [i for i in project.intents if i.to is None and i.worker is None]
        assert len(unclaimed) == 0, "precondition: no unclaimed intents"
        trigger = loop._reason_trigger(project)
        assert trigger is not None, "precondition: reason should be triggered"

        # 3) Attempt dispatch — post-fix should dispatch reason
        _run_one_dispatch_cycle(loop)

        # POST-FIX: the dispatcher should have re-dispatched reason
        assert loop.futures, (
            "dispatcher should re-dispatch reason to plan remaining recon work "
            f"even when recon gate is incomplete (trigger={trigger!r})"
        )
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Defect 2 — structured metadata before keyword fallback
# ---------------------------------------------------------------------------


def test_check_recon_executed_prefers_structured_recon_metadata() -> None:
    """Structured recon metadata is the canonical gate signal.

    The descriptions intentionally avoid the legacy keywords.  Post-fix,
    ``recon_category`` + ``recon_executed`` should drive coverage, and negative
    results should still count as executed work.
    """
    facts = [
        Fact.model_validate({
            "id": "f1",
            "description": "Network reachability inventory completed",
            "recon_category": "port_scan",
            "recon_executed": True,
            "recon_found_results": True,
            "recon_tool": "nmap",
            "recon_target": "10.0.0.5",
        }),
        Fact.model_validate({
            "id": "f2",
            "description": "Name inventory completed with no additional hosts",
            "recon_category": "subdomain",
            "recon_executed": True,
            "recon_found_results": False,
            "recon_tool": "subfinder",
            "recon_target": "example.test",
        }),
        Fact.model_validate({
            "id": "f3",
            "description": "Web location inventory completed",
            "recon_category": "directory",
            "recon_executed": True,
            "recon_found_results": True,
            "recon_tool": "ffuf",
            "recon_target": "https://example.test",
        }),
        Fact.model_validate({
            "id": "f4",
            "description": "Client resource inventory completed",
            "recon_category": "asset",
            "recon_executed": True,
            "recon_found_results": True,
            "recon_tool": "katana",
            "recon_target": "https://example.test",
        }),
    ]

    status = check_recon_executed(facts)

    assert status.all_executed, f"structured recon facts should pass, missing={status.missing_executions}"
    assert status.subdomain.executed is True
    assert status.subdomain.found_results is False


def test_recon_profile_skips_subdomain_for_ip_targets() -> None:
    """A single-IP target should not wait forever for subdomain enumeration."""
    facts = [
        Fact.model_validate({"id": "f1", "description": "inventory", "recon_category": "port_scan", "recon_executed": True}),
        Fact.model_validate({"id": "f2", "description": "inventory", "recon_category": "directory", "recon_executed": True}),
        Fact.model_validate({"id": "f3", "description": "inventory", "recon_category": "asset", "recon_executed": True}),
    ]
    profile = {
        "target_type": "ip",
        "required_categories": ["port_scan", "directory", "asset"],
        "optional_categories": [],
        "disabled_categories": ["subdomain"],
    }

    status = check_recon_executed(facts, profile=profile)

    assert status.all_executed, f"IP profile should not require subdomain, missing={status.missing_executions}"
    assert "subdomain" not in status.missing_executions


def test_scheduler_recon_gate_uses_project_recon_profile(http_client: TestClient) -> None:
    """The scheduler gate must use the project's persisted profile, not the
    default web profile."""
    response = http_client.post(
        "/projects",
        json={
            "title": "single ip",
            "origin": "10.0.0.5",
            "goal": "authorized assessment",
            "mode": "real_website",
            "bootstrap_enabled": False,
            "recon_profile": {
                "target_type": "ip",
                "required_categories": ["port_scan", "directory", "asset"],
                "optional_categories": [],
                "disabled_categories": ["subdomain"],
            },
        },
    )
    assert response.status_code == 201
    project_id = response.json()["project"]["id"]
    for category in ("port_scan", "directory", "asset"):
        assert http_client.post(
            f"/projects/{project_id}/facts",
            json={
                "description": f"{category} inventory completed",
                "recon_category": category,
                "recon_executed": True,
                "recon_found_results": False,
            },
        ).status_code == 201

    client = InProcessClient(http_client)
    containers = LocalContainerManager()
    loop = make_loop(
        mock_config(
            bootstrap=phase("complete"),
            reason=phase("intent"),
            explore=phase("fact"),
        ),
        client,
        containers,
    )
    try:
        project = client.get_project(project_id)
        assert loop._recon_gate_check(project), "IP profile should pass without subdomain recon"
    finally:
        loop.close()


def test_android_profile_uses_mobile_recon_categories() -> None:
    """Android recon should be profile-driven, not forced through web categories."""
    facts = [
        Fact.model_validate({"id": "f1", "description": "package observed", "recon_category": "android_app", "recon_executed": True}),
        Fact.model_validate({"id": "f2", "description": "login screen observed", "recon_category": "android_ui", "recon_executed": True}),
        Fact.model_validate({"id": "f3", "description": "network history observed", "recon_category": "mobile_api", "recon_executed": True}),
    ]
    profile = {
        "target_type": "android",
        "required_categories": ["android_app", "android_ui", "mobile_api"],
        "optional_categories": ["android_storage"],
        "disabled_categories": ["subdomain", "directory"],
    }

    status = check_recon_executed(facts, profile=profile)

    assert status.all_executed, f"Android profile should pass on mobile recon categories, missing={status.missing_executions}"


# ---------------------------------------------------------------------------
# Sanity check — keyword path still works
# ---------------------------------------------------------------------------


def test_check_recon_executed_passes_with_exact_keywords() -> None:
    """The keyword path MUST still work: descriptions containing the exact
    hardcoded keywords are recognized.  This is NOT the only path post-fix,
    but it must remain functional for backward compatibility.
    """
    facts = [
        Fact(id="f1", description="nmap port scan discovered open ports on target"),
        Fact(id="f2", description="subfinder found subdomains for target"),
        Fact(id="f3", description="gobuster directory enumeration detected paths"),
        Fact(id="f4", description="katana crawl discovered asset URLs"),
    ]

    status = check_recon_executed(facts)

    assert status.all_executed, "gate should pass when keywords match exactly"
    assert status.port_scan.executed and status.port_scan.found_results
    assert status.subdomain.executed and status.subdomain.found_results
    assert status.directory.executed and status.directory.found_results
    assert status.asset.executed and status.asset.found_results


# ---------------------------------------------------------------------------
# Focused single-test for -q verification
# ---------------------------------------------------------------------------


def test_structured_metadata_gap_is_reproducible_in_isolation() -> None:
    """Single focused test for the structured metadata gap.

    Run:
      pytest tests/test_recon_gate.py::test_structured_metadata_gap_is_reproducible_in_isolation -q

    Expected today: FAILS because Fact drops recon metadata and the gate only
    matches exact keywords.
    """
    facts = [
        Fact.model_validate({"id": "f1", "description": "inventory", "recon_category": "port_scan", "recon_executed": True}),
        Fact.model_validate({"id": "f2", "description": "inventory", "recon_category": "subdomain", "recon_executed": True}),
        Fact.model_validate({"id": "f3", "description": "inventory", "recon_category": "directory", "recon_executed": True}),
        Fact.model_validate({"id": "f4", "description": "inventory", "recon_category": "asset", "recon_executed": True}),
    ]
    status = check_recon_executed(facts)
    assert status.all_executed, (
        f"Expected all_executed=True from structured recon metadata, got False. missing={status.missing_executions}"
    )

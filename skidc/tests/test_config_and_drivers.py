from __future__ import annotations

import pytest

from skidc.dispatcher.coverage_profile import (
    build_web_coverage_profile,
    normalize_surface_entry,
)
from skidc.dispatcher.config import DispatchConfig, WorkerConfig
from skidc.dispatcher.contracts import (
    extract_reason_attack_paths,
    extract_reason_handoff,
    parse_json_output,
    validate_bootstrap_execute_payload,
    validate_explore_payload,
    validate_reason_payload,
)
from skidc.dispatcher.workers.registry import get_driver


def _claudecode_worker(model="deepseek-chat", base="https://api.deepseek.com/anthropic"):
    return WorkerConfig(
        name="cc", type="claudecode", task_types=["explore"], max_running=1, priority=0,
        env={"ANTHROPIC_MODEL": model, "ANTHROPIC_BASE_URL": base, "ANTHROPIC_AUTH_TOKEN": "sk-x"},
    )


def _codex_worker(model="qwen-max", base="https://dashscope.aliyuncs.com/compatible-mode/v1"):
    return WorkerConfig(
        name="cx", type="codex", task_types=["explore"], max_running=1, priority=0,
        env={"CODEX_MODEL": model, "CODEX_BASE_URL": base, "OPENAI_API_KEY": "sk-y"},
    )


# ---- model swap is the headline feature: assert the brain follows the env --------

def test_claudecode_driver_targets_deepseek_endpoint_and_model():
    driver = get_driver("claudecode")
    worker = _claudecode_worker()
    hc = driver.build_healthcheck(worker)
    assert any("api.deepseek.com/anthropic/v1/messages" in a for a in hc)
    assert any("deepseek-chat" in a for a in hc)
    execute = driver.build_execute(worker, "PROMPT", "sess-1")
    assert execute.argv[0] == "claude"
    assert "sess-1" in execute.argv


def test_codex_driver_targets_qwen_endpoint_and_model():
    driver = get_driver("codex")
    worker = _codex_worker()
    hc = driver.build_healthcheck(worker)
    assert any("dashscope.aliyuncs.com/compatible-mode/v1/responses" in a for a in hc)
    assert any("qwen-max" in a for a in hc)
    execute = driver.build_execute(worker, "PROMPT", None)
    assert execute.argv[0] == "codex"
    assert "qwen-max" in execute.argv


def test_codex_extracts_session_from_stderr():
    driver = get_driver("codex")
    assert driver.extract_session(None, "", "session id: 1a2b3c4d-0000") == "1a2b3c4d-0000"


def test_claudecode_seeds_session():
    driver = get_driver("claudecode")
    assert driver.prepare_session() is not None


# ---- config validation -----------------------------------------------------------

def _base_config(workers):
    return {
        "server": "http://x",
        "runtime": {
            "max_workers": 4, "max_running_projects": 2, "max_project_workers": 2,
            "interval": 3, "healthcheck_timeout": 10, "prompt_group": "default",
        },
        "tasks": {
            "bootstrap": {"timeout": 60, "conclude_timeout": 30},
            "reason": {"timeout": 45, "max_intents": 2},
            "explore": {"timeout": 120, "conclude_timeout": 30},
        },
        "container": {"image": "img", "network_mode": "host", "completed_action": "stop"},
        "workers": workers,
    }


def test_common_env_is_merged_then_overridden():
    cfg = DispatchConfig.model_validate(
        {
            **_base_config([
                {
                    "name": "cc", "type": "claudecode", "task_types": ["explore"],
                    "max_running": 1, "priority": 0,
                    "env": {"ANTHROPIC_MODEL": "deepseek-chat", "ANTHROPIC_AUTH_TOKEN": "sk-worker"},
                }
            ]),
            "common_env": {
                "ANTHROPIC_BASE_URL": "https://api.deepseek.com/anthropic",
                "ANTHROPIC_AUTH_TOKEN": "sk-common",
            },
        }
    )
    env = cfg.workers[0].env
    assert env["ANTHROPIC_BASE_URL"] == "https://api.deepseek.com/anthropic"  # from common
    assert env["ANTHROPIC_AUTH_TOKEN"] == "sk-worker"  # worker overrides common


def test_missing_env_keys_rejected():
    with pytest.raises(ValueError, match="missing env keys"):
        DispatchConfig.model_validate(
            _base_config([
                {"name": "cc", "type": "claudecode", "task_types": ["explore"], "max_running": 1, "priority": 0, "env": {}}
            ])
        )


def test_duplicate_worker_names_rejected():
    w = {"name": "dup", "type": "mock", "task_types": ["explore"], "max_running": 1, "priority": 0, "env": {}}
    with pytest.raises(ValueError, match="worker names must be unique"):
        DispatchConfig.model_validate(_base_config([w, dict(w)]))


def test_max_project_workers_cannot_exceed_max_workers():
    cfg = _base_config([
        {"name": "m", "type": "mock", "task_types": ["explore"], "max_running": 1, "priority": 0, "env": {}}
    ])
    cfg["runtime"]["max_project_workers"] = 99
    with pytest.raises(ValueError, match="max_project_workers cannot exceed"):
        DispatchConfig.model_validate(cfg)


# ---- contract parsing ------------------------------------------------------------

def test_parse_json_from_fenced_block():
    out = 'noise\n```json\n{"accepted": true, "data": {"description": "x"}}\n```\ntrailer'
    assert parse_json_output(out)["accepted"] is True


def test_validate_explore_accepts_wrapped_and_bare():
    assert validate_explore_payload({"accepted": True, "data": {"description": "found it"}}) == ("fact", {"description": "found it"})
    assert validate_explore_payload({"description": "bare"}) == ("fact", {"description": "bare"})


def test_validate_explore_carries_structured_fields():
    kind, data = validate_explore_payload(
        {"accepted": True, "data": {
            "description": "IDOR on /admin", "scope": "api.example.com/admin",
            "vuln_type": "IDOR", "severity": "high", "parent_fact": "f002",
            "verification_of": "f001", "goal_type": "potential_target", "status": "verified",
            "recon_category": "port_scan", "recon_executed": True, "recon_found_results": False,
            "recon_tool": "nmap", "recon_target": "api.example.com", "recon_evidence_ref": "log001",
        }}
    )
    assert kind == "fact"
    assert data == {
        "description": "IDOR on /admin", "scope": "api.example.com/admin",
        "vuln_type": "IDOR", "severity": "high", "parent_fact": "f002",
        "verification_of": "f001", "goal_type": "potential_target", "status": "verified",
        "recon_category": "port_scan", "recon_executed": True, "recon_found_results": False,
        "recon_tool": "nmap", "recon_target": "api.example.com", "recon_evidence_ref": "log001",
    }


def test_validate_explore_rejection():
    assert validate_explore_payload({"accepted": False, "reason": "no"}) == ("rejected", None)


def test_validate_reason_complete_and_intents():
    kind, data, recon_complete = validate_reason_payload(
        {"accepted": True, "data": {"complete": {"from": ["f001"], "description": "done"}}},
        open_intents_empty=True, max_intents=3,
    )
    assert kind == "complete"
    assert recon_complete is False
    kind, data, recon_complete = validate_reason_payload(
        {
            "accepted": True,
            "data": {
                "intents": [
                    {"from": ["f001"], "description": "a", "target": "example.test", "port": 443},
                    {"from": ["f002"], "description": "b"},
                ],
                "recon_complete": True,
            },
        },
        open_intents_empty=True, max_intents=1,
    )
    assert kind == "intents" and len(data) == 1  # capped to max_intents
    assert data[0]["target"] == "example.test"
    assert data[0]["port"] == 443
    assert recon_complete is True


def test_validate_reason_accepts_checkpointing_noop_when_graph_has_no_new_work():
    kind, data, recon_complete = validate_reason_payload(
        {"accepted": True, "data": {}},
        open_intents_empty=True,
        max_intents=3,
    )
    assert (kind, data, recon_complete) == ("noop", None, False)


def test_reason_intents_with_attack_paths_still_valid():
    # intents + attack_paths coexisting must still parse as "intents"
    kind, data, _recon_complete = validate_reason_payload(
        {"accepted": True, "data": {
            "intents": [{"from": ["f001"], "description": "a"}],
            "attack_paths": [{"name": "chain", "fact_chain": ["f001", "f002"], "description": "d", "severity": "high"}],
        }},
        open_intents_empty=True, max_intents=3,
    )
    assert kind == "intents" and len(data) == 1


def test_validate_reason_accepts_attack_surface_handoff_seed_deck():
    payload = {"accepted": True, "data": {
        "recon_complete": True,
        "attack_surface_map": {
            "summary": "HTTPS app with API",
            "surfaces": [{"name": "api", "target": "example.test", "port": 443, "evidence": ["f001"]}],
        },
        "explore_seed_deck": {
            "seeds": [
                {
                    "from": ["f001"],
                    "description": "Probe object authorization",
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

    kind, data, recon_complete = validate_reason_payload(payload, open_intents_empty=True, max_intents=3)
    handoff = extract_reason_handoff(payload)

    assert kind == "noop"
    assert recon_complete is True
    assert data is None
    assert handoff["attack_surface_map"]["summary"] == "HTTPS app with API"
    assert handoff["explore_seed_deck"][0]["action_kind"] == "authz_probe"


def test_extract_reason_attack_paths():
    payload = {"accepted": True, "data": {
        "intents": [],
        "attack_paths": [
            {"name": "auth->idor->dump", "fact_chain": ["f001", "f003"], "description": "full chain", "severity": "critical"},
            {"name": "no chain", "fact_chain": [], "description": "x"},          # dropped: empty chain
            {"fact_chain": ["f001"], "description": "x"},                          # dropped: no name
            {"name": "default sev", "fact_chain": ["f002"], "description": "d"},   # severity defaults to medium
        ],
    }}
    paths = extract_reason_attack_paths(payload)
    assert len(paths) == 2
    assert paths[0] == {
        "name": "auth->idor->dump",
        "fact_chain": ["f001", "f003"],
        "description": "full chain",
        "severity": "critical",
        "status": "hypothesis",
    }
    assert paths[1]["severity"] == "medium"
    assert paths[1]["status"] == "hypothesis"


def test_extract_reason_attack_paths_absent():
    assert extract_reason_attack_paths({"accepted": True, "data": {"intents": []}}) == []
    assert extract_reason_attack_paths({"accepted": False, "reason": "no"}) == []


def test_validate_bootstrap_requires_fact_and_complete():
    kind, data = validate_bootstrap_execute_payload(
        {"accepted": True, "data": {"fact": {"description": "flag{x}"}, "complete": {"description": "goal met"}}}
    )
    assert kind == "complete"
    assert data["fact_description"] == "flag{x}"
    with pytest.raises(ValueError):
        validate_bootstrap_execute_payload({"accepted": True, "data": {"fact": {"description": "only fact"}}})


def test_public_upload_listing_does_not_create_authorization_coverage():
    surface = normalize_surface_entry(
        {
            "target": "example.test",
            "port": 80,
            "path": "/uploads/",
            "method": "GET",
            "surface_type": "route",
        }
    )
    assert surface is not None

    families = {item["test_family"] for item in build_web_coverage_profile(surface)}

    assert "file_path" in families
    assert "authorization" not in families


def test_admin_management_and_object_reference_create_authorization_coverage():
    surface = normalize_surface_entry(
        {
            "target": "example.test",
            "port": 443,
            "path": "/admin/users",
            "method": "POST",
            "params": ["id"],
            "surface_type": "form",
            "auth_context": "admin",
        }
    )
    assert surface is not None

    families = {item["test_family"] for item in build_web_coverage_profile(surface)}

    assert "authorization" in families


def test_allowed_support_service_is_optional_and_separate():
    surface = normalize_surface_entry(
        {
            "target": "example.test",
            "port": 3306,
            "surface_type": "service",
        },
        support_ports=[3306],
    )
    assert surface is not None

    profile = build_web_coverage_profile(surface)

    assert len(profile) == 1
    assert profile[0]["test_family"] == "support_service"
    assert profile[0]["required"] is False

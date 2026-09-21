from __future__ import annotations

import json
from importlib import resources
from typing import Any

from skidc.planning import behavior_identity, cluster_behaviors
from skidc.server.models import ProjectDetail


def load_prompt(group: str, name: str) -> str:
    return resources.files("skidc.dispatcher.prompts").joinpath(group).joinpath(name).read_text(encoding="utf-8")


def render_prompt(template: str, replacements: dict[str, str]) -> str:
    text = template
    for key, value in replacements.items():
        text = text.replace("{" + key + "}", value)
    return text


def format_fact_ids(fact_ids: list[str]) -> str:
    return format_json_block(fact_ids)


def format_open_intents(intents: list[dict[str, Any]]) -> str:
    return format_json_block(intents)


def format_dispatch_graph(project: ProjectDetail, *, limit: int | None = None) -> str:
    """Build the bounded V3 reasoning view instead of replaying the full export."""
    context_limit = limit or project.project.recon_profile.reason_context_limit
    behavior_limit = max(12, min(50, context_limit // 2))
    hypothesis_limit = max(12, min(40, context_limit // 2))
    fact_order = {fact.id: index for index, fact in enumerate(project.facts)}
    behavior_meta: dict[str, dict[str, Any]] = {}
    for surface in project.surface_inventory:
        behavior_key, _, _ = behavior_identity(surface)
        meta = behavior_meta.setdefault(
            behavior_key,
            {"observation_count": 0, "planning_status": "assessed"},
        )
        meta["observation_count"] += 1
        if surface.planning_status == "pending":
            meta["planning_status"] = "pending"
    behaviors = cluster_behaviors(project.surface_inventory)
    behaviors.sort(
        key=lambda item: (
            behavior_meta[item["behavior_key"]]["planning_status"] == "pending",
            bool(item.get("auth_context") and item.get("auth_context") != "anonymous"),
            len(item.get("capabilities") or []),
            len(item.get("params") or []),
            item["behavior_key"],
        ),
        reverse=True,
    )
    behaviors = behaviors[:behavior_limit]
    referenced_fact_ids = {"origin", "goal"}
    for intent in project.intents:
        if intent.status == "open" and intent.to is None:
            referenced_fact_ids.update(intent.from_)
    for hypothesis in project.hypotheses:
        referenced_fact_ids.update(hypothesis.trigger_fact_ids)
    for behavior in behaviors:
        referenced_fact_ids.update(behavior.get("evidence_fact_ids") or [])
        if behavior.get("source_fact_id"):
            referenced_fact_ids.add(behavior["source_fact_id"])
    for fact in project.facts:
        if fact.id in referenced_fact_ids:
            referenced_fact_ids.update(fact.parent_fact_ids)

    def fact_score(fact) -> tuple[int, int]:
        score = 0
        status = str(fact.status or "").casefold()
        severity = str(fact.severity or "").casefold()
        if fact.id in {"origin", "goal"}:
            score += 100
        if fact.id in referenced_fact_ids:
            score += 60
        if fact.kind == "execution_result" or status in {"failed", "inconclusive", "blocked_by_precondition"}:
            score += 45
        if status in {"confirmed", "verified", "vulnerable"}:
            score += 50
        if severity in {"critical", "high"}:
            score += 30
        if fact.goal_type == "potential_target":
            score += 20
        return score, fact_order[fact.id]

    selected_facts = sorted(project.facts, key=fact_score, reverse=True)[:context_limit]
    selected_facts.sort(key=lambda fact: fact_order[fact.id])
    facts = [
        {
            "id": fact.id,
            "kind": fact.kind,
            "summary": fact.summary or fact.description[:320],
            "subject": fact.subject,
            "data": fact.data,
            "parent_fact_ids": fact.parent_fact_ids,
            "evidence_refs": fact.evidence_refs,
            "confidence": fact.confidence,
            "status": fact.status,
            "severity": fact.severity,
        }
        for fact in selected_facts
    ]
    open_intents = [
        {
            "id": intent.id,
            "from": intent.from_,
            "description": intent.description,
            "target": intent.target,
            "port": intent.port,
            "path": intent.path,
            "action_kind": intent.action_kind,
            "test_variant": intent.test_variant,
            "hypothesis_id": intent.hypothesis_id,
        }
        for intent in project.intents
        if intent.status == "open" and intent.to is None
    ]
    hypotheses = [
        {
            "id": item.id,
            "behavior_key": item.behavior_key,
            "test_family": item.test_family,
            "test_variant": item.test_variant,
            "rationale": item.rationale,
            "trigger_fact_ids": item.trigger_fact_ids,
            "status": item.status,
            "score": item.score,
        }
        for item in project.hypotheses[-hypothesis_limit:]
    ]
    behavior_view = [
        {
            "behavior_key": item["behavior_key"],
            "target": item.get("target"),
            "port": item.get("port"),
            "method": item.get("method"),
            "path_template": item.get("path_template"),
            "params": item.get("params") or [],
            "auth_context": item.get("auth_context"),
            "roles": item.get("roles") or [],
            "operation_type": item.get("operation_type"),
            "capabilities": item.get("capabilities") or [],
            "planning_status": behavior_meta[item["behavior_key"]]["planning_status"],
            "observation_count": behavior_meta[item["behavior_key"]]["observation_count"],
            "evidence_fact_ids": item.get("evidence_fact_ids") or [],
        }
        for item in behaviors
    ]
    return format_json_block(
        {
            "project": {
                "id": project.project.id,
                "mode": project.project.mode,
                "phase": project.project.phase,
                "planning_version": project.project.planning_version,
            },
            "facts": facts,
            "open_intents": open_intents,
            "hypotheses": hypotheses,
            "behaviors": behavior_view,
        }
    )


def format_coverage_summary(project: ProjectDetail, *, limit: int = 10) -> str:
    family_counts: dict[str, dict[str, int]] = {}
    unresolved = []
    for item in project.coverage_items:
        family = item.test_family or item.item_type
        counts = family_counts.setdefault(family, {})
        verdict = item.outcome or "pending"
        counts[item.execution_status] = counts.get(item.execution_status, 0) + 1
        counts[verdict] = counts.get(verdict, 0) + 1
        if item.required and (item.execution_status != "completed" or verdict in {"pending", "inconclusive"}):
            unresolved.append(item)
    unresolved.sort(key=lambda item: (-(item.priority or 0), item.surface_group or "", item.id))
    blockers = [
        {
            "kind": blocker.kind,
            "ref": blocker.ref,
            "status": blocker.status,
            "priority": blocker.priority,
            "reason": blocker.reason,
        }
        for blocker in project.project.completion_blockers[:limit]
    ]
    top_items = [
        {
            "id": item.id,
            "surface_group": item.surface_group,
            "test_family": item.test_family,
            "auth_context": item.auth_context,
            "priority": item.priority,
            "execution_status": item.execution_status,
            "outcome": item.outcome,
            "variants": item.test_variants,
        }
        for item in unresolved[:limit]
    ]
    return format_json_block({"by_test_family": family_counts, "blockers": blockers, "top_unresolved": top_items})


def format_intent_coverage(project: ProjectDetail, intent_id: str, *, limit: int = 1) -> str:
    items = [item for item in project.coverage_items if intent_id in item.intent_ids or item.intent_id == intent_id]
    intent = next((item for item in project.intents if item.id == intent_id), None)
    items.sort(key=lambda item: (-(item.priority or 0), item.id))
    return format_json_block([
        {
            "id": item.id,
            "surface_group": item.surface_group,
            "test_family": item.test_family,
            "variants": item.test_variants,
            "assigned_variant": intent.test_variant if intent else None,
            "auth_context": item.auth_context,
            "path": item.path,
            "params": item.param,
            "priority": item.priority,
            "execution_status": item.execution_status,
            "outcome": item.outcome,
        }
        for item in items[:limit]
    ])


def format_hints(hints: list[dict[str, Any]]) -> str:
    return format_json_block(hints)


def format_scope_constraints(project: ProjectDetail) -> str:
    policy = project.project.scope_policy
    profile = project.project.recon_profile
    hints = [
        {"id": hint.id, "content": hint.content, "creator": hint.creator, "created_at": hint.created_at}
        for hint in project.hints
    ]
    payload = {
        "mode": project.project.mode,
        "phase": project.project.phase,
        "target_type": profile.target_type,
        "scope_policy": {
            "allowed_targets": policy.allowed_targets,
            "blocked_targets": policy.blocked_targets,
            "allowed_ports": policy.allowed_ports,
            "blocked_ports": policy.blocked_ports,
            "allowed_paths": policy.allowed_paths,
            "blocked_paths": policy.blocked_paths,
            "support_ports": policy.support_ports,
            "allow_subdomains": policy.allow_subdomains,
            "allow_domain_scan": policy.allow_domain_scan,
            "rate_limits": policy.rate_limits,
            "passive_only": policy.passive_only,
            "allow_state_change": policy.allow_state_change,
            "allow_destructive": policy.allow_destructive,
        },
        "recon_profile": {
            "required_categories": profile.required_categories,
            "optional_categories": profile.optional_categories,
            "disabled_categories": profile.disabled_categories,
            "frontier_breadth_slots": profile.frontier_breadth_slots,
            "branch_no_progress_limit": profile.branch_no_progress_limit,
            "reason_context_limit": profile.reason_context_limit,
        },
        "hints": hints,
    }
    return format_json_block(payload)


def format_json_block(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)

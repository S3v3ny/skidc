from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from datetime import datetime
import json
import yaml

from skidc.server.db import get_conn
from skidc.server.services import (
    build_completed_attack_paths,
    build_coverage_items,
    build_hypotheses,
    assessment_limitations,
    fact_to_model,
    get_project_or_404,
)

router = APIRouter(tags=["export"])


def format_export_timestamp(value: str | None) -> str | None:
    if not value:
        return value
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _load_project_data(conn, project_id: str):

    facts = conn.execute("SELECT * FROM facts WHERE project_id = ?", (project_id,)).fetchall()
    proj = get_project_or_404(conn, project_id)
    hints = conn.execute(
        "SELECT content, creator, created_at FROM hints WHERE project_id = ? ORDER BY created_at",
        (project_id,),
    ).fetchall()
    intents = conn.execute(
        "SELECT * FROM intents WHERE project_id = ? ORDER BY created_at",
        (project_id,),
    ).fetchall()

    sources_by_intent = {}
    for i in intents:
        rows = conn.execute(
            "SELECT fact_id FROM intent_sources WHERE intent_id = ? AND project_id = ? ORDER BY rowid",
            (i["id"], project_id),
        ).fetchall()
        sources_by_intent[i["id"]] = [r["fact_id"] for r in rows]

    attack_paths = build_completed_attack_paths(conn, project_id)

    return proj, facts, hints, intents, sources_by_intent, attack_paths


def _load_coverage_items(conn, project_id: str):
    return conn.execute(
        "SELECT * FROM coverage_items WHERE project_id = ? ORDER BY created_at",
        (project_id,),
    ).fetchall()


def _load_surface_inventory(conn, project_id: str):
    return conn.execute(
        "SELECT * FROM surface_inventory WHERE project_id = ? ORDER BY created_at, id",
        (project_id,),
    ).fetchall()


def _load_coverage_links(conn, project_id: str):
    intent_refs: dict[str, list[str]] = {}
    fact_refs: dict[str, list[str]] = {}
    evidence_refs: dict[str, list[str]] = {}
    for row in conn.execute(
        "SELECT coverage_id, intent_id FROM coverage_intents WHERE project_id = ? ORDER BY coverage_id, intent_id",
        (project_id,),
    ).fetchall():
        intent_refs.setdefault(row["coverage_id"], []).append(row["intent_id"])
    for row in conn.execute(
        "SELECT coverage_id, fact_id FROM coverage_evidence WHERE project_id = ? ORDER BY coverage_id, fact_id",
        (project_id,),
    ).fetchall():
        evidence_refs.setdefault(row["coverage_id"], []).append(row["fact_id"])
        fact_refs.setdefault(row["fact_id"], []).append(row["coverage_id"])
    return intent_refs, fact_refs, evidence_refs


def _export_yaml(conn, project_id: str) -> str:
    proj, facts, hints, intents, sources_by_intent, attack_paths = _load_project_data(conn, project_id)
    coverage_items = _load_coverage_items(conn, project_id)
    surface_inventory = _load_surface_inventory(conn, project_id)
    coverage_intents, fact_coverage, coverage_evidence = _load_coverage_links(conn, project_id)
    fact_models = {f["id"]: fact_to_model(conn, f, project_id) for f in facts}
    coverage_models = {
        item.id: item
        for item in build_coverage_items(conn, project_id, coverage_items)
    }

    hypotheses = build_hypotheses(conn, project_id)
    origin_desc = ""
    goal_desc = ""
    for f in facts:
        if f["id"] == "origin":
            origin_desc = f["description"]
        elif f["id"] == "goal":
            goal_desc = f["description"]

    data: dict = {
        "project": {
            "title": proj["title"],
            "origin": origin_desc,
            "goal": goal_desc,
            "bootstrap_enabled": bool(proj["bootstrap_enabled"]),
            "phase": proj["phase"] if "phase" in proj.keys() else "explore",
            "mode": _project_mode(proj),
        }
    }
    scope_policy = _json_object(_row_get(proj, "scope_policy"))
    recon_profile = _json_object(_row_get(proj, "recon_profile"))
    if scope_policy:
        data["project"]["scope_policy"] = scope_policy
    if recon_profile:
        data["project"]["recon_profile"] = recon_profile

    if hints:
        data["hints"] = [
            {
                "content": h["content"],
                "creator": h["creator"],
                "created_at": format_export_timestamp(h["created_at"]),
            }
            for h in hints
        ]

    fact_list = []
    for f in facts:
        model = fact_models[f["id"]]
        entry: dict = {"id": f["id"], "description": f["description"]}
        for col in (
            "scope", "vuln_type", "severity", "parent_fact", "verification_of", "goal_type", "status",
            "recon_category", "recon_tool", "recon_target", "recon_evidence_ref",
        ):
            if col in f.keys() and f[col]:
                entry[col] = f[col]
        for col in ("recon_executed", "recon_found_results"):
            if col in f.keys() and f[col] is not None:
                entry[col] = bool(f[col])
        entry.update({
            "surface_class": model.surface_class,
            "result_class": model.result_class,
            "coverage_refs": model.coverage_refs,
            "intent_refs": model.intent_refs,
            "task_log_refs": model.task_log_refs,
        })
        fact_list.append(entry)
    data["facts"] = fact_list

    intent_list = []
    for i in intents:
        entry: dict = {
            "from": sources_by_intent.get(i["id"], []),
            "to": i["to_fact_id"],
            "description": i["description"],
            "creator": i["creator"],
            "worker": i["worker"],
            "created_at": format_export_timestamp(i["created_at"]),
            "concluded_at": format_export_timestamp(i["concluded_at"]),
        }
        for col in (
            "target", "port", "path", "surface_type", "action_kind", "test_variant", "priority", "attempt_count",
            "last_error", "last_worker", "next_retry_at", "failed_at", "dead_lettered_at", "status",
        ):
            if col in i.keys() and i[col] is not None:
                entry[col] = i[col]
        suggested_tools = _json_list(_row_get(i, "suggested_tools"))
        if suggested_tools:
            entry["suggested_tools"] = suggested_tools
        coverage_refs = [
            coverage_id
            for coverage_id, intent_ids in coverage_intents.items()
            if i["id"] in intent_ids
        ]
        if coverage_refs:
            entry["coverage_refs"] = coverage_refs
        intent_list.append(entry)

    if intent_list:
        data["intents"] = intent_list

    if attack_paths:
        data["attack_paths"] = [
            path.model_dump(mode="json")
            for path in attack_paths
        ]

    if coverage_items:
        data["coverage_items"] = [
            coverage_models[item["id"]].model_dump(exclude_none=True)
            for item in coverage_items
        ]

    if hypotheses:
        data["hypotheses"] = [
            item.model_dump(exclude_none=True) for item in hypotheses
        ]
    if surface_inventory:
        data["surface_inventory"] = [
            {
                key: value
                for key, value in {
                    "id": item["id"],
                    "surface_group": item["surface_group"],
                    "target": item["target"],
                    "port": item["port"],
                    "method": item["method"],
                    "path_template": item["path_template"],
                    "params": _json_list(item["params"]),
                    "surface_type": item["surface_type"],
                    "auth_context": item["auth_context"],
                    "roles": _json_list(item["roles"]),
                    "traits": _json_object(item["traits"]),
                    "source_fact_id": item["source_fact_id"],
                }.items()
                if value is not None
            }
            for item in surface_inventory
        ]

    return yaml.dump(data, allow_unicode=True, default_flow_style=False, sort_keys=False)


def _row_get(row, key: str):
    return row[key] if key in row.keys() else None


def _json_object(value: str | None) -> dict:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _json_list(value: str | list | None) -> list:
    if isinstance(value, list):
        return value
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def _project_mode(proj) -> str:
    mode = _row_get(proj, "mode")
    if mode in ("ctf", "real_website"):
        return mode
    phase = _row_get(proj, "phase") or "explore"
    return "real_website" if (not bool(proj["bootstrap_enabled"]) or phase == "recon") else "ctf"


def _export_timeline(conn, project_id: str) -> str:
    proj, facts, hints, intents, sources_by_intent, _attack_paths = _load_project_data(conn, project_id)

    facts_by_id = {f["id"]: f["description"] for f in facts}

    events: list[tuple[str, int, str]] = []  # (timestamp, order, text)
    order = 0

    origin_desc = facts_by_id.get("origin", "")
    goal_desc = facts_by_id.get("goal", "")
    ts = format_export_timestamp(proj["created_at"]) or ""
    block = f"[{ts}] PROJECT CREATED\n  origin: {origin_desc}\n  goal: {goal_desc}"
    events.append((proj["created_at"] or "", order, block))
    order += 1

    for h in hints:
        ts = format_export_timestamp(h["created_at"]) or ""
        block = f"[{ts}] HINT by {h['creator']}\n  {h['content']}"
        events.append((h["created_at"] or "", order, block))
        order += 1

    for i in intents:
        src = sources_by_intent.get(i["id"], [])
        from_str = ", ".join(src)

        ts = format_export_timestamp(i["created_at"]) or ""
        meta = f"  from: {from_str}"
        if i["worker"] and not i["concluded_at"]:
            meta += f"\n  worker: {i['worker']} (in progress)"
        block = f"[{ts}] INTENT DECLARED {i['id']} by {i['creator']}\n{meta}\n  {i['description']}"
        events.append((i["created_at"] or "", order, block))
        order += 1

        if not i["concluded_at"] or not i["to_fact_id"]:
            continue

        ts = format_export_timestamp(i["concluded_at"]) or ""
        actor = i["worker"] or i["creator"]

        if i["to_fact_id"] == "goal":
            block = f"[{ts}] PROJECT COMPLETED by {actor}\n  via: {i['id']} from {from_str}"
        else:
            fact_desc = facts_by_id.get(i["to_fact_id"], "")
            block = f"[{ts}] INTENT CONCLUDED {i['id']} by {actor}\n  from: {from_str}\n  produced: {i['to_fact_id']}\n  {fact_desc}"

        events.append((i["concluded_at"] or "", order, block))
        order += 1

    events.sort(key=lambda e: (e[0], e[1]))

    return "\n\n".join(e[2] for e in events) + "\n"


def _export_report(conn, project_id: str) -> str:
    proj, facts, hints, intents, sources_by_intent, attack_paths = _load_project_data(conn, project_id)
    coverage_items = _load_coverage_items(conn, project_id)
    logs = conn.execute(
        "SELECT * FROM task_logs WHERE project_id = ? ORDER BY created_at",
        (project_id,),
    ).fetchall()

    facts_by_id = {f["id"]: f for f in facts}
    fact_models = {f["id"]: fact_to_model(conn, f, project_id) for f in facts}
    coverage_models = {
        item.id: item
        for item in build_coverage_items(conn, project_id, coverage_items)
    }
    hypotheses = build_hypotheses(conn, project_id)
    limitations = assessment_limitations(conn, project_id)
    attack_path_models = {path.id: path for path in attack_paths}
    origin_fact = facts_by_id.get("origin")
    goal_fact = facts_by_id.get("goal")
    origin_desc = origin_fact["description"] if origin_fact is not None else ""
    goal_desc = goal_fact["description"] if goal_fact is not None else ""
    mode = _project_mode(proj)
    scope_policy = _json_object(_row_get(proj, "scope_policy"))
    recon_profile = _json_object(_row_get(proj, "recon_profile"))

    report: list[str] = [
        f"# Penetration Test Report: {proj['title']}",
        "",
        "## Project",
        "",
        f"- Project ID: {proj['id']}",
        f"- Mode: {mode}",
        f"- Status: {proj['status']}",
        f"- Completion Outcome: {_row_get(proj, 'completion_outcome') or 'pending'}",
        f"- Stop Reason: {_row_get(proj, 'stop_reason_code') or '-'}",
        f"- Stop Detail: {_row_get(proj, 'stop_reason_detail') or '-'}",
        f"- Phase: {_row_get(proj, 'phase') or 'explore'}",
        f"- Created At: {format_export_timestamp(proj['created_at']) or proj['created_at']}",
        f"- Origin: {origin_desc}",
        f"- Goal: {goal_desc}",
        "",
        "## Scope And Safety Boundaries",
        "",
    ]

    if scope_policy:
        report.extend(_format_scope_policy(scope_policy))
    else:
        report.append("- Scope policy: not configured")
    if recon_profile:
        report.extend(["", "## Recon Profile", ""])
        report.extend(_format_recon_profile(recon_profile))

    report.extend(["", "## Executive Summary", ""])
    completion_intent = next((intent for intent in intents if intent["to_fact_id"] == "goal"), None)
    if completion_intent is not None:
        report.append(f"- Completion summary: {completion_intent['description']}")
    report.append(f"- Facts recorded: {len(facts)}")
    report.append(f"- Intents recorded: {len(intents)}")
    report.append(f"- Completed causal attack paths: {len(attack_paths)}")
    report.append(f"- Coverage items recorded: {len(coverage_items)}")
    report.append(f"- Execution logs recorded: {len(logs)}")
    report.append(
        "- Confirmed security findings: "
        f"{sum(model.result_class == 'confirmed' for fact_id, model in fact_models.items() if fact_id not in {'origin', 'goal'})}"
    )
    report.append(f"- Hypotheses recorded: {len(hypotheses)}")

    report.extend(["", "## Hypothesis Plan", ""])
    report.append(
        "Planning semantics: Coverage and Hypotheses are an audit ledger. They guide Reason and document limitations, but do not block completion."
    )
    if hypotheses:
        for item in hypotheses:
            refs = ", ".join(item.trigger_fact_ids) or "-"
            report.append(
                f"- {item.id}: status={item.status}; score={item.score:.3f}; "
                f"test={item.test_family}/{item.test_variant}; behavior={item.behavior_key}; evidence={refs}"
            )
            report.append(f"  Rationale: {item.rationale}")
            if item.last_error:
                report.append(f"  Limitation: {item.last_error}")
    else:
        report.append("No evidence-supported Hypotheses were recorded.")

    report.extend(["", "## Assessment Limitations", ""])
    report.append(
        "Reason decides whether the current Facts sufficiently assess the Goal. Coverage, Surface, Hypothesis, "
        "failed, and inconclusive records remain visible here but do not force the project to stop."
    )
    if limitations:
        for limitation in limitations:
            report.append(
                f"- {limitation.kind}/{limitation.ref}: status={limitation.status}; "
                f"reason={limitation.reason}"
            )
    else:
        report.append("- No assessment limitations are currently recorded.")

    report.extend(["", "## Coverage Ledger", ""])
    if coverage_items:
        report.extend(_format_coverage_ledger(coverage_items, coverage_models))
    else:
        report.append("No coverage items were recorded.")

    findings = _report_findings(facts, fact_models)
    confirmed_findings = [fact for fact in findings if fact_models[fact["id"]].result_class == "confirmed"]
    failed_findings = [fact for fact in findings if str(fact["status"] or "").casefold() == "failed"]
    inconclusive_findings = [
        fact for fact in findings
        if fact_models[fact["id"]].result_class == "limited"
        and str(fact["status"] or "").casefold() != "failed"
    ]
    negative_findings = [fact for fact in findings if fact_models[fact["id"]].result_class == "refuted"]
    report.extend(["", "## Test Results", ""])
    for surface_class, heading in (
        ("web", "Web Application Findings"),
        ("api", "API Findings"),
        ("support_service", "Support Service Findings"),
    ):
        surface_findings = [
            fact for fact in confirmed_findings
            if fact_models[fact["id"]].surface_class == surface_class
        ]
        report.extend([f"### {heading}", ""])
        if surface_findings:
            for fact in surface_findings:
                report.extend(_format_finding(fact, fact_models[fact["id"]], heading_level=4))
        else:
            report.extend(["No confirmed findings were recorded in this section.", ""])

    other_confirmed = [
        fact for fact in confirmed_findings
        if fact_models[fact["id"]].surface_class == "unclassified"
    ]
    if other_confirmed:
        report.extend(["### Other Confirmed Findings", ""])
        for fact in other_confirmed:
            report.extend(_format_finding(fact, fact_models[fact["id"]], heading_level=4))

    if failed_findings:
        report.extend(["", "### Failed Tests", ""])
        for fact in failed_findings:
            report.extend(_format_finding(fact, fact_models[fact["id"]], heading_level=4))

    if inconclusive_findings:
        report.extend(["", "### Inconclusive Tests", ""])
        for fact in inconclusive_findings:
            report.extend(_format_finding(fact, fact_models[fact["id"]], heading_level=4))

    if negative_findings:
        report.extend(["", "### Negative Tests", ""])
        for fact in negative_findings:
            report.extend(_format_finding(fact, fact_models[fact["id"]], heading_level=4))

    report.extend(["", "## Test Process", ""])
    if logs:
        for log in logs:
            report.append(_format_log_timeline_item(log))
    else:
        report.append("No execution logs were recorded.")

    report.extend(["", "## Execution Input Index", ""])
    if logs:
        for log in logs:
            report.extend(_format_log_input_summary(log))
    else:
        report.append("No execution inputs were recorded.")

    confirmed_paths = [path.model_dump(mode="json") for path in attack_paths]
    hypothesis_paths = []
    inconclusive_paths = []
    refuted_paths = []

    report.extend(["", "## PoC And Evidence", ""])
    if confirmed_paths:
        for path in confirmed_paths:
            report.extend(_format_attack_path(path, facts_by_id, attack_path_models[path["id"]]))
    elif confirmed_findings:
        report.append("No confirmed attack path was recorded. Evidence below is derived from confirmed facts.")
        for fact in confirmed_findings:
            report.extend(_format_fact_evidence(fact, fact_models[fact["id"]]))
    else:
        report.append("No confirmed PoC or evidence chain was recorded.")

    if hypothesis_paths:
        report.extend(["", "## Hypothesized Attack Paths", ""])
        for path in hypothesis_paths:
            report.extend(_format_attack_path(path, facts_by_id, attack_path_models[path["id"]]))

    if inconclusive_paths:
        report.extend(["", "## Inconclusive Attack Paths", ""])
        for path in inconclusive_paths:
            report.extend(_format_attack_path(path, facts_by_id, attack_path_models[path["id"]]))

    if refuted_paths:
        report.extend(["", "## Refuted Attack Paths", ""])
        for path in refuted_paths:
            report.extend(_format_attack_path(path, facts_by_id, attack_path_models[path["id"]]))

    report.extend(["", "## Operator Hints", ""])
    if hints:
        for hint in hints:
            report.append(f"- [{format_export_timestamp(hint['created_at'])}] {hint['creator']}: {hint['content']}")
    else:
        report.append("No operator hints were recorded.")

    failed_logs = [
        log for log in logs
        if bool(log["timed_out"]) or (log["return_code"] is not None and log["return_code"] != 0)
    ]
    report.extend(["", "## Failed Execution Log Details", ""])
    if failed_logs:
        for log in failed_logs:
            report.extend(_format_log_appendix(log))
    else:
        report.append("No failed or timed-out execution logs were recorded.")

    return "\n".join(report).rstrip() + "\n"


def _format_coverage_ledger(items, coverage_models: dict) -> list[str]:
    counts: dict[str, int] = {}
    legacy_counts: dict[str, int] = {}
    family_counts: dict[str, dict[str, int]] = {}
    surface_counts: dict[str, int] = {}
    for item in items:
        model = coverage_models[item["id"]]
        surface_counts[model.surface_class] = surface_counts.get(model.surface_class, 0) + 1
        legacy_status = item["status"] or "untested"
        legacy_counts[legacy_status] = legacy_counts.get(legacy_status, 0) + 1
        execution = item["execution_status"] or "untested"
        outcome = item["outcome"] or "pending"
        state = outcome if execution == "completed" else execution
        counts[state] = counts.get(state, 0) + 1
        family = item["test_family"] or "legacy_or_unclassified"
        family_states = family_counts.setdefault(family, {})
        family_states[state] = family_states.get(state, 0) + 1

    lines = ["Execution/outcome counts:"]
    for status in (
        "untested", "queued", "testing", "blocked", "vulnerable",
        "not_vulnerable", "inconclusive", "not_applicable", "informational",
    ):
        if status in counts:
            lines.append(f"- {status}: {counts[status]}")

    lines.extend(["", "Legacy status counts (compatibility):"])
    for status in (
        "untested", "testing", "confirmed", "not_vulnerable", "inconclusive", "failed", "informational",
    ):
        if status in legacy_counts:
            lines.append(f"- {status}: {legacy_counts[status]}")

    if family_counts:
        lines.extend(["", "Test family summary:"])
        for family in sorted(family_counts):
            states = ", ".join(
                f"{state}={count}" for state, count in sorted(family_counts[family].items())
            )
            lines.append(f"- {family}: {states}")

    lines.extend(["", "Surface classification:"])
    for surface_class, label in (
        ("web", "Web application"),
        ("api", "API"),
        ("support_service", "Support service"),
    ):
        lines.append(f"- {label}: {surface_counts.get(surface_class, 0)}")

    conflicts = [
        (item, result)
        for item in items
        for result in coverage_models[item["id"]].variant_results
        if result.status == "conflict"
    ]
    if conflicts:
        lines.extend(["", "Conflicting coverage evidence:"])
        for item, result in conflicts:
            lines.append(
                f"- {item['id']}/{result.variant}: facts={_inline_list(result.fact_ids)}; "
                f"reason={result.reason}"
            )

    unresolved = [
        item for item in items
        if item["disposition"] != "excluded"
        and (
            item["execution_status"] in ("untested", "queued", "testing", "blocked")
            or item["outcome"] in (None, "inconclusive")
        )
    ]
    if unresolved:
        lines.extend(["", "Required untested or incomplete coverage (blocks real_website completion):"])
        for item in unresolved:
            lines.extend(_format_coverage_item(item, coverage_models[item["id"]]))
    else:
        lines.extend(["", "Required untested or incomplete coverage (blocks real_website completion): none"])

    unresolved_ids = {item["id"] for item in unresolved}
    limited = [
        item for item in items
        if item["id"] not in unresolved_ids
        and (item["execution_status"] == "blocked" or item["outcome"] == "inconclusive")
    ]
    if limited:
        lines.extend(["", "Limited or inconclusive coverage:"])
        for item in limited:
            lines.extend(_format_coverage_item(item, coverage_models[item["id"]]))

    terminal = [
        item for item in items
        if bool(item["required"])
        and item["execution_status"] == "completed"
        and item["outcome"] in ("vulnerable", "not_vulnerable", "informational")
    ]
    if terminal:
        lines.extend(["", "Completed coverage:"])
        for item in terminal:
            lines.extend(_format_coverage_item(item, coverage_models[item["id"]]))

    excluded = [
        item for item in items
        if not bool(item["required"]) or item["outcome"] == "not_applicable"
    ]
    if excluded:
        lines.extend(["", "Optional or not-applicable coverage:"])
        for item in excluded:
            lines.extend(_format_coverage_item(item, coverage_models[item["id"]]))

    return lines


def _format_coverage_item(item, model) -> list[str]:
    where = _coverage_location(item)
    lines = [
        f"- {item['id']} [surface={model.surface_class} execution={item['execution_status']} "
        f"outcome={item['outcome'] or 'pending'}] required={bool(item['required'])} priority={item['priority']} "
        f"family={item['test_family'] or '-'} {where}: {item['description']}"
    ]
    lines.append(
        f"  Trace: intents={_inline_list(model.intent_ids)}; "
        f"facts={_inline_list(model.evidence_fact_ids)}; logs={_inline_list(model.task_log_refs)}"
    )
    for result in model.variant_results:
        verification = f"; verification={result.verification}" if result.verification else ""
        lines.append(
            f"  Variant {result.variant}: {result.status}{verification}; "
            f"facts={_inline_list(result.fact_ids)}; reason={result.reason}"
        )
    lines.append(f"  Next action: {_coverage_next_action(item)}")
    return lines


def _coverage_next_action(item) -> str:
    if not bool(item["required"]):
        return item["applicability_reason"] or "Optional coverage; no completion action is required."
    if item["outcome"] == "informational":
        return "No vulnerability action; this item records completed reconnaissance only."
    if item["outcome"] == "not_applicable":
        return item["applicability_reason"] or "No action unless the surface changes."
    if item["outcome"] == "not_vulnerable":
        return "Retest only when the application or scope changes."
    if item["outcome"] == "vulnerable":
        return "Preserve evidence and include the confirmed result in remediation tracking."
    if item["execution_status"] == "blocked":
        return "Recorded as a failed attempt; retest only when a materially different method or new evidence exists."
    if item["execution_status"] in ("untested", "queued"):
        return "Required work is unresolved; schedule or resume the exact Variant before completion."
    if item["execution_status"] == "testing":
        return "Finish the active attempt or recover it if the worker has stopped."
    return "Recorded as inconclusive; retest only when a materially different method or new evidence exists."


def _coverage_location(item) -> str:
    parts = []
    if item["target"]:
        parts.append(str(item["target"]))
    if item["port"] is not None:
        parts.append(f":{item['port']}")
    if item["method"]:
        parts.append(str(item["method"]))
    if item["path"]:
        parts.append(str(item["path"]))
    if item["param"]:
        parts.append(f"param={item['param']}")
    return " ".join(parts) if parts else "-"


def _report_findings(facts, fact_models: dict) -> list:
    excluded_goal_types = {"attack_surface_map", "explore_seed_deck", "potential_target"}
    findings = []
    for fact in facts:
        if fact["id"] in ("origin", "goal"):
            continue
        goal_type = _row_get(fact, "goal_type")
        if goal_type in excluded_goal_types:
            continue
        if fact_models[fact["id"]].result_class == "informational":
            continue
        findings.append(fact)
    return findings


def _format_scope_policy(scope: dict) -> list[str]:
    lines = []
    for key, label in (
        ("allowed_targets", "Allowed targets"),
        ("blocked_targets", "Blocked targets"),
        ("allowed_ports", "Allowed ports"),
        ("blocked_ports", "Blocked ports"),
        ("allowed_paths", "Allowed paths"),
        ("blocked_paths", "Blocked paths"),
        ("support_ports", "Support service ports"),
    ):
        value = scope.get(key) or []
        lines.append(f"- {label}: {_inline_list(value)}")
    lines.append(f"- Allow subdomains: {bool(scope.get('allow_subdomains', True))}")
    lines.append(f"- Allow domain scan: {bool(scope.get('allow_domain_scan', True))}")
    lines.append(f"- Passive only: {bool(scope.get('passive_only'))}")
    rate_limits = scope.get("rate_limits") or {}
    if rate_limits:
        lines.append(f"- Rate limits: {json.dumps(rate_limits, ensure_ascii=False, sort_keys=True)}")
    return lines


def _format_recon_profile(profile: dict) -> list[str]:
    return [
        f"- Target type: {profile.get('target_type') or 'domain'}",
        f"- Required categories: {_inline_list(profile.get('required_categories') or [])}",
        f"- Optional categories: {_inline_list(profile.get('optional_categories') or [])}",
        f"- Disabled categories: {_inline_list(profile.get('disabled_categories') or [])}",
    ]


def _format_finding(fact, model, *, heading_level: int = 3) -> list[str]:
    description_limit = 4000 if model.result_class == "confirmed" else 1600
    lines = [
        f"{'#' * heading_level} {fact['id']}",
        "",
        _clip_block(fact["description"], description_limit),
        "",
    ]
    meta = []
    meta.append(f"- Classification: {model.surface_class}")
    meta.append(f"- Result class: {model.result_class}")
    for key, label in (
        ("severity", "Severity"),
        ("vuln_type", "Type"),
        ("scope", "Scope"),
        ("status", "Status"),
        ("parent_fact", "Parent"),
        ("verification_of", "Verifies"),
        ("recon_evidence_ref", "Evidence Ref"),
    ):
        value = _row_get(fact, key)
        if value:
            meta.append(f"- {label}: {value}")
    if meta:
        lines.extend(meta)
    fact_status = str(_row_get(fact, "status") or "").casefold()
    severity = str(_row_get(fact, "severity") or "").casefold()
    if fact_status == "verified":
        lines.append("- Verification: independently verified by a separate Intent.")
    elif fact_status == "confirmed" and severity in {"high", "critical"}:
        lines.append("- Verification: pending independent high-risk verification.")
    lines.extend([
        f"- Coverage: {_inline_list(model.coverage_refs)}",
        f"- Intents: {_inline_list(model.intent_refs)}",
        f"- Task logs: {_inline_list(model.task_log_refs)}",
    ])
    if model.result_class == "limited":
        lines.append("- Next action: retry with an alternate method or record an explicit testing limitation.")
    elif model.result_class == "refuted":
        lines.append("- Next action: no further action unless the scope or supporting evidence changes.")
    lines.append("")
    return lines


def _format_attack_path(path, facts_by_id: dict, model) -> list[str]:
    chain = _json_list(path["fact_chain"])
    steps_by_fact = {step.fact_id: step for step in model.steps}
    lines = [
        f"### {path['id']}: {path['name']}",
        "",
        f"- Severity: {path['severity']}",
        f"- Status: {_attack_path_status(path)}",
        f"- Suggested status: {_row_get(path, 'suggested_status') or 'hypothesis'}",
        f"- Derived reason: {_row_get(path, 'status_reason') or 'not calculated'}",
        f"- Chain: {' -> '.join(chain)}",
        f"- Task logs: {_inline_list(model.task_log_refs)}",
        "",
        path["description"],
        "",
        "Evidence chain:",
    ]
    for fact_id in chain:
        fact = facts_by_id.get(fact_id)
        if fact is None:
            lines.append(f"- {fact_id}: missing fact reference")
        else:
            summary = _clip_block(fact["description"].replace("\n", " "), 800)
            step = steps_by_fact.get(fact_id)
            suffix = ""
            if step is not None:
                suffix = (
                    f"; derived={step.derived_status}; coverage={_inline_list(step.coverage_refs)}; "
                    f"reason={step.reason}"
                )
            lines.append(f"- {fact_id} [{_row_get(fact, 'status') or 'pending'}]{suffix}: {summary}")
    lines.append("")
    return lines


def _format_fact_evidence(fact, model) -> list[str]:
    lines = [f"### Evidence: {fact['id']}", "", _clip_block(fact["description"], 4000), ""]
    lines.extend([
        f"- Coverage: {_inline_list(model.coverage_refs)}",
        f"- Intents: {_inline_list(model.intent_refs)}",
        f"- Task logs: {_inline_list(model.task_log_refs)}",
        "",
    ])
    evidence_ref = _row_get(fact, "recon_evidence_ref")
    if evidence_ref:
        lines.extend(["Evidence reference:", "", f"```text\n{evidence_ref}\n```", ""])
    return lines


def _format_log_timeline_item(log) -> str:
    code = "timeout" if bool(log["timed_out"]) else log["return_code"]
    return (
        f"- [{format_export_timestamp(log['created_at'])}] {log['task_type']}/{log['phase']} "
        f"worker={log['worker_name']} intent={log['intent_id'] or '-'} code={code} "
        f"duration_ms={log['duration_ms'] if log['duration_ms'] is not None else '-'}"
    )


def _format_log_input_summary(log) -> list[str]:
    return [
        f"### {log['id']} - {log['task_type']}/{log['phase']}",
        "",
        f"- Intent: {log['intent_id'] or '-'}",
        f"- Return code: {log['return_code']}",
        f"- Timed out: {bool(log['timed_out'])}",
        "",
        "Input:",
        "",
        f"```text\n{_operation_input(log['stdin'])}\n```",
        "",
    ]


def _format_log_appendix(log) -> list[str]:
    title = f"### {log['id']} - {log['task_type']}/{log['phase']}"
    lines = [
        title,
        "",
        f"- Worker: {log['worker_name']}",
        f"- Intent: {log['intent_id'] or '-'}",
        f"- Return code: {log['return_code']}",
        f"- Timed out: {bool(log['timed_out'])}",
        f"- Duration ms: {log['duration_ms'] if log['duration_ms'] is not None else '-'}",
        f"- Created at: {format_export_timestamp(log['created_at'])}",
        "",
        "Input:",
        "",
        f"```text\n{_operation_input(log['stdin'])}\n```",
        "",
        "stdout:",
        "",
        f"```text\n{_clip_block(log['stdout'])}\n```",
        "",
        "stderr:",
        "",
        f"```text\n{_clip_block(log['stderr'])}\n```",
        "",
    ]
    return lines


def _inline_list(value: list) -> str:
    return ", ".join(str(item) for item in value) if value else "not configured"


def _attack_path_status(path) -> str:
    status = _row_get(path, "status")
    return status if status in ("hypothesis", "confirmed", "inconclusive", "refuted") else "hypothesis"


def _clip_block(value: str | None, limit: int = 4000) -> str:
    if not value:
        return "(empty)"
    if len(value) <= limit:
        return value
    omitted = len(value) - limit
    return value[:limit] + f"\n... truncated {omitted} characters ..."


def _operation_input(value: str | None) -> str:
    if not value:
        return "(empty)"
    prefixes = (
        "operation:", "intent_description:", "target:", "port:", "surface_type:",
        "action_kind:", "priority:", "suggested_tools:", "timeout_seconds:",
    )
    selected = [
        line.strip()
        for line in value.splitlines()
        if line.strip().casefold().startswith(prefixes)
    ]
    if selected:
        return _clip_block("\n".join(selected), 900)

    prompt_marker = "prompt:"
    marker_at = value.casefold().find(prompt_marker)
    if marker_at >= 0:
        legacy_operation = value[marker_at + len(prompt_marker):].strip()
        return f"operation: {_clip_block(legacy_operation, 350)}"
    return _clip_block(value, 350)


@router.get("/projects/{project_id}/export")
def export_project(project_id: str, format: str = "yaml"):
    if format not in ("yaml", "timeline", "report"):
        raise HTTPException(400, "Supported formats: yaml, timeline, report")

    with get_conn() as conn:
        if format == "timeline":
            text = _export_timeline(conn, project_id)
        elif format == "report":
            text = _export_report(conn, project_id)
        else:
            text = _export_yaml(conn, project_id)

        return Response(content=text, media_type="text/plain")

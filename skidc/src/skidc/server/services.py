from __future__ import annotations

import sqlite3
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from fastapi import HTTPException

from skidc.planning import behavior_identity
from skidc.server.models import (
    AttackPath,
    AttackPathStep,
    CompletionBlocker,
    CoverageItem,
    Fact,
    CoverageVariantResult,
    Hypothesis,
    Intent,
    ProjectMeta,
    ProjectReason,
    ReconProfile,
    UpsertSurfaceInventoryRequest,
    ScopePolicy,
    SurfaceInventoryItem,
)


ACTIVE_ACTION_KEYWORDS = (
    "attack",
    "brute",
    "delete",
    "exploit",
    "fuzz",
    "login",
    "mutate",
    "post",
    "spray",
    "write",
)
DOMAIN_SCAN_ACTION_KEYWORDS = ("dns", "domain", "subdomain", "zone")

_RECON_CATEGORY_HINTS: dict[str, tuple[str, ...]] = {
    "port_scan": ("port_scan", "port", "service", "nmap", "naabu", "tcp", "udp"),
    "subdomain": ("subdomain", "dns", "subfinder", "amass", "cname"),
    "directory": ("directory", "dir", "path", "endpoint", "ffuf", "gobuster", "dirsearch"),
    "asset": ("asset", "crawl", "url", "javascript", "katana"),
    "android_app": ("android_app", "apk", "package", "manifest"),
    "android_ui": ("android_ui", "ui", "screen", "activity"),
    "mobile_api": ("mobile_api", "api_call", "network"),
    "android_storage": ("android_storage", "storage", "sqlite", "keystore"),
}


@dataclass(slots=True)
class ReconGateResult:
    ready: bool
    required_categories: list[str]
    executed_categories: list[str]
    missing_categories: list[str]
    open_recon_intents: list[str]


def recon_category_from_intent(row: sqlite3.Row) -> str | None:
    """Derive Recon identity from structured Intent fields, never Fact prose."""
    values = (
        _row_get(row, "action_kind"),
        _row_get(row, "test_variant"),
        _row_get(row, "surface_type"),
        _row_get(row, "suggested_tools"),
    )
    haystack = " ".join(str(value or "") for value in values).casefold()
    for category, hints in _RECON_CATEGORY_HINTS.items():
        if category in haystack or any(hint in haystack for hint in hints):
            return category
    return None


def derive_recon_fact_fields(
    intent: sqlite3.Row,
    *,
    supplied_category: str | None,
    supplied_executed: bool | None,
    supplied_found_results: bool | None,
    observed_surface_count: int = 0,
) -> tuple[str | None, bool | None, bool | None]:
    """Return canonical Recon fields for an Intent conclusion."""
    derived_category = recon_category_from_intent(intent)
    category = derived_category or (supplied_category.strip() if supplied_category else None)
    if category not in _RECON_CATEGORY_HINTS:
        return category, supplied_executed, supplied_found_results
    executed = True if supplied_executed is None else bool(supplied_executed)
    found_results = (
        bool(supplied_found_results)
        if supplied_found_results is not None
        else observed_surface_count > 0
    )
    return category, executed, found_results



_LEGACY_RECON_PATTERNS: dict[str, re.Pattern[str]] = {
    "port_scan": re.compile(r"\b(?:port[ _-]?scan|nmap|naabu|service enumeration)\b", re.I),
    "subdomain": re.compile(r"\b(?:subdomain|subfinder|amass|dns enumeration)\b", re.I),
    "directory": re.compile(r"\b(?:directory|dirsearch|gobuster|ffuf|path enumeration)\b", re.I),
    "asset": re.compile(r"\b(?:asset|crawl(?:er|ing)?|katana|javascript discovery)\b", re.I),
}


def backfill_legacy_recon_facts(conn: sqlite3.Connection, project_id: str) -> int:
    """Persist canonical Recon fields for legacy concluded Intent/Fact pairs.

    Prose matching is deliberately isolated here as a one-time compatibility
    migration. Runtime gates continue to consume only the persisted fields.
    """
    rows = conn.execute(
        """SELECT f.id AS fact_id, f.description AS fact_description,
                  f.recon_category, f.recon_executed, f.recon_found_results,
                  i.description AS intent_description, i.action_kind,
                  i.test_variant, i.surface_type, i.suggested_tools
        FROM facts f
        JOIN intents i ON i.project_id = f.project_id AND i.to_fact_id = f.id
        WHERE f.project_id = ?
          AND (f.recon_category IS NULL OR f.recon_executed IS NULL)
        ORDER BY f.id, i.id""",
        (project_id,),
    ).fetchall()
    updated = 0
    for row in rows:
        category = recon_category_from_intent(row)
        if category is None:
            prose = f"{row['intent_description'] or ''} {row['fact_description'] or ''}"
            matches = [
                name for name, pattern in _LEGACY_RECON_PATTERNS.items()
                if pattern.search(prose)
            ]
            category = matches[0] if len(matches) == 1 else None
        if category is None:
            continue
        observed_surface = conn.execute(
            """SELECT 1 FROM surface_inventory
            WHERE project_id = ? AND source_fact_id = ? LIMIT 1""",
            (project_id, row["fact_id"]),
        ).fetchone()
        found_results = (
            bool(row["recon_found_results"])
            if row["recon_found_results"] is not None
            else observed_surface is not None
        )
        conn.execute(
            """UPDATE facts
            SET recon_category = COALESCE(recon_category, ?),
                recon_executed = COALESCE(recon_executed, 1),
                recon_found_results = COALESCE(recon_found_results, ?)
            WHERE project_id = ? AND id = ?""",
            (category, int(found_results), project_id, row["fact_id"]),
        )
        updated += 1
    return updated


def recon_gate_result(
    conn: sqlite3.Connection,
    project_id: str,
    profile: ReconProfile,
) -> ReconGateResult:
    disabled = {value.strip() for value in profile.disabled_categories if value.strip()}
    required = []
    for value in profile.required_categories:
        category = value.strip()
        if category and category not in disabled and category not in required:
            required.append(category)
    executed = {
        str(row["recon_category"]).strip()
        for row in conn.execute(
            """SELECT recon_category FROM facts
            WHERE project_id = ? AND recon_category IS NOT NULL AND recon_executed = 1""",
            (project_id,),
        ).fetchall()
        if str(row["recon_category"] or "").strip()
    }
    open_recon = []
    for row in conn.execute(
        """SELECT * FROM intents
        WHERE project_id = ? AND to_fact_id IS NULL AND status = 'open'
        ORDER BY created_at, id""",
        (project_id,),
    ).fetchall():
        if recon_category_from_intent(row) in required:
            open_recon.append(row["id"])
    missing = [category for category in required if category not in executed]
    return ReconGateResult(
        ready=not missing and not open_recon,
        required_categories=required,
        executed_categories=[category for category in required if category in executed],
        missing_categories=missing,
        open_recon_intents=open_recon,
    )


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_after_seconds(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def reason_state_fingerprint(conn: sqlite3.Connection, project_id: str) -> str:
    """Hash semantic graph state; duplicate Hint rows do not create new work."""
    project = conn.execute(
        "SELECT phase, mode, scope_policy, recon_profile FROM projects WHERE id = ?",
        (project_id,),
    ).fetchone()
    payload = {
        "project": dict(project) if project is not None else {},
        "facts": [dict(row) for row in conn.execute(
            """SELECT id, description, status, recon_category, recon_executed,
                      recon_found_results, verification_of
               FROM facts WHERE project_id = ? ORDER BY id""",
            (project_id,),
        ).fetchall()],
        "hints": [list(row) for row in conn.execute(
            "SELECT DISTINCT content, creator FROM hints WHERE project_id = ? ORDER BY content, creator",
            (project_id,),
        ).fetchall()],
        "intents": [dict(row) for row in conn.execute(
            """SELECT id, to_fact_id, status, action_kind, test_variant
               FROM intents WHERE project_id = ? ORDER BY id""",
            (project_id,),
        ).fetchall()],
        "intent_sources": [dict(row) for row in conn.execute(
            """SELECT intent_id, fact_id
               FROM intent_sources WHERE project_id = ? ORDER BY intent_id, fact_id""",
            (project_id,),
        ).fetchall()],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def validate_coverage_exists(conn: sqlite3.Connection, project_id: str, coverage_ids: list[str]) -> None:
    for coverage_id in coverage_ids:
        row = conn.execute(
            "SELECT 1 FROM coverage_items WHERE id = ? AND project_id = ?",
            (coverage_id, project_id),
        ).fetchone()
        if row is None:
            raise HTTPException(404, f"Coverage item {coverage_id} not found")

def coverage_work_key(
    coverage: sqlite3.Row,
    variant: str,
    action_kind: str | None = None,
) -> str:
    """Return a stable identity for one exact Surface/Coverage/Variant job."""
    work_role = "verification" if "verif" in str(action_kind or "").casefold() else "primary"
    identity = {
        "surface_fingerprint": str(_row_get(coverage, "surface_fingerprint") or "").casefold(),
        "target": str(coverage["target"] or "").casefold(),
        "port": coverage["port"],
        "method": str(coverage["method"] or "").upper(),
        "path": str(coverage["path"] or ""),
        "surface_group": str(coverage["surface_group"] or "").casefold(),
        "test_family": str(coverage["test_family"] or "").casefold(),
        "auth_context": str(coverage["auth_context"] or "anonymous").casefold(),
        "variant": variant.strip().casefold(),
        "work_role": work_role,
    }
    digest = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:32]
    return f"coverage:{digest}"



def bind_coverage_intent(
    conn: sqlite3.Connection,
    project_id: str,
    coverage_id: str,
    intent_id: str,
    *,
    created_at: str | None = None,
) -> None:
    project = conn.execute("SELECT mode FROM projects WHERE id = ?", (project_id,)).fetchone()
    coverage = conn.execute(
        "SELECT test_variants, execution_status, outcome FROM coverage_items WHERE project_id = ? AND id = ?",
        (project_id, coverage_id),
    ).fetchone()
    intent = conn.execute(
        "SELECT status, test_variant FROM intents WHERE project_id = ? AND id = ?",
        (project_id, intent_id),
    ).fetchone()
    if project is not None and project["mode"] == "real_website":
        exact_existing = conn.execute(
            "SELECT 1 FROM coverage_intents WHERE project_id = ? AND intent_id = ? AND coverage_id = ?",
            (project_id, intent_id, coverage_id),
        ).fetchone()
        existing = conn.execute(
            "SELECT coverage_id FROM coverage_intents WHERE project_id = ? AND intent_id = ? AND coverage_id <> ?",
            (project_id, intent_id, coverage_id),
        ).fetchone()
        if exact_existing is None and existing is not None:
            raise HTTPException(409, "A real_website Intent may bind at most one Coverage item")
        variants = _normalized_variants(_json_list(coverage["test_variants"])) if coverage else []
        intent_variant = str(intent["test_variant"] or "").strip() if intent else ""
        if exact_existing is None and variants and intent_variant and intent_variant.casefold() not in {
            variant.casefold() for variant in variants
        }:
            raise HTTPException(
                409, "Intent test_variant is not declared by the Coverage item"
            )
    now = created_at or utcnow()
    conn.execute(
        """
        INSERT OR IGNORE INTO coverage_intents (project_id, coverage_id, intent_id, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (project_id, coverage_id, intent_id, now),
    )
    queued = intent is not None and intent["status"] == "open"
    should_requeue = queued and coverage is not None and (
        coverage["execution_status"] in {"untested", "blocked"}
        or (
            coverage["execution_status"] == "completed"
            and coverage["outcome"] == "inconclusive"
        )
    )
    conn.execute(
        """
        UPDATE coverage_items
        SET intent_id = COALESCE(intent_id, ?),
            execution_status = CASE
                WHEN ? THEN 'queued'
                ELSE execution_status
            END,
            status = CASE
                WHEN ? THEN 'untested'
                ELSE status
            END,
            outcome = CASE
                WHEN ? THEN NULL
                ELSE outcome
            END,
            updated_at = ?
        WHERE id = ? AND project_id = ?
          AND (
              intent_id IS NULL
              OR ?
          )
        """,
        (
            intent_id, int(should_requeue), int(should_requeue), int(should_requeue),
            now, coverage_id, project_id, int(should_requeue),
        ),
    )


def link_coverage_evidence(
    conn: sqlite3.Connection,
    project_id: str,
    coverage_id: str,
    fact_id: str,
    relation: str,
    *,
    created_at: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO coverage_evidence (
            project_id, coverage_id, fact_id, relation, created_at
        ) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (project_id, coverage_id, fact_id)
        DO UPDATE SET relation = excluded.relation
        WHERE coverage_evidence.relation <> excluded.relation
        """,
        (project_id, coverage_id, fact_id, relation, created_at or utcnow()),
    )


def _fact_values(row: sqlite3.Row, *, compact: bool = False, include_detail: bool = True) -> dict:
    values = dict(row)
    values.pop("project_id", None)
    summary = str(values.get("summary") or values.get("description") or "")[:320]
    values["summary"] = summary
    values["subject"] = _json_dict(values.get("subject"))
    values["data"] = _json_dict(values.get("data"))
    values["parent_fact_ids"] = _json_list(values.get("parent_fact_ids"))
    values["evidence_refs"] = _json_list(values.get("evidence_refs"))
    values["schema_version"] = int(values.get("schema_version") or 1)
    values["kind"] = str(values.get("kind") or "legacy_text")
    if compact:
        values["description"] = summary
        if not include_detail:
            values["subject"] = {}
            values["data"] = {}
    return values



def fact_to_model(conn: sqlite3.Connection, row: sqlite3.Row, project_id: str) -> Fact:
    coverage_rows = conn.execute(
        """
        SELECT DISTINCT c.*
        FROM coverage_items c
        JOIN coverage_evidence ce
          ON ce.project_id = c.project_id AND ce.coverage_id = c.id
        WHERE c.project_id = ?
          AND ce.fact_id = ?
        ORDER BY c.id
        """,
        (project_id, row["id"]),
    ).fetchall()
    intent_refs = _fact_intent_refs(conn, project_id, row["id"], coverage_rows)
    values = _fact_values(row)
    return Fact(
        **values,
        coverage_refs=[item["id"] for item in coverage_rows],
        surface_class=_fact_surface_class(conn, project_id, row, coverage_rows),
        result_class=_fact_result_class(conn, project_id, row, coverage_rows),
        intent_refs=intent_refs,
        task_log_refs=_task_log_refs_for_intents(conn, project_id, intent_refs),
    )



def fact_to_dispatch_model(row: sqlite3.Row, *, include_detail: bool = False) -> Fact:
    """Return a compact Fact index with selected structured details."""
    return Fact(**_fact_values(row, compact=True, include_detail=include_detail))


def coverage_item_to_model(conn: sqlite3.Connection, row: sqlite3.Row, project_id: str) -> CoverageItem:
    intent_rows = conn.execute(
        """
        SELECT intent_id FROM coverage_intents
        WHERE project_id = ? AND coverage_id = ?
        ORDER BY created_at, intent_id
        """,
        (project_id, row["id"]),
    ).fetchall()
    evidence_rows = conn.execute(
        """
        SELECT DISTINCT fact_id FROM coverage_evidence
        WHERE project_id = ? AND coverage_id = ?
        ORDER BY fact_id
        """,
        (project_id, row["id"]),
    ).fetchall()
    values = dict(row)
    values.pop("project_id", None)
    values["test_variants"] = _json_list(values.get("test_variants"))
    values["roles"] = _json_list(values.get("roles"))
    values["standard_refs"] = _json_list(values.get("standard_refs"))
    values["required"] = bool(values.get("required", 1))
    intent_ids = [item["intent_id"] for item in intent_rows]
    return CoverageItem(
        **values,
        intent_ids=intent_ids,
        evidence_fact_ids=[item["fact_id"] for item in evidence_rows],
        surface_class=_coverage_surface_class(row),
        variant_results=coverage_variant_results(conn, project_id, row),
        task_log_refs=_task_log_refs_for_intents(conn, project_id, intent_ids),
    )


def build_coverage_items(
    conn: sqlite3.Connection,
    project_id: str,
    rows: list[sqlite3.Row] | None = None,
) -> list[CoverageItem]:
    """Build all Coverage models with a fixed set of relationship queries."""
    coverage_rows = rows if rows is not None else conn.execute(
        "SELECT * FROM coverage_items WHERE project_id = ? ORDER BY created_at, id",
        (project_id,),
    ).fetchall()
    intent_links: dict[str, list[sqlite3.Row]] = {}
    for row in conn.execute(
        """SELECT ci.coverage_id AS bound_coverage_id, i.*
        FROM coverage_intents ci
        JOIN intents i ON i.project_id = ci.project_id AND i.id = ci.intent_id
        WHERE ci.project_id = ? ORDER BY ci.created_at, i.id""",
        (project_id,),
    ).fetchall():
        intent_links.setdefault(row["bound_coverage_id"], []).append(row)
    evidence_links: dict[str, list[sqlite3.Row]] = {}
    for row in conn.execute(
        """SELECT ce.coverage_id AS bound_coverage_id, ce.relation,
                  f.*, i.id AS source_intent_id,
                  i.test_variant AS intent_test_variant,
                  i.action_kind AS intent_action_kind
        FROM coverage_evidence ce
        JOIN facts f ON f.project_id = ce.project_id AND f.id = ce.fact_id
        LEFT JOIN intents i ON i.project_id = f.project_id AND i.to_fact_id = f.id
        WHERE ce.project_id = ? ORDER BY ce.coverage_id, f.id, i.id""",
        (project_id,),
    ).fetchall():
        evidence_links.setdefault(row["bound_coverage_id"], []).append(row)
    log_ids_by_intent: dict[str, list[str]] = {}
    for row in conn.execute(
        """SELECT id, intent_id FROM task_logs
        WHERE project_id = ? AND intent_id IS NOT NULL ORDER BY created_at, id""",
        (project_id,),
    ).fetchall():
        log_ids_by_intent.setdefault(row["intent_id"], []).append(row["id"])
    models: list[CoverageItem] = []
    for coverage in coverage_rows:
        bound_intents = intent_links.get(coverage["id"], [])
        evidence = evidence_links.get(coverage["id"], [])
        intent_ids = [row["id"] for row in bound_intents]
        task_log_refs: list[str] = []
        for intent_id in intent_ids:
            for log_id in log_ids_by_intent.get(intent_id, []):
                if log_id not in task_log_refs:
                    task_log_refs.append(log_id)
        values = dict(coverage)
        values.pop("project_id", None)
        values["test_variants"] = _json_list(values.get("test_variants"))
        values["roles"] = _json_list(values.get("roles"))
        values["standard_refs"] = _json_list(values.get("standard_refs"))
        values["required"] = bool(values.get("required", 1))
        models.append(CoverageItem(
            **values,
            intent_ids=intent_ids,
            evidence_fact_ids=sorted({row["id"] for row in evidence}),
            surface_class=_coverage_surface_class(coverage),
            variant_results=coverage_variant_results(
                conn, project_id, coverage,
                evidence_rows=evidence,
                bound_intent_rows=bound_intents,
            ),
            task_log_refs=task_log_refs,
        ))
    return models


def _coverage_surface_class(row: sqlite3.Row) -> str:
    family = str(_row_get(row, "test_family") or "").casefold()
    group = str(_row_get(row, "surface_group") or "").casefold()
    if family == "support_service" or group.startswith("support:"):
        return "support_service"
    if family == "api_behavior" or group.startswith("api:"):
        return "api"
    return "web"


def _fact_surface_class(
    conn: sqlite3.Connection,
    project_id: str,
    fact: sqlite3.Row,
    coverage_rows: list[sqlite3.Row],
) -> str:
    classes = {_coverage_surface_class(row) for row in coverage_rows}
    if "support_service" in classes:
        return "support_service"
    if "api" in classes:
        return "api"
    project = conn.execute("SELECT scope_policy, recon_profile FROM projects WHERE id = ?", (project_id,)).fetchone()
    scope_policy = _json_dict(project["scope_policy"] if project else None)
    support_ports = [int(port) for port in scope_policy.get("support_ports", []) if str(port).isdigit()]
    fact_text = " ".join(
        str(value or "")
        for value in (fact["description"], fact["scope"], fact["recon_target"], fact["vuln_type"])
    ).casefold()
    for port in support_ports:
        if re.search(rf"(?<!\d){port}(?:/tcp)?(?!\d)", fact_text):
            return "support_service"
    api_tokens = ("/api/", "graphql", "rest api", "bola", "bfla", "mass_assignment")
    if any(token in fact_text for token in api_tokens):
        return "api"
    if coverage_rows or fact["vuln_type"] or fact["severity"]:
        return "web"
    return "unclassified"


def _fact_result_class(
    conn: sqlite3.Connection,
    project_id: str,
    fact: sqlite3.Row,
    coverage_rows: list[sqlite3.Row],
) -> str:
    status = str(fact["status"] or "").casefold()
    if status in {"refuted", "false_positive", "not_vulnerable"}:
        return "refuted"
    # Direct failed/inconclusive Facts are still reportable test results even
    # when they have no vulnerability metadata or source Intent.
    if status in {"failed", "inconclusive"}:
        return "limited"
    is_finding = (
        bool(fact["vuln_type"] or fact["severity"])
        or _fact_has_security_intent(conn, project_id, fact["id"])
        or any(_coverage_is_security_check(row) for row in coverage_rows)
    )
    if not is_finding:
        return "informational"
    if status in {"failed", "inconclusive"}:
        return "limited"
    if status in {"confirmed", "verified"}:
        return "confirmed"
    if any(
        row["execution_status"] == "blocked" or row["outcome"] == "inconclusive"
        for row in coverage_rows
    ):
        return "limited"
    return "limited"


def _fact_has_security_intent(
    conn: sqlite3.Connection,
    project_id: str,
    fact_id: str,
) -> bool:
    rows = conn.execute(
        """
        SELECT action_kind
        FROM intents
        WHERE project_id = ? AND to_fact_id = ?
        """,
        (project_id, fact_id),
    ).fetchall()
    recon_markers = (
        "recon", "discover", "enumerat", "fingerprint", "crawl", "asset", "directory", "port_scan",
    )
    for row in rows:
        action_kind = str(row["action_kind"] or "").strip().casefold()
        if action_kind and not any(marker in action_kind for marker in recon_markers):
            return True
    return False


def _fact_intent_refs(
    conn: sqlite3.Connection,
    project_id: str,
    fact_id: str,
    coverage_rows: list[sqlite3.Row],
) -> list[str]:
    refs = [
        row["id"] for row in conn.execute(
            "SELECT id FROM intents WHERE project_id = ? AND to_fact_id = ? ORDER BY created_at, id",
            (project_id, fact_id),
        ).fetchall()
    ]
    coverage_ids = {row["id"] for row in coverage_rows}
    if coverage_ids:
        for row in conn.execute(
            "SELECT coverage_id, intent_id FROM coverage_intents WHERE project_id = ? ORDER BY created_at, intent_id",
            (project_id,),
        ).fetchall():
            if row["coverage_id"] in coverage_ids and row["intent_id"] not in refs:
                refs.append(row["intent_id"])
    return refs


def _task_log_refs_for_intents(
    conn: sqlite3.Connection,
    project_id: str,
    intent_ids: list[str],
) -> list[str]:
    intent_set = set(intent_ids)
    if not intent_set:
        return []
    return [
        row["id"] for row in conn.execute(
            "SELECT id, intent_id FROM task_logs WHERE project_id = ? ORDER BY created_at, id",
            (project_id,),
        ).fetchall()
        if row["intent_id"] in intent_set
    ]


def _reason_task_log_refs(conn: sqlite3.Connection, project_id: str) -> list[str]:
    return [
        row["id"] for row in conn.execute(
            """
            SELECT id FROM task_logs
            WHERE project_id = ? AND task_type = 'reason'
            ORDER BY created_at DESC, id DESC
            LIMIT 10
            """,
            (project_id,),
        ).fetchall()
    ]


def surface_inventory_to_model(row: sqlite3.Row) -> SurfaceInventoryItem:
    values = dict(row)
    values.pop("project_id", None)
    values["params"] = _json_list(values.get("params"))
    values["roles"] = _json_list(values.get("roles"))
    values["traits"] = _json_dict(values.get("traits"))
    values["capabilities"] = _json_list(values.get("capabilities"))
    values["evidence_fact_ids"] = _json_list(values.get("evidence_fact_ids"))
    return SurfaceInventoryItem(**values)


def hypothesis_to_model(row: sqlite3.Row) -> Hypothesis:
    values = dict(row)
    values.pop("project_id", None)
    values["trigger_fact_ids"] = _json_list(values.get("trigger_fact_ids"))
    values["required"] = bool(values.get("required", 1))
    return Hypothesis(**values)


def build_hypotheses(conn: sqlite3.Connection, project_id: str) -> list[Hypothesis]:
    rows = conn.execute(
        "SELECT * FROM hypotheses WHERE project_id = ? ORDER BY score DESC, created_at, id",
        (project_id,),
    ).fetchall()
    return [hypothesis_to_model(row) for row in rows]


def attack_path_signature(fact_chain: list[str]) -> str:
    normalized: list[str] = []
    for value in fact_chain:
        fact_id = value.strip()
        if fact_id and fact_id not in normalized:
            normalized.append(fact_id)
    payload = json.dumps(normalized, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode()).hexdigest()[:24]


def validate_completion_source_integrity(
    conn: sqlite3.Connection,
    project_id: str,
    fact_ids: list[str],
) -> None:
    """Require real-website completion sources to be terminal Facts with one producer."""
    project = get_project_or_404(conn, project_id)
    if _row_get(project, "mode") != "real_website":
        return
    for fact_id in fact_ids:
        # origin may anchor a conclusive no-finding/limited assessment, but it
        # can never produce an attack path because it is not verified evidence.
        if fact_id == "origin":
            continue
        if fact_id == "goal":
            raise HTTPException(
                409,
                detail={
                    "code": "invalid_completion_source",
                    "fact_id": fact_id,
                    "message": "goal cannot be used as completion evidence.",
                },
            )
        fact = conn.execute(
            "SELECT status FROM facts WHERE project_id = ? AND id = ?",
            (project_id, fact_id),
        ).fetchone()
        status = str(fact["status"] or "").strip().casefold() if fact is not None else ""
        if not status or status in {"pending", "open", "candidate", "queued", "testing", "running"}:
            raise HTTPException(
                409,
                detail={
                    "code": "invalid_completion_source",
                    "fact_id": fact_id,
                    "message": "Completion sources must be terminal Facts, not planning or pending records.",
                },
            )
        producers = conn.execute(
            """SELECT id FROM intents
               WHERE project_id = ? AND to_fact_id = ?
                 AND status = 'concluded' AND concluded_at IS NOT NULL
               ORDER BY created_at, id""",
            (project_id, fact_id),
        ).fetchall()
        if len(producers) != 1:
            raise HTTPException(
                409,
                detail={
                    "code": "invalid_completion_source",
                    "fact_id": fact_id,
                    "message": "Each completion source must have exactly one concluded producer Intent.",
                    "producer_intents": [row["id"] for row in producers],
                },
            )


def _trace_concluded_fact(
    conn: sqlite3.Connection,
    project_id: str,
    fact_id: str,
    fact_chain: list[str],
    intent_refs: list[str],
    visiting: set[str],
) -> None:
    if fact_id in visiting:
        raise HTTPException(409, "Fact鈥揑ntent graph contains a cycle")
    if fact_id in fact_chain:
        return
    visiting.add(fact_id)
    producers = conn.execute(
        """SELECT * FROM intents
           WHERE project_id = ? AND to_fact_id = ?
             AND status = 'concluded' AND concluded_at IS NOT NULL
           ORDER BY created_at, id""",
        (project_id, fact_id),
    ).fetchall()
    for producer in producers:
        sources = conn.execute(
            """SELECT fact_id FROM intent_sources
               WHERE project_id = ? AND intent_id = ? ORDER BY rowid""",
            (project_id, producer["id"]),
        ).fetchall()
        for source in sources:
            if source["fact_id"] != "goal":
                _trace_concluded_fact(
                    conn,
                    project_id,
                    source["fact_id"],
                    fact_chain,
                    intent_refs,
                    visiting,
                )
        if producer["id"] not in intent_refs:
            intent_refs.append(producer["id"])
    visiting.remove(fact_id)
    if fact_id not in fact_chain:
        fact_chain.append(fact_id)


def build_completed_attack_paths(
    conn: sqlite3.Connection,
    project_id: str,
) -> list[AttackPath]:
    """Project verified goal-reaching causal subgraphs; never read legacy path rows."""
    project = get_project_or_404(conn, project_id)
    if project["status"] != "completed":
        return []
    completion_rows = conn.execute(
        """SELECT * FROM intents
           WHERE project_id = ? AND to_fact_id = 'goal'
             AND status = 'concluded' AND concluded_at IS NOT NULL
           ORDER BY created_at, id""",
        (project_id,),
    ).fetchall()
    if len(completion_rows) != 1:
        return []
    completion = completion_rows[0]
    source_rows = conn.execute(
        """SELECT fact_id FROM intent_sources
           WHERE project_id = ? AND intent_id = ? ORDER BY rowid""",
        (project_id, completion["id"]),
    ).fetchall()
    eligible_source_ids: list[str] = []
    for source in source_rows:
        candidate = conn.execute(
            "SELECT * FROM facts WHERE project_id = ? AND id = ?",
            (project_id, source["fact_id"]),
        ).fetchone()
        if (
            candidate is not None
            and str(candidate["status"] or "").casefold() in {"confirmed", "verified"}
            and fact_to_model(conn, candidate, project_id).result_class == "confirmed"
        ):
            eligible_source_ids.append(source["fact_id"])

    paths: list[AttackPath] = []
    for source in source_rows:
        source_id = source["fact_id"]
        if source_id not in eligible_source_ids:
            continue
        source_is_ancestor = False
        for other_source_id in eligible_source_ids:
            if other_source_id == source_id:
                continue
            other_chain: list[str] = []
            other_intents: list[str] = []
            _trace_concluded_fact(
                conn,
                project_id,
                other_source_id,
                other_chain,
                other_intents,
                set(),
            )
            if source_id in other_chain:
                source_is_ancestor = True
                break
        if source_is_ancestor:
            continue
        fact = conn.execute(
            "SELECT * FROM facts WHERE project_id = ? AND id = ?",
            (project_id, source_id),
        ).fetchone()
        if fact is None or str(fact["status"] or "").casefold() not in {"confirmed", "verified"}:
            continue
        fact_model = fact_to_model(conn, fact, project_id)
        if fact_model.result_class != "confirmed":
            continue
        fact_chain: list[str] = []
        intent_refs: list[str] = []
        _trace_concluded_fact(
            conn,
            project_id,
            source_id,
            fact_chain,
            intent_refs,
            set(),
        )
        if not intent_refs:
            continue
        intent_refs.append(completion["id"])
        if "goal" not in fact_chain:
            fact_chain.append("goal")
        steps: list[AttackPathStep] = []
        for order, step_fact_id in enumerate(fact_chain):
            step_fact = conn.execute(
                "SELECT * FROM facts WHERE project_id = ? AND id = ?",
                (project_id, step_fact_id),
            ).fetchone()
            if step_fact is None:
                continue
            step_model = fact_to_model(conn, step_fact, project_id)
            if step_fact_id == "goal":
                reason = f"Reached by concluded completion Intent {completion['id']}"
            else:
                producers = conn.execute(
                    """SELECT id FROM intents
                       WHERE project_id = ? AND to_fact_id = ?
                         AND status = 'concluded' AND concluded_at IS NOT NULL
                       ORDER BY created_at, id""",
                    (project_id, step_fact_id),
                ).fetchall()
                reason = (
                    "Produced by concluded Intent(s): " + ", ".join(row["id"] for row in producers)
                    if producers
                    else "Root Fact referenced by the concluded causal graph"
                )
            steps.append(
                AttackPathStep(
                    fact_id=step_fact_id,
                    required=step_fact_id != "origin",
                    order=order,
                    fact_status=step_fact["status"],
                    derived_status="confirmed",
                    reason=reason,
                    coverage_refs=step_model.coverage_refs,
                )
            )
        signature_payload = json.dumps(
            {
                "completion_intent": completion["id"],
                "terminal_fact": source_id,
                "intent_refs": intent_refs,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        signature = hashlib.sha256(signature_payload.encode()).hexdigest()[:24]
        created_at = completion["concluded_at"] or completion["created_at"]
        title = str(fact["summary"] or fact["description"] or source_id).strip()
        paths.append(
            AttackPath(
                id=f"goal-{completion['id']}-{source_id}",
                name=title[:160],
                fact_chain=fact_chain,
                description=(
                    f"{completion['description']}\n"
                    f"Terminal verified Fact {source_id}: {fact['description']}"
                ),
                severity=str(fact["severity"] or "medium"),
                status="confirmed",
                suggested_status="confirmed",
                status_reason=(
                    f"Derived from {len(intent_refs)} concluded Intent edge(s), "
                    f"ending at goal through {completion['id']}."
                ),
                signature=signature,
                steps=steps,
                intent_refs=intent_refs,
                task_log_refs=_task_log_refs_for_intents(conn, project_id, intent_refs),
                derived_from_goal=True,
                created_at=created_at,
                updated_at=created_at,
            )
        )
    return paths

def ensure_attack_path_steps(
    conn: sqlite3.Connection,
    project_id: str,
    path_id: str,
    fact_chain: list[str],
) -> None:
    for order, fact_id in enumerate(fact_chain):
        conn.execute(
            """
            INSERT OR IGNORE INTO attack_path_steps (
                project_id, path_id, fact_id, required, step_order
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (project_id, path_id, fact_id, int(fact_id not in {"origin", "goal"}), order),
        )


def reconcile_attack_path(conn: sqlite3.Connection, project_id: str, path_id: str) -> sqlite3.Row:
    path = conn.execute(
        "SELECT * FROM attack_paths WHERE project_id = ? AND id = ?",
        (project_id, path_id),
    ).fetchone()
    if path is None:
        raise HTTPException(404, "Attack path not found")
    ensure_attack_path_steps(conn, project_id, path_id, _json_list(path["fact_chain"]))
    steps = _attack_path_step_models(conn, project_id, path_id)
    required_steps = [step for step in steps if step.required]
    if any(step.derived_status == "refuted" for step in required_steps):
        status = "refuted"
        decisive = next(step for step in required_steps if step.derived_status == "refuted")
        reason = f"required step {decisive.fact_id} is refuted: {decisive.reason}"
    elif any(step.derived_status == "inconclusive" for step in required_steps):
        status = "inconclusive"
        decisive = next(step for step in required_steps if step.derived_status == "inconclusive")
        reason = f"required step {decisive.fact_id} is inconclusive: {decisive.reason}"
    elif required_steps and all(step.derived_status == "confirmed" for step in required_steps):
        status = "confirmed"
        reason = "all required steps are supported by confirmed or verified Facts"
    else:
        status = "hypothesis"
        pending = [step.fact_id for step in required_steps if step.derived_status == "hypothesis"]
        reason = "required steps still need evidence" + (f": {', '.join(pending)}" if pending else "")
    if path["status"] != status or path["status_reason"] != reason:
        conn.execute(
            """
            UPDATE attack_paths
            SET status = ?, status_reason = ?, updated_at = ?
            WHERE project_id = ? AND id = ?
            """,
            (status, reason, utcnow(), project_id, path_id),
        )
        path = conn.execute(
            "SELECT * FROM attack_paths WHERE project_id = ? AND id = ?",
            (project_id, path_id),
        ).fetchone()
    assert path is not None
    return path


def reconcile_project_attack_paths(conn: sqlite3.Connection, project_id: str) -> int:
    rows = conn.execute(
        "SELECT id, status, status_reason FROM attack_paths WHERE project_id = ? ORDER BY created_at, id",
        (project_id,),
    ).fetchall()
    changed = 0
    for row in rows:
        updated = reconcile_attack_path(conn, project_id, row["id"])
        if updated["status"] != row["status"] or updated["status_reason"] != row["status_reason"]:
            changed += 1
    return changed


def attack_path_to_model(conn: sqlite3.Connection, row: sqlite3.Row, project_id: str) -> AttackPath:
    updated = row
    steps = _attack_path_step_models(conn, project_id, updated["id"])
    step_fact_ids = {step.fact_id for step in steps}
    coverage_ids = {coverage_id for step in steps for coverage_id in step.coverage_refs}
    intent_refs = [
        item["id"] for item in conn.execute(
            "SELECT id, to_fact_id FROM intents WHERE project_id = ? ORDER BY created_at, id",
            (project_id,),
        ).fetchall()
        if item["to_fact_id"] in step_fact_ids
    ]
    for item in conn.execute(
        "SELECT coverage_id, intent_id FROM coverage_intents WHERE project_id = ? ORDER BY created_at, intent_id",
        (project_id,),
    ).fetchall():
        if item["coverage_id"] in coverage_ids and item["intent_id"] not in intent_refs:
            intent_refs.append(item["intent_id"])
    return AttackPath(
        id=updated["id"],
        name=updated["name"],
        fact_chain=_json_list(updated["fact_chain"]),
        description=updated["description"],
        severity=updated["severity"],
        status=updated["status"] or "hypothesis",
        suggested_status=updated["suggested_status"] or "hypothesis",
        status_reason=updated["status_reason"],
        signature=updated["signature"],
        steps=steps,
        task_log_refs=_task_log_refs_for_intents(conn, project_id, intent_refs),
        created_at=updated["created_at"],
        updated_at=updated["updated_at"] or updated["created_at"],
    )


def _attack_path_step_models(
    conn: sqlite3.Connection,
    project_id: str,
    path_id: str,
) -> list[AttackPathStep]:
    rows = conn.execute(
        """
        SELECT aps.fact_id, aps.required, aps.step_order, f.*
        FROM attack_path_steps aps
        JOIN facts f ON f.project_id = aps.project_id AND f.id = aps.fact_id
        WHERE aps.project_id = ? AND aps.path_id = ?
        ORDER BY aps.step_order
        """,
        (project_id, path_id),
    ).fetchall()
    models: list[AttackPathStep] = []
    for row in rows:
        coverage_rows = conn.execute(
            """
            SELECT DISTINCT c.*
            FROM coverage_evidence ce
            JOIN coverage_items c
              ON c.project_id = ce.project_id AND c.id = ce.coverage_id
            WHERE ce.project_id = ? AND ce.fact_id = ?
            ORDER BY c.id
            """,
            (project_id, row["fact_id"]),
        ).fetchall()
        derived, reason = _derive_attack_path_step_status(conn, project_id, row, coverage_rows)
        if not bool(row["required"]):
            reason = f"context step; {reason}"
        models.append(
            AttackPathStep(
                fact_id=row["fact_id"],
                required=bool(row["required"]),
                order=row["step_order"],
                fact_status=row["status"],
                derived_status=derived,
                reason=reason,
                coverage_refs=[coverage["id"] for coverage in coverage_rows],
            )
        )
    return models


def _derive_attack_path_step_status(
    conn: sqlite3.Connection,
    project_id: str,
    fact: sqlite3.Row,
    coverage_rows: list[sqlite3.Row],
) -> tuple[str, str]:
    normalized = str(fact["status"] or "").casefold()
    if normalized in {"refuted", "false_positive", "not_vulnerable"}:
        return "refuted", f"Fact status is {normalized}"
    if normalized in {"failed", "inconclusive"}:
        return "inconclusive", f"Fact status is {normalized}"

    fact_variant = _fact_variant_value(conn, project_id, fact)
    conflicts: list[str] = []
    if fact_variant:
        for coverage in coverage_rows:
            result = next(
                (
                    item for item in coverage_variant_results(conn, project_id, coverage)
                    if item.variant.casefold() == fact_variant.casefold()
                ),
                None,
            )
            if result is not None and result.status == "conflict":
                conflicts.append(f"{coverage['id']}/{result.variant}")
    if conflicts:
        return "inconclusive", f"same-variant evidence conflicts: {', '.join(conflicts)}"
    if normalized in {"confirmed", "verified"}:
        return "confirmed", f"Fact status is {normalized}"
    return "hypothesis", "Fact has no confirmed terminal evidence"


def coverage_state_fields(
    status: str,
    execution_status: str | None = None,
    outcome: str | None = None,
) -> tuple[str, str | None, str]:
    if execution_status is None:
        execution_status, outcome = {
            "untested": ("untested", None),
            "testing": ("testing", None),
            "confirmed": ("completed", "vulnerable"),
            "not_vulnerable": ("completed", "not_vulnerable"),
            "inconclusive": ("completed", "inconclusive"),
            "failed": ("blocked", None),
            "informational": ("completed", "informational"),
        }[status]
    if execution_status in {"untested", "queued"}:
        legacy_status = "untested"
    elif execution_status == "testing":
        legacy_status = "testing"
    elif execution_status == "blocked":
        legacy_status = "failed"
    elif outcome == "vulnerable":
        legacy_status = "confirmed"
    elif outcome == "not_vulnerable" or outcome == "not_applicable":
        legacy_status = "not_vulnerable"
    elif outcome == "informational":
        legacy_status = "informational"
    else:
        legacy_status = "inconclusive"
    return execution_status, outcome, legacy_status


def coverage_variant_results(
    conn: sqlite3.Connection,
    project_id: str,
    coverage: sqlite3.Row,
    *,
    evidence_rows: list[sqlite3.Row] | None = None,
    bound_intent_rows: list[sqlite3.Row] | None = None,
) -> list[CoverageVariantResult]:
    declared = _normalized_variants(_json_list(coverage["test_variants"]))
    rows = evidence_rows
    if rows is None:
        rows = conn.execute(
            """
            SELECT f.*, ce.relation,
                   i.id AS source_intent_id,
                   i.test_variant AS intent_test_variant,
                   i.action_kind AS intent_action_kind
            FROM coverage_evidence ce
            JOIN facts f ON f.project_id = ce.project_id AND f.id = ce.fact_id
            LEFT JOIN intents i ON i.project_id = f.project_id AND i.to_fact_id = f.id
            WHERE ce.project_id = ? AND ce.coverage_id = ?
            ORDER BY f.id, i.id
            """,
            (project_id, coverage["id"]),
        ).fetchall()

    grouped: dict[str, list[sqlite3.Row]] = {variant: [] for variant in declared}
    seen_fact_ids: dict[str, set[str]] = {variant: set() for variant in declared}
    for row in rows:
        variant = _coverage_evidence_variant(coverage, row, declared)
        if variant is None:
            continue
        grouped.setdefault(variant, [])
        seen_fact_ids.setdefault(variant, set())
        if row["id"] in seen_fact_ids[variant]:
            continue
        seen_fact_ids[variant].add(row["id"])
        grouped[variant].append(row)

    if not grouped:
        default_variant = str(coverage["test_family"] or coverage["item_type"] or "general")
        grouped[default_variant] = []

    return [
        _derive_variant_result(
            conn,
            project_id,
            coverage,
            variant,
            grouped[variant],
            bound_intent_rows=bound_intent_rows,
        )
        for variant in grouped
    ]


def _normalized_variants(values: list) -> list[str]:
    normalized: list[str] = []
    for value in values:
        variant = str(value).strip()
        if variant and variant.casefold() not in {item.casefold() for item in normalized}:
            normalized.append(variant)
    return normalized


def _coverage_evidence_variant(
    coverage: sqlite3.Row,
    row: sqlite3.Row,
    declared: list[str],
) -> str | None:
    raw = str(row["intent_test_variant"] or row["vuln_type"] or "").strip()
    if declared:
        if raw:
            return next((item for item in declared if item.casefold() == raw.casefold()), None)
        return declared[0] if len(declared) == 1 else None
    return raw or str(coverage["test_family"] or coverage["item_type"] or "general")


def _derive_variant_result(
    conn: sqlite3.Connection,
    project_id: str,
    coverage: sqlite3.Row,
    variant: str,
    rows: list[sqlite3.Row],
    *,
    bound_intent_rows: list[sqlite3.Row] | None = None,
) -> CoverageVariantResult:
    if not rows:
        if bound_intent_rows is None:
            bound_intent_rows = conn.execute(
                """
                SELECT i.*
                FROM coverage_intents ci
                JOIN intents i ON i.project_id = ci.project_id AND i.id = ci.intent_id
                WHERE ci.project_id = ? AND ci.coverage_id = ?
                ORDER BY i.created_at, i.id
                """,
                (project_id, coverage["id"]),
            ).fetchall()
        declared = _normalized_variants(_json_list(coverage["test_variants"]))
        matching_intents = [
            row
            for row in bound_intent_rows
            if not declared
            or str(row["test_variant"] or "").casefold() == variant.casefold()
            or (len(declared) == 1 and not str(row["test_variant"] or "").strip())
        ]
        active_intent = next(
            (
                row
                for row in matching_intents
                if row["status"] == "open" and row["to_fact_id"] is None
            ),
            None,
        )
        if active_intent is not None:
            return CoverageVariantResult(
                variant=variant,
                status="untested",
                open_intent_id=active_intent["id"],
                reason=f"{active_intent['id']} is still executable",
            )

        terminal_intent = next(
            (
                row
                for row in reversed(matching_intents)
                if row["status"] == "dead_lettered"
            ),
            None,
        )
        if terminal_intent is not None:
            return CoverageVariantResult(
                variant=variant,
                status="inconclusive",
                reason=f"{terminal_intent['id']} exhausted bounded retries: {terminal_intent['last_error'] or 'execution failed'}",
            )
        # Profile variants are evidence-driven. An item-level disposition must
        # never fan out to sibling variants that have no bound Fact.
        manual = None if declared else _manual_variant_status(coverage)
        if manual is not None:
            return CoverageVariantResult(
                variant=variant,
                status=manual,
                reason="manual Coverage disposition; no Fact evidence",
            )
        return CoverageVariantResult(variant=variant, status="untested", reason="no bound Fact evidence")

    positive: list[sqlite3.Row] = []
    negative: list[sqlite3.Row] = []
    limited: list[sqlite3.Row] = []
    informational: list[sqlite3.Row] = []
    for row in rows:
        verdict = _variant_fact_verdict(conn, project_id, coverage, row)
        if verdict in {"confirmed", "verified"}:
            positive.append(row)
        elif verdict == "not_vulnerable":
            negative.append(row)
        elif verdict in {"inconclusive", "failed"}:
            limited.append(row)
        elif verdict == "informational":
            informational.append(row)

    valid_verified = [row for row in positive if _valid_variant_verification(row, rows)]
    fact_ids = sorted({row["id"] for row in rows})
    if valid_verified:
        return CoverageVariantResult(
            variant=variant,
            status="vulnerable",
            fact_ids=fact_ids,
            verification="verified",
            reason=f"independent verification confirmed by {', '.join(row['id'] for row in valid_verified)}",
        )
    if positive and negative:
        return CoverageVariantResult(
            variant=variant,
            status="conflict",
            fact_ids=fact_ids,
            verification="unverified",
            reason="confirmed and not_vulnerable evidence conflict for the same variant",
        )
    if positive:
        return CoverageVariantResult(
            variant=variant,
            status="vulnerable",
            fact_ids=fact_ids,
            verification="unverified",
            reason="positive evidence is confirmed but not independently verified",
        )
    if negative:
        return CoverageVariantResult(
            variant=variant,
            status="not_vulnerable",
            fact_ids=fact_ids,
            reason="only negative terminal evidence is present",
        )
    if limited:
        return CoverageVariantResult(
            variant=variant,
            status="inconclusive",
            fact_ids=fact_ids,
            reason="testing is inconclusive or failed",
        )
    return CoverageVariantResult(
        variant=variant,
        status="informational",
        fact_ids=fact_ids,
        reason="evidence is informational and does not establish a vulnerability verdict",
    )


def _variant_fact_verdict(
    conn: sqlite3.Connection,
    project_id: str,
    coverage: sqlite3.Row,
    row: sqlite3.Row,
) -> str:
    status = str(row["status"] or "").strip().casefold()
    if status in {"confirmed", "verified"}:
        if row["intent_test_variant"] or row["vuln_type"] or row["severity"]:
            return status
        action_kind = str(row["intent_action_kind"] or "").strip().casefold()
        if action_kind:
            if any(marker in action_kind for marker in ("recon", "discover", "fingerprint", "inventory", "map")):
                return "informational"
            return status
        return status if _coverage_is_security_check(coverage) else "informational"
    if status in {"not_vulnerable", "refuted", "false_positive"}:
        return "not_vulnerable"
    if status in {"failed"}:
        return "failed"
    if status in {"inconclusive", "pending"}:
        return "inconclusive"
    if status in {"informational", "completed"}:
        return "informational"
    return "inconclusive" if row["relation"] == "limits" else "informational"


def _valid_variant_verification(candidate: sqlite3.Row, rows: list[sqlite3.Row]) -> bool:
    if str(candidate["status"] or "").casefold() != "verified" or not candidate["verification_of"]:
        return False
    target = next((row for row in rows if row["id"] == candidate["verification_of"]), None)
    if target is None or str(target["status"] or "").casefold() not in {"confirmed", "verified"}:
        return False
    candidate_intent = candidate["source_intent_id"]
    target_intent = target["source_intent_id"]
    return not (candidate_intent and target_intent and candidate_intent == target_intent)


def _manual_variant_status(coverage: sqlite3.Row) -> str | None:
    if coverage["execution_status"] != "completed":
        return None
    return {
        "vulnerable": "vulnerable",
        "not_vulnerable": "not_vulnerable",
        "inconclusive": "inconclusive",
        "not_applicable": "not_applicable",
        "informational": "informational",
    }.get(coverage["outcome"])


def _aggregate_variant_results(
    coverage: sqlite3.Row,
    results: list[CoverageVariantResult],
) -> tuple[str, str | None, str]:
    statuses = {result.status for result in results}
    if "vulnerable" in statuses:
        outcome = "vulnerable"
    elif statuses & {"conflict", "inconclusive"}:
        outcome = "inconclusive"
    elif statuses == {"not_applicable"}:
        outcome = "not_applicable"
    elif statuses and statuses <= {"not_vulnerable", "not_applicable"}:
        outcome = "not_vulnerable"
    elif statuses == {"informational"}:
        outcome = "informational"
    else:
        outcome = None

    if "conflict" in statuses:
        execution = "blocked"
    elif outcome == "vulnerable":
        execution = "completed"
    elif "untested" in statuses:
        current_execution = str(coverage["execution_status"] or "")
        execution = (
            current_execution
            if current_execution in {"queued", "testing"}
            and any(result.open_intent_id for result in results)
            else "untested"
        )
    elif "inconclusive" in statuses:
        execution = "completed"
    else:
        execution = "completed"

    if outcome == "vulnerable":
        legacy_status = "confirmed"
    elif execution == "blocked":
        legacy_status = "failed"
    elif execution in {"untested", "queued"}:
        legacy_status = "untested"
    elif execution == "testing":
        legacy_status = "testing"
    elif outcome in {"not_vulnerable", "not_applicable"}:
        legacy_status = "not_vulnerable"
    elif outcome == "informational":
        legacy_status = "informational"
    else:
        legacy_status = "inconclusive"
    return execution, outcome, legacy_status


def _recompute_coverage_item(
    conn: sqlite3.Connection,
    project_id: str,
    coverage: sqlite3.Row,
) -> int:
    if coverage["disposition"] == "excluded" and coverage["outcome"] == "not_applicable":
        return 0
    results = coverage_variant_results(conn, project_id, coverage)
    execution, outcome, legacy_status = _aggregate_variant_results(coverage, results)
    fact_ids = [fact_id for result in results for fact_id in result.fact_ids]
    evidence_ref = fact_ids[0] if fact_ids else coverage["evidence_ref"]
    current = (
        coverage["execution_status"],
        coverage["outcome"],
        coverage["status"],
        coverage["evidence_ref"],
    )
    if current == (execution, outcome, legacy_status, evidence_ref):
        return 0
    before = conn.total_changes
    conn.execute(
        """
        UPDATE coverage_items
        SET execution_status = ?, outcome = ?, status = ?, evidence_ref = ?, updated_at = ?
        WHERE project_id = ? AND id = ?
        """,
        (execution, outcome, legacy_status, evidence_ref, utcnow(), project_id, coverage["id"]),
    )
    return conn.total_changes - before


def reconcile_fact_coverage(
    conn: sqlite3.Connection,
    project_id: str,
    fact_id: str,
    *,
    intent_id: str | None = None,
    explicit_coverage_refs: list[str] | None = None,
) -> list[str]:
    fact = conn.execute(
        "SELECT * FROM facts WHERE id = ? AND project_id = ?",
        (fact_id, project_id),
    ).fetchone()
    if fact is None:
        raise HTTPException(404, f"Fact {fact_id} not found")

    explicit = explicit_coverage_refs or []
    validate_coverage_exists(conn, project_id, explicit)
    coverage_ids = set(explicit)
    existing_rows = conn.execute(
        """
        SELECT coverage_id FROM coverage_evidence
        WHERE project_id = ? AND fact_id = ?
        """,
        (project_id, fact_id),
    ).fetchall()
    coverage_ids.update(row["coverage_id"] for row in existing_rows)
    if intent_id:
        rows = conn.execute(
            """
            SELECT coverage_id FROM coverage_intents
            WHERE project_id = ? AND intent_id = ?
            UNION
            SELECT id FROM coverage_items
            WHERE project_id = ? AND intent_id = ?
            """,
            (project_id, intent_id, project_id, intent_id),
        ).fetchall()
        coverage_ids.update(row["coverage_id"] for row in rows)

    exact_ids = set(coverage_ids)
    for coverage_id in exact_ids:
        _apply_fact_to_coverage(
            conn,
            project_id,
            coverage_id,
            fact,
            intent_id=intent_id,
        )

    return sorted(coverage_ids)


def cleanup_legacy_coverage_evidence(conn: sqlite3.Connection, project_id: str) -> int:
    before = conn.total_changes
    conn.execute(
        """
        DELETE FROM coverage_evidence
        WHERE project_id = ?
          AND EXISTS (
              SELECT 1
              FROM intents source_intent
              WHERE source_intent.project_id = coverage_evidence.project_id
                AND source_intent.to_fact_id = coverage_evidence.fact_id
          )
          AND NOT EXISTS (
              SELECT 1
              FROM intents source_intent
              WHERE source_intent.project_id = coverage_evidence.project_id
                AND source_intent.to_fact_id = coverage_evidence.fact_id
                AND (
                    EXISTS (
                        SELECT 1 FROM coverage_intents ci
                        WHERE ci.project_id = coverage_evidence.project_id
                          AND ci.coverage_id = coverage_evidence.coverage_id
                          AND ci.intent_id = source_intent.id
                    )
                    OR EXISTS (
                        SELECT 1 FROM coverage_items bound
                        WHERE bound.project_id = coverage_evidence.project_id
                          AND bound.id = coverage_evidence.coverage_id
                          AND bound.intent_id = source_intent.id
                    )
                )
          )
          AND NOT EXISTS (
              SELECT 1 FROM coverage_items direct_source
              WHERE direct_source.project_id = coverage_evidence.project_id
                AND direct_source.id = coverage_evidence.coverage_id
                AND direct_source.source_fact_id = coverage_evidence.fact_id
          )
        """,
        (project_id,),
    )
    return conn.total_changes - before


def merge_duplicate_profile_coverage(conn: sqlite3.Connection, project_id: str) -> int:
    rows = conn.execute(
        """
        SELECT * FROM coverage_items
        WHERE project_id = ?
          AND NULLIF(surface_group, '') IS NOT NULL
          AND NULLIF(test_family, '') IS NOT NULL
        ORDER BY created_at, id
        """,
        (project_id,),
    ).fetchall()
    groups: dict[tuple[str, str, str], list[sqlite3.Row]] = {}
    for row in rows:
        family = str(row["test_family"]).casefold()
        auth_key = "any" if family == "surface_config" else str(row["auth_context"] or "anonymous").casefold()
        surface_key = str(_row_get(row, "surface_fingerprint") or "").casefold()
        if not surface_key:
            surface_key = json.dumps(
                {
                    "target": str(row["target"] or "").casefold(),
                    "port": row["port"],
                    "method": str(row["method"] or "").upper(),
                    "path": str(row["path"] or ""),
                },
                sort_keys=True,
            )
        key = (
            surface_key,
            family,
            auth_key,
        )
        groups.setdefault(key, []).append(row)

    before = conn.total_changes
    for group in groups.values():
        if len(group) < 2 or any(_untraceable_terminal_coverage(conn, row) for row in group):
            continue
        canonical = group[0]
        duplicates = group[1:]
        variants = sorted({value for row in group for value in _json_list(row["test_variants"])})
        roles = sorted({value for row in group for value in _json_list(row["roles"])})
        standard_refs = sorted({value for row in group for value in _json_list(row["standard_refs"])})
        priorities = [row["priority"] for row in group if row["priority"] is not None]
        excluded_reason = next(
            (
                row["applicability_reason"] for row in group
                if str(row["applicability_reason"] or "").startswith(
                    "Excluded from required scope:"
                )
            ),
            None,
        )
        required = 0 if excluded_reason else int(any(bool(row["required"]) for row in group))
        primary_intent = next((row["intent_id"] for row in group if row["intent_id"]), None)
        source_fact = next((row["source_fact_id"] for row in group if row["source_fact_id"]), None)
        applicability_reason = excluded_reason or next(
            (row["applicability_reason"] for row in group if row["applicability_reason"]),
            None,
        )

        for duplicate in duplicates:
            conn.execute(
                """
                INSERT OR IGNORE INTO coverage_intents (
                    project_id, coverage_id, intent_id, created_at
                )
                SELECT project_id, ?, intent_id, created_at
                FROM coverage_intents
                WHERE project_id = ? AND coverage_id = ?
                """,
                (canonical["id"], project_id, duplicate["id"]),
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO coverage_evidence (
                    project_id, coverage_id, fact_id, relation, created_at
                )
                SELECT project_id, ?, fact_id, relation, created_at
                FROM coverage_evidence
                WHERE project_id = ? AND coverage_id = ?
                """,
                (canonical["id"], project_id, duplicate["id"]),
            )

        conn.execute(
            """
            UPDATE coverage_items
            SET priority = ?, test_variants = ?, roles = ?, standard_refs = ?,
                required = ?, intent_id = ?, source_fact_id = ?,
                applicability_reason = ?, updated_at = ?
            WHERE project_id = ? AND id = ?
            """,
            (
                max(priorities) if priorities else None,
                json.dumps(variants),
                json.dumps(roles),
                json.dumps(standard_refs),
                required,
                primary_intent,
                source_fact,
                applicability_reason,
                max(row["updated_at"] for row in group),
                project_id,
                canonical["id"],
            ),
        )
        for duplicate in duplicates:
            conn.execute(
                "DELETE FROM coverage_items WHERE project_id = ? AND id = ?",
                (project_id, duplicate["id"]),
            )
    return conn.total_changes - before


def _untraceable_terminal_coverage(conn: sqlite3.Connection, coverage: sqlite3.Row) -> bool:
    terminal = (
        coverage["execution_status"] == "completed"
        or coverage["status"] not in ("untested", "testing")
    )
    if not terminal:
        return False
    evidence = conn.execute(
        """
        SELECT 1 FROM coverage_evidence
        WHERE project_id = ? AND coverage_id = ?
        LIMIT 1
        """,
        (coverage["project_id"], coverage["id"]),
    ).fetchone()
    return evidence is None



def _backfill_coverage_surface_fingerprints(conn: sqlite3.Connection, project_id: str) -> int:
    before = conn.total_changes
    conn.execute(
        """
        UPDATE coverage_items AS coverage
        SET surface_fingerprint = (
            SELECT surface.fingerprint
            FROM surface_inventory AS surface
            WHERE surface.project_id = coverage.project_id
              AND LOWER(COALESCE(surface.target, '')) = LOWER(COALESCE(coverage.target, ''))
              AND COALESCE(surface.port, -1) = COALESCE(coverage.port, -1)
              AND UPPER(COALESCE(surface.method, '')) = UPPER(COALESCE(coverage.method, ''))
              AND COALESCE(surface.path_template, '') = COALESCE(coverage.path, '')
              AND LOWER(COALESCE(surface.auth_context, 'anonymous')) = LOWER(COALESCE(coverage.auth_context, 'anonymous'))
            ORDER BY surface.created_at,
              surface.id
            LIMIT 1
        )
        WHERE coverage.project_id = ?
          AND COALESCE(coverage.surface_fingerprint, '') = ''
          AND EXISTS (
              SELECT 1
              FROM surface_inventory AS candidate
              WHERE candidate.project_id = coverage.project_id
                AND LOWER(COALESCE(candidate.target, '')) = LOWER(COALESCE(coverage.target, ''))
                AND COALESCE(candidate.port, -1) = COALESCE(coverage.port, -1)
                AND UPPER(COALESCE(candidate.method, '')) = UPPER(COALESCE(coverage.method, ''))
                AND COALESCE(candidate.path_template, '') = COALESCE(coverage.path, '')
                AND LOWER(COALESCE(candidate.auth_context, 'anonymous')) =
                    LOWER(COALESCE(coverage.auth_context, 'anonymous'))
          )
        """,
        (project_id,),
    )
    return conn.total_changes - before
def reconcile_project_coverage(conn: sqlite3.Connection, project_id: str) -> int:
    changed = _backfill_coverage_surface_fingerprints(conn, project_id)
    changed += cleanup_legacy_coverage_evidence(conn, project_id)
    changed += merge_duplicate_profile_coverage(conn, project_id)
    before = conn.total_changes
    conn.execute(
        """
        UPDATE coverage_items
        SET test_variants = CASE test_family
                WHEN 'business_logic' THEN '["workflow_integrity"]'
                WHEN 'crypto_transport' THEN '["tls_transport"]'
                ELSE test_variants
            END,
            updated_at = ?
        WHERE project_id = ?
          AND test_family IN ('business_logic', 'crypto_transport')
          AND (test_variants IS NULL OR test_variants = '' OR test_variants = '[]')
        """,
        (utcnow(), project_id),
    )
    changed += conn.total_changes - before

    before = conn.total_changes
    conn.execute(
        """
        UPDATE coverage_items
        SET status = 'not_vulnerable', execution_status = 'completed',
            outcome = 'not_applicable', required = 0, disposition = 'excluded',
            disposition_reason = 'TLS transport checks do not apply to an HTTP-only port.',
            applicability_reason = 'TLS transport checks do not apply to an HTTP-only port.',
            updated_at = ?
        WHERE project_id = ? AND test_family = 'crypto_transport'
          AND port IS NOT NULL AND port <> 443
          AND (
              COALESCE(status, '') <> 'not_vulnerable' OR COALESCE(execution_status, '') <> 'completed'
              OR COALESCE(outcome, '') <> 'not_applicable' OR required <> 0
              OR COALESCE(disposition, '') <> 'excluded'
          )
        """,
        (utcnow(), project_id),
    )
    changed += conn.total_changes - before

    before = conn.total_changes
    conn.execute(
        """
        UPDATE coverage_items
        SET required = 0, disposition = 'excluded',
            disposition_reason = COALESCE(disposition_reason, 'Inventory-only surface configuration coverage.'),
            updated_at = ?
        WHERE project_id = ? AND test_family = 'surface_config'
          AND (required <> 0 OR disposition <> 'excluded')
        """,
        (utcnow(), project_id),
    )
    changed += conn.total_changes - before

    concluded = conn.execute(
        """
        SELECT ci.coverage_id, ci.intent_id, i.to_fact_id
        FROM coverage_intents ci
        JOIN intents i ON i.project_id = ci.project_id AND i.id = ci.intent_id
        WHERE ci.project_id = ? AND i.to_fact_id IS NOT NULL
        """,
        (project_id,),
    ).fetchall()
    for row in concluded:
        fact = conn.execute(
            "SELECT * FROM facts WHERE id = ? AND project_id = ?",
            (row["to_fact_id"], project_id),
        ).fetchone()
        if fact is None:
            continue
        changed += _apply_fact_to_coverage(
            conn,
            project_id,
            row["coverage_id"],
            fact,
            intent_id=row["intent_id"],
        )

    for coverage in conn.execute(
        "SELECT * FROM coverage_items WHERE project_id = ? ORDER BY created_at, id",
        (project_id,),
    ).fetchall():
        changed += _recompute_coverage_item(conn, project_id, coverage)
    return changed


def _apply_fact_to_coverage(
    conn: sqlite3.Connection,
    project_id: str,
    coverage_id: str,
    fact: sqlite3.Row,
    *,
    intent_id: str | None,
) -> int:
    coverage = conn.execute(
        "SELECT * FROM coverage_items WHERE id = ? AND project_id = ?",
        (coverage_id, project_id),
    ).fetchone()
    if coverage is None:
        return 0
    fact_status = (fact["status"] or "").casefold()
    if fact_status in {"confirmed", "verified"}:
        relation = "supports"
    elif fact_status in {"not_vulnerable", "refuted", "false_positive"}:
        relation = "refutes"
    elif fact_status in {"informational", "completed"}:
        relation = "observes"
    else:
        relation = "limits"
    before = conn.total_changes
    link_coverage_evidence(conn, project_id, coverage_id, fact["id"], relation)
    if intent_id:
        bind_coverage_intent(conn, project_id, coverage_id, intent_id)
    coverage = conn.execute(
        "SELECT * FROM coverage_items WHERE id = ? AND project_id = ?",
        (coverage_id, project_id),
    ).fetchone()
    assert coverage is not None
    _recompute_coverage_item(conn, project_id, coverage)
    return 1 if conn.total_changes > before else 0



def _coverage_is_security_check(coverage: sqlite3.Row) -> bool:
    family = str(coverage["test_family"] or "") or _test_family_for_legacy_coverage(coverage)
    return bool(family and family != "surface_config")



def _test_family_for_legacy_coverage(coverage: sqlite3.Row) -> str | None:
    text = " ".join(
        str(value or "")
        for value in (
            coverage["item_type"], coverage["description"], coverage["path"], coverage["param"]
        )
    ).casefold().replace("-", "_")
    if coverage["item_type"] == "upload_point" or any(
        token in text for token in ("upload", "download", "path traversal", "file inclusion", "lfi", "rfi")
    ):
        return "file_path"
    if any(token in text for token in ("login", "signin", "password", "credential", "authentication")):
        return "identity_auth"
    if any(token in text for token in ("sql", "injection", "command", "ssti")):
        return "injection"
    if any(token in text for token in ("idor", "authorization", "access control", "privilege")):
        return "authorization"
    if any(token in text for token in ("csrf", "session", "cookie")):
        return "session_csrf"
    if any(token in text for token in ("xss", "cors", "clickjack", "client side")):
        return "client_side"
    if any(token in text for token in ("ssrf", "xxe", "deserial", "template")):
        return "server_side_processing"
    return None


def next_project_id(conn: sqlite3.Connection) -> str:
    conn.execute("UPDATE counters SET value = value + 1 WHERE name = 'project'")
    row = conn.execute("SELECT value FROM counters WHERE name = 'project'").fetchone()
    return f"proj_{row['value']:03d}"


def _next_scoped_id(conn: sqlite3.Connection, kind: str, prefix: str, project_id: str) -> str:
    conn.execute(
        "INSERT OR IGNORE INTO scoped_counters (project_id, kind, value) VALUES (?, ?, 0)",
        (project_id, kind),
    )
    conn.execute(
        "UPDATE scoped_counters SET value = value + 1 WHERE project_id = ? AND kind = ?",
        (project_id, kind),
    )
    row = conn.execute(
        "SELECT value FROM scoped_counters WHERE project_id = ? AND kind = ?",
        (project_id, kind),
    ).fetchone()
    assert row is not None
    return f"{prefix}{row['value']:03d}"


def next_fact_id(conn: sqlite3.Connection, project_id: str) -> str:
    return _next_scoped_id(conn, "fact", "f", project_id)


def next_intent_id(conn: sqlite3.Connection, project_id: str) -> str:
    return _next_scoped_id(conn, "intent", "i", project_id)


def next_hint_id(conn: sqlite3.Connection, project_id: str) -> str:
    return _next_scoped_id(conn, "hint", "h", project_id)


def next_attack_path_id(conn: sqlite3.Connection, project_id: str) -> str:
    return _next_scoped_id(conn, "attack_path", "ap", project_id)


def next_coverage_id(conn: sqlite3.Connection, project_id: str) -> str:
    return _next_scoped_id(conn, "coverage", "cov", project_id)


def next_surface_id(conn: sqlite3.Connection, project_id: str) -> str:
    return _next_scoped_id(conn, "surface", "surf", project_id)


def next_hypothesis_id(conn: sqlite3.Connection, project_id: str) -> str:
    return _next_scoped_id(conn, "hypothesis", "hyp", project_id)


def upsert_surface_inventory_record(
    conn: sqlite3.Connection,
    project_id: str,
    body: UpsertSurfaceInventoryRequest,
    *,
    source_fact_id: str | None = None,
) -> sqlite3.Row:
    existing = conn.execute(
        "SELECT * FROM surface_inventory WHERE project_id = ? AND fingerprint = ?",
        (project_id, body.fingerprint),
    ).fetchone()
    derived_behavior_key, derived_operation, derived_capabilities = behavior_identity(body)
    behavior_key = body.behavior_key or derived_behavior_key
    operation_type = body.operation_type if body.operation_type != "unknown" else derived_operation
    behavior_rows = conn.execute(
        "SELECT * FROM surface_inventory WHERE project_id = ? AND behavior_key = ? ORDER BY created_at, id",
        (project_id, behavior_key),
    ).fetchall()
    previous_params = {
        item for row in behavior_rows for item in _json_list(row["params"])
    }
    previous_roles = {
        item for row in behavior_rows for item in _json_list(row["roles"])
    }
    previous_capabilities = {
        item for row in behavior_rows for item in _json_list(_row_get(row, "capabilities"))
    }
    incoming_capabilities = set(body.capabilities) | set(derived_capabilities)
    merged_params = sorted(previous_params | set(body.params))
    merged_roles = sorted(previous_roles | set(body.roles))
    merged_capabilities = sorted(previous_capabilities | incoming_capabilities)
    merged_evidence = {
        item for row in behavior_rows for item in _json_list(_row_get(row, "evidence_fact_ids"))
    } | set(body.evidence_fact_ids)
    if source_fact_id or body.source_fact_id:
        merged_evidence.add(source_fact_id or body.source_fact_id)
    previous_traits: dict = {}
    for row in behavior_rows:
        for key, value in _json_dict(row["traits"]).items():
            if isinstance(value, bool):
                previous_traits[key] = bool(previous_traits.get(key)) or value
            else:
                previous_traits[key] = value
    merged_traits = dict(previous_traits)
    for key, value in body.traits.items():
        if isinstance(value, bool):
            merged_traits[key] = bool(merged_traits.get(key)) or value
        else:
            merged_traits[key] = value

    # Re-observing the same behavior only merges evidence. It must not turn an
    # assessed node back into pending unless the behavior gained new semantics.
    semantic_delta = bool(
        set(body.params) - previous_params
        or set(body.roles) - previous_roles
        or incoming_capabilities - previous_capabilities
        or any(
            isinstance(value, bool) and value and not bool(previous_traits.get(key))
            for key, value in body.traits.items()
        )
    )
    previous_statuses = {
        str(_row_get(row, "planning_status") or "pending") for row in behavior_rows
    }
    if body.planning_status == "assessed":
        planning_status = "assessed"
    elif not behavior_rows or semantic_delta or "pending" in previous_statuses:
        planning_status = "pending"
    else:
        planning_status = "assessed"
    now = utcnow()
    surface_id = existing["id"] if existing else next_surface_id(conn, project_id)
    created_at = existing["created_at"] if existing else now
    effective_source = source_fact_id or body.source_fact_id
    conn.execute(
        """
        INSERT INTO surface_inventory (
            id, project_id, fingerprint, surface_group, target, port, method,
            path_template, params, surface_type, auth_context, roles, traits,
            source_fact_id, behavior_key, operation_type, capabilities,
            evidence_fact_ids, planning_status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (project_id, fingerprint) DO UPDATE SET
            surface_group = excluded.surface_group,
            target = excluded.target,
            port = excluded.port,
            method = excluded.method,
            path_template = excluded.path_template,
            params = excluded.params,
            surface_type = excluded.surface_type,
            auth_context = excluded.auth_context,
            roles = excluded.roles,
            traits = excluded.traits,
            source_fact_id = COALESCE(excluded.source_fact_id, surface_inventory.source_fact_id),
            behavior_key = excluded.behavior_key,
            operation_type = excluded.operation_type,
            capabilities = excluded.capabilities,
            evidence_fact_ids = excluded.evidence_fact_ids,
            planning_status = excluded.planning_status,
            updated_at = excluded.updated_at
        """,
        (
            surface_id, project_id, body.fingerprint, body.surface_group, body.target,
            body.port, body.method, body.path_template, json.dumps(merged_params),
            body.surface_type, body.auth_context, json.dumps(merged_roles),
            json.dumps(merged_traits), effective_source, behavior_key, operation_type,
            json.dumps(merged_capabilities), json.dumps(sorted(merged_evidence)),
            planning_status, created_at, now,
        ),
    )
    row = conn.execute(
        "SELECT * FROM surface_inventory WHERE project_id = ? AND fingerprint = ?",
        (project_id, body.fingerprint),
    ).fetchone()
    assert row is not None
    return row



def get_project_or_404(conn: sqlite3.Connection, project_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "Project not found")
    return row


def check_project_active(conn: sqlite3.Connection, project_id: str) -> sqlite3.Row:
    row = get_project_or_404(conn, project_id)
    if row["status"] != "active":
        raise HTTPException(403, "Project is not active")
    return row


def check_project_hint_writable(conn: sqlite3.Connection, project_id: str) -> sqlite3.Row:
    row = get_project_or_404(conn, project_id)
    if row["status"] == "completed":
        raise HTTPException(403, "Completed project is read-only")
    return row


def check_project_completed(conn: sqlite3.Connection, project_id: str) -> sqlite3.Row:
    row = get_project_or_404(conn, project_id)
    if row["status"] != "completed":
        raise HTTPException(409, "Project is not completed")
    return row


def validate_facts_exist(conn: sqlite3.Connection, project_id: str, fact_ids: list[str]) -> None:
    for fact_id in fact_ids:
        row = conn.execute(
            "SELECT 1 FROM facts WHERE id = ? AND project_id = ?",
            (fact_id, project_id),
        ).fetchone()
        if row is None:
            raise HTTPException(404, f"Fact {fact_id} not found")


def validate_verification_reference(
    conn: sqlite3.Connection,
    project_id: str,
    verification_of: str | None,
    *,
    candidate_variant: str | None,
    candidate_status: str | None,
    candidate_intent_id: str | None = None,
) -> None:
    if not verification_of:
        return
    target = conn.execute(
        "SELECT * FROM facts WHERE project_id = ? AND id = ?",
        (project_id, verification_of),
    ).fetchone()
    if target is None:
        raise HTTPException(404, f"Fact {verification_of} not found")
    target_variant = _fact_variant_value(conn, project_id, target)
    variant = str(candidate_variant or "").strip()
    if not variant or not target_variant or variant.casefold() != target_variant.casefold():
        raise HTTPException(409, "Verification Fact must use the same test variant as its target")
    if str(candidate_status or "").casefold() == "verified":
        if str(target["status"] or "").casefold() not in {"confirmed", "verified"}:
            raise HTTPException(409, "A verified Fact must reference confirmed evidence")
        target_intent = _source_intent_id(conn, project_id, verification_of)
        if candidate_intent_id and target_intent == candidate_intent_id:
            raise HTTPException(409, "Verification must come from an independent Intent")


def validate_goal_not_in_sources(fact_ids: list[str]) -> None:
    if "goal" in fact_ids:
        raise HTTPException(400, "goal cannot be used as a source Fact")


def validate_project_completion_allowed(conn: sqlite3.Connection, project_id: str) -> None:
    blockers = completion_blockers(conn, project_id)
    if blockers:
        raise HTTPException(
            409,
            detail={
                "code": "completion_blocked",
                "message": "Project still has unfinished executable work or coverage lifecycle work.",
                "blockers": [blocker.model_dump(mode="json") for blocker in blockers],
            },
        )


def assessment_limitations(conn: sqlite3.Connection, project_id: str) -> list[CompletionBlocker]:
    blockers: list[CompletionBlocker] = []
    project = conn.execute(
        "SELECT mode, phase, planning_version, recon_profile FROM projects WHERE id = ?", (project_id,)
    ).fetchone()
    real_website = project is not None and project["mode"] == "real_website"
    planning_v2 = real_website and int(project["planning_version"] or 1) >= 2
    profile = _json_dict(project["recon_profile"]) if project is not None else {}
    hypothesis_min_score = float(profile.get("hypothesis_min_score", 1.0) or 1.0)

    if real_website and project["phase"] != "explore":
        blockers.append(
            CompletionBlocker(
                kind="reason", ref="project-phase", status=project["phase"],
                reason="real_website projects must finish structured recon before completion",
                description="Recon has not advanced through the unified explore transition.",
                suggested_action="finish_recon_then_plan_coverage",
            )
        )
    open_rows = conn.execute(
        """
        SELECT id, status, priority, description, worker, next_retry_at, last_error, failed_at
        FROM intents
        WHERE project_id = ? AND to_fact_id IS NULL AND status = 'open'
        ORDER BY COALESCE(priority, 0) DESC, created_at, id
        """,
        (project_id,),
    ).fetchall()
    for row in open_rows:
        if row["worker"]:
            status = "running"
        elif row["next_retry_at"]:
            status = f"retry_delayed_until={row['next_retry_at']}"
        else:
            status = "open"
        blockers.append(
            CompletionBlocker(
                kind="intent",
                ref=row["id"],
                status=status,
                priority=row["priority"],
                reason=f"{row['id']}:intent status={status}",
                description=row["description"],
                suggested_action="wait_for_terminal_result",
                task_log_refs=_task_log_refs_for_intents(conn, project_id, [row["id"]]),
                updated_at=row["failed_at"],
            )
        )

    if not real_website:
        return blockers

    if planning_v2:
        surface_rows = conn.execute(
            """SELECT * FROM surface_inventory
            WHERE project_id = ? AND planning_status = 'pending'
            ORDER BY created_at, id""",
            (project_id,),
        ).fetchall()
        for surface in surface_rows:
            traits = _json_dict(surface["traits"])
            if traits.get("out_of_scope_support"):
                continue
            blockers.append(
                CompletionBlocker(
                    kind="surface", ref=surface["id"], status="planning_pending",
                    reason="new behavior evidence has not been assessed by the hypothesis planner",
                    description=f"{surface['method'] or 'GET'} {surface['target'] or ''}{surface['path_template'] or '/'}",
                    suggested_action="assess_behavior_and_rank_hypotheses",
                    updated_at=surface["updated_at"],
                )
            )
        hypothesis_rows = conn.execute(
            """SELECT * FROM hypotheses WHERE project_id = ? AND required <> 0
            ORDER BY score DESC, created_at, id""",
            (project_id,),
        ).fetchall()
        for hypothesis in hypothesis_rows:
            status = hypothesis["status"]
            if status in {"supported", "refuted", "waived"}:
                continue
            if status == "candidate" and float(hypothesis["score"] or 0) < hypothesis_min_score:
                continue
            action = {
                "candidate": "repair_or_schedule_selected_hypothesis",
                "planned": "wait_for_hypothesis_intent",
                "testing": "wait_for_hypothesis_result",
                "inconclusive": "review_or_retry_required_hypothesis",
            }.get(status, "review_required_hypothesis")
            log_refs = _task_log_refs_for_intents(
                conn, project_id,
                [hypothesis["intent_id"]] if hypothesis["intent_id"] else [],
            )
            blockers.append(
                CompletionBlocker(
                    kind="coverage", ref=hypothesis["id"], status=status,
                    priority=max(1, min(10, int(round(float(hypothesis["score"] or 0) * 2)))),
                    reason=hypothesis["last_error"] or hypothesis["rationale"],
                    description=(
                        f"{hypothesis['test_family']} / {hypothesis['test_variant']} "
                        f"on {hypothesis['behavior_key']}"
                    ),
                    suggested_action=action,
                    related_refs=[
                        ref for ref in (hypothesis["coverage_id"], hypothesis["intent_id"])
                        if ref
                    ],
                    task_log_refs=log_refs,
                    updated_at=hypothesis["updated_at"],
                )
            )
        orphan_coverage = conn.execute(
            """SELECT * FROM coverage_items AS coverage
            WHERE coverage.project_id = ? AND coverage.required <> 0
              AND coverage.disposition <> 'excluded'
              AND NOT (
                  coverage.execution_status = 'completed'
                  AND coverage.outcome IN ('vulnerable', 'not_vulnerable', 'not_applicable', 'informational')
              )
              AND NOT EXISTS (
                  SELECT 1 FROM hypotheses AS hypothesis
                  WHERE hypothesis.project_id = coverage.project_id
                    AND hypothesis.coverage_id = coverage.id
              )
            ORDER BY COALESCE(coverage.priority, 0) DESC, coverage.created_at, coverage.id""",
            (project_id,),
        ).fetchall()
        for coverage in orphan_coverage:
            variant_statuses = {
                result.status for result in coverage_variant_results(conn, project_id, coverage)
            }
            blocker_status = (
                "conflict" if "conflict" in variant_statuses
                else "inconclusive" if coverage["outcome"] == "inconclusive" else coverage["status"]
            )
            blockers.append(
                CompletionBlocker(
                    kind="coverage", ref=coverage["id"], status=blocker_status,
                    priority=coverage["priority"],
                    reason="required Coverage has no structured Hypothesis binding",
                    description=coverage["description"],
                    suggested_action="bind_to_hypothesis_or_structurally_waive",
                    updated_at=coverage["updated_at"],
                )
            )
        return blockers

    surface_rows = conn.execute(
        """
        SELECT surface.*
        FROM surface_inventory AS surface
        WHERE surface.project_id = ?
          AND NOT EXISTS (
              SELECT 1 FROM coverage_items AS coverage
              WHERE coverage.project_id = surface.project_id
                AND coverage.surface_fingerprint = surface.fingerprint
          )
        ORDER BY surface.created_at, surface.id
        """,
        (project_id,),
    ).fetchall()
    for surface in surface_rows:
        traits = _json_dict(surface["traits"])
        if traits.get("out_of_scope_support"):
            continue
        blockers.append(
            CompletionBlocker(
                kind="surface", ref=surface["id"], status="unprofiled",
                reason="discovered in-scope Surface has no Coverage profile",
                description=f"{surface['method'] or 'GET'} {surface['target'] or ''}{surface['path_template'] or '/'}",
                suggested_action="profile_surface_and_plan_variants",
                updated_at=surface["updated_at"],
            )
        )
    coverage_rows = conn.execute(
        """
        SELECT *
        FROM coverage_items
        WHERE project_id = ? AND disposition <> 'excluded'
        ORDER BY COALESCE(priority, 0) DESC, created_at, id
        """,
        (project_id,),
    ).fetchall()
    coverage_models = {
        item.id: item for item in build_coverage_items(conn, project_id, coverage_rows)
    }
    terminal_statuses = {
        "vulnerable",
        "not_vulnerable",
        "not_applicable",
        "informational",
    }
    for coverage in coverage_rows:
        variants = _normalized_variants(_json_list(coverage["test_variants"]))
        coverage_model = coverage_models[coverage["id"]]
        for result in coverage_model.variant_results:
            if result.status in terminal_statuses:
                continue
            suggested_action = (
                "define_variant_or_waive_coverage"
                if not variants and result.status == "untested"
                else {
                    "conflict": "review_conflicting_evidence",
                    "inconclusive": "review_or_retry_required_variant",
                    "untested": "materialize_or_resume_exact_coverage_intent",
                }.get(result.status, "review_required_variant")
            )
            blockers.append(
                CompletionBlocker(
                    kind="coverage",
                    ref=f"{coverage['id']}:{result.variant}",
                    status=result.status,
                    priority=coverage["priority"],
                    reason=result.reason,
                    description=f"{coverage['description']} / {result.variant}",
                    suggested_action=suggested_action,
                    related_refs=[coverage["id"], *result.fact_ids],
                    task_log_refs=coverage_model.task_log_refs,
                    updated_at=coverage["updated_at"],
                )
            )

    return blockers


def completion_blockers(conn: sqlite3.Connection, project_id: str) -> list[CompletionBlocker]:
    """Return only lifecycle work that makes an atomic completion write unsafe.

    Coverage, Surface, and Hypothesis records are assessment limitations, not a
    second task graph. Keeping them out of this result prevents metadata from
    deadlocking an otherwise finished project.
    """
    return [
        item
        for item in assessment_limitations(conn, project_id)
        if item.kind in {"intent", "reason"}
    ]


def project_runtime_fields(
    conn: sqlite3.Connection,
    row: sqlite3.Row,
    *,
    include_completion_blockers: bool = True,
) -> dict:
    status = row["status"]
    blockers: list[CompletionBlocker] = []
    if status == "completed":
        run_state = "completed"
    elif status == "stopped":
        run_state = (
            "needs_attention"
            if _row_get(row, "completion_outcome") == "needs_attention"
            else "stopped"
        )
    else:
        run_state = "running"
    progress_values = [row["created_at"], _row_get(row, "reason_started_at"), _row_get(row, "reason_last_heartbeat_at")]
    for table, column in (
        ("intents", "COALESCE(concluded_at, failed_at, created_at)"),
        ("coverage_items", "updated_at"),
        ("task_logs", "created_at"),
    ):
        progress = conn.execute(
            f"SELECT MAX({column}) AS value FROM {table} WHERE project_id = ?",
            (row["id"],),
        ).fetchone()
        if progress and progress["value"]:
            progress_values.append(progress["value"])
    return {
        "run_state": run_state,
        # Full detail is the diagnostic view; blockers must be visible before
        # the first completion attempt as well as after it.
        "completion_blockers": blockers if include_completion_blockers else [],
        "last_progress_at": max(value for value in progress_values if value),
    }


def validate_intent_creator_worker(creator: str, worker: str | None) -> None:
    if worker is not None and worker != creator:
        raise HTTPException(400, "worker must be null or equal to creator")


def validate_intent_scope(
    policy: ScopePolicy,
    *,
    target: str | None,
    port: int | None,
    path: str | None = None,
    action_kind: str | None = None,
) -> None:
    reason = scope_violation_reason(
        policy, target=target, port=port, path=path, action_kind=action_kind
    )
    if reason is not None:
        raise HTTPException(400, reason)


def scope_violation_reason(
    policy: ScopePolicy,
    *,
    target: str | None,
    port: int | None,
    path: str | None = None,
    action_kind: str | None = None,
) -> str | None:
    normalized_target = _normalize_target(target)
    if normalized_target is not None:
        if any(_target_matches(pattern, normalized_target, allow_subdomains=True) for pattern in policy.blocked_targets):
            return f"Intent target {normalized_target!r} is blocked by project scope policy"
        if policy.allowed_targets and not any(
            _target_matches(pattern, normalized_target, allow_subdomains=policy.allow_subdomains)
            for pattern in policy.allowed_targets
        ):
            return f"Intent target {normalized_target!r} is outside project allowed_targets"

    if port is not None:
        if port in policy.blocked_ports:
            return f"Intent port {port} is blocked by project scope policy"
        if port in policy.support_ports and _looks_active_action(action_kind):
            return f"Intent port {port} is a support service port; only passive/probe actions are allowed"
        if policy.allowed_ports and port not in set(policy.allowed_ports) | set(policy.support_ports):
            return f"Intent port {port} is outside project allowed_ports"

    normalized_path = _normalize_path(path or target)
    if normalized_path is not None:
        if any(_path_matches(pattern, normalized_path) for pattern in policy.blocked_paths):
            return f"Intent path {normalized_path!r} is blocked by project scope policy"
        if policy.allowed_paths and not any(_path_matches(pattern, normalized_path) for pattern in policy.allowed_paths):
            return f"Intent path {normalized_path!r} is outside project allowed_paths"

    if not policy.allow_destructive and _looks_destructive_action(action_kind):
        return "Project scope policy does not authorize destructive actions"

    if policy.passive_only and _looks_active_action(action_kind):
        return "Project scope policy is passive_only; active intent action_kind is not allowed"

    if not policy.allow_domain_scan and _looks_domain_scan_action(action_kind):
        return "Project scope policy disables domain/subdomain scanning"

    return None


def _normalize_target(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip().lower()
    if not text:
        return None
    parsed = urlparse(text if "://" in text else f"//{text}")
    host = parsed.hostname
    if host:
        return host.rstrip(".")
    return text.split("/", 1)[0].split(":", 1)[0].rstrip(".")


def _target_matches(pattern: str, target: str, *, allow_subdomains: bool) -> bool:
    normalized_pattern = _normalize_target(pattern)
    if normalized_pattern is None:
        return False
    return target == normalized_pattern or (allow_subdomains and target.endswith(f".{normalized_pattern}"))


def _normalize_path(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    parsed = urlparse(text if "://" in text else f"//{text}")
    path = parsed.path or ""
    if not path and text.startswith("/"):
        path = text
    if not path:
        return None
    return _normalize_path_pattern(path)


def _normalize_path_pattern(value: str) -> str:
    text = value.strip()
    if not text:
        return "/"
    parsed = urlparse(text if "://" in text else text)
    path = parsed.path or text
    if not path.startswith("/"):
        path = f"/{path}"
    return path


def _path_matches(pattern: str, path: str) -> bool:
    normalized_pattern = _normalize_path_pattern(pattern)
    if normalized_pattern == "/":
        return True
    if path == normalized_pattern:
        return True
    return path.startswith(normalized_pattern.rstrip("/") + "/")


def _looks_active_action(action_kind: str | None) -> bool:
    if action_kind is None:
        return False
    text = action_kind.strip().lower()
    return any(keyword in text for keyword in ACTIVE_ACTION_KEYWORDS)


def _looks_domain_scan_action(action_kind: str | None) -> bool:
    if action_kind is None:
        return False
    text = action_kind.strip().lower()
    return any(keyword in text for keyword in DOMAIN_SCAN_ACTION_KEYWORDS)

def _looks_destructive_action(action_kind: str | None) -> bool:
    if action_kind is None:
        return False
    text = action_kind.strip().lower().replace("-", "_")
    return any(
        keyword in text
        for keyword in ("delete", "drop", "truncate", "reset", "install", "uninstall", "wipe", "shutdown", "password_change", "destructive")
    )


def _fact_variant_value(conn: sqlite3.Connection, project_id: str, fact: sqlite3.Row) -> str:
    row = conn.execute(
        "SELECT test_variant FROM intents WHERE project_id = ? AND to_fact_id = ? ORDER BY id LIMIT 1",
        (project_id, fact["id"]),
    ).fetchone()
    return str((row["test_variant"] if row else None) or fact["vuln_type"] or "").strip()


def _source_intent_id(conn: sqlite3.Connection, project_id: str, fact_id: str) -> str | None:
    row = conn.execute(
        "SELECT id FROM intents WHERE project_id = ? AND to_fact_id = ? ORDER BY id LIMIT 1",
        (project_id, fact_id),
    ).fetchone()
    return row["id"] if row else None


def _fact_coverage_ids(conn: sqlite3.Connection, project_id: str, fact_id: str) -> set[str]:
    return {
        row["coverage_id"] for row in conn.execute(
            "SELECT coverage_id FROM coverage_evidence WHERE project_id = ? AND fact_id = ?",
            (project_id, fact_id),
        ).fetchall()
    }


def get_intent_or_404(conn: sqlite3.Connection, project_id: str, intent_id: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM intents WHERE id = ? AND project_id = ?",
        (intent_id, project_id),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "Intent not found")
    return row


def get_claimable_open_intent_or_404(
    conn: sqlite3.Connection, project_id: str, intent_id: str, worker: str
) -> sqlite3.Row:
    expire_workers(conn, project_id)
    row = get_intent_or_404(conn, project_id, intent_id)
    if row["to_fact_id"] is not None:
        raise HTTPException(409, "Intent already concluded")
    status = _row_get(row, "status") or "open"
    if status != "open":
        raise HTTPException(409, f"Intent is {status}")
    next_retry_at = _row_get(row, "next_retry_at")
    if next_retry_at and next_retry_at > utcnow():
        raise HTTPException(409, f"Intent retry is delayed until {next_retry_at}")
    if row["worker"] is not None and row["worker"] != worker:
        raise HTTPException(409, f"Intent is currently claimed by {row['worker']}")
    return row


def get_releasable_open_intent_or_404(
    conn: sqlite3.Connection, project_id: str, intent_id: str, worker: str
) -> sqlite3.Row:
    expire_workers(conn, project_id)
    row = get_intent_or_404(conn, project_id, intent_id)
    if row["to_fact_id"] is not None:
        raise HTTPException(409, "Intent already concluded")
    if row["worker"] is None:
        return row
    if row["worker"] != worker:
        raise HTTPException(409, f"Intent is currently claimed by {row['worker']}")
    return row


def conclude_intent_with_failure_fact(
    conn: sqlite3.Connection,
    project_id: str,
    intent_id: str,
    *,
    worker: str,
    error: str,
    attempt_count: int,
    failure_stage: str,
    execution_status: str = "failed",
    now: str | None = None,
) -> str:
    """Close a terminally failed Intent with a structured result Fact."""
    intent = get_intent_or_404(conn, project_id, intent_id)
    if intent["to_fact_id"] is not None:
        return str(intent["to_fact_id"])
    timestamp = now or utcnow()
    fact_id = next_fact_id(conn, project_id)
    source_ids = [
        str(row["fact_id"])
        for row in conn.execute(
            """SELECT fact_id FROM intent_sources
               WHERE project_id = ? AND intent_id = ? ORDER BY fact_id""",
            (project_id, intent_id),
        ).fetchall()
    ]
    log_ids = [
        str(row["id"])
        for row in conn.execute(
            """SELECT id FROM task_logs
               WHERE project_id = ? AND intent_id = ? ORDER BY created_at, id""",
            (project_id, intent_id),
        ).fetchall()
    ]
    clean_error = error.strip()[:2000] or "unknown terminal failure"
    summary = f"{intent_id} ended with {failure_stage}: {clean_error}"[:320]
    subject = {
        "intent_id": intent_id,
        "target": intent["target"],
        "port": intent["port"],
        "path": intent["path"],
        "action_kind": intent["action_kind"],
        "test_variant": intent["test_variant"],
    }
    data = {
        "outcome": "failed",
        "failure_stage": failure_stage,
        "error": clean_error,
        "attempt_count": attempt_count,
        "retry_exhausted": True,
    }
    conn.execute(
        """INSERT INTO facts (
               id, project_id, description, parent_fact, status,
               schema_version, kind, summary, subject, data,
               parent_fact_ids, evidence_refs, confidence, created_by, created_at
           ) VALUES (?, ?, ?, ?, 'failed', 1, 'execution_result', ?, ?, ?, ?, ?, 1.0, ?, ?)""",
        (
            fact_id, project_id, summary, source_ids[0] if source_ids else None,
            summary, json.dumps(subject, ensure_ascii=False),
            json.dumps(data, ensure_ascii=False),
            json.dumps(source_ids, ensure_ascii=False),
            json.dumps(log_ids, ensure_ascii=False), worker, timestamp,
        ),
    )
    conn.execute(
        """UPDATE intents SET to_fact_id = ?, worker = NULL,
           last_heartbeat_at = NULL, concluded_at = ?, next_retry_at = NULL,
           status = 'concluded', execution_status = ?, commit_status = 'committed'
           WHERE project_id = ? AND id = ?""",
        (fact_id, timestamp, execution_status, project_id, intent_id),
    )
    reconcile_project_coverage(conn, project_id)
    reconcile_project_attack_paths(conn, project_id)
    return fact_id


def mark_intent_failure(
    conn: sqlite3.Connection,
    project_id: str,
    intent_id: str,
    *,
    worker: str,
    error: str,
    max_attempts: int,
    backoff_seconds: int,
) -> sqlite3.Row:
    row = get_intent_or_404(conn, project_id, intent_id)
    if row["to_fact_id"] is not None:
        return row
    now = utcnow()
    next_attempt = (_row_get(row, "attempt_count") or 0) + 1
    if next_attempt >= max_attempts:
        conn.execute(
            """
            UPDATE intents
            SET worker = NULL,
                last_heartbeat_at = NULL,
                attempt_count = ?,
                last_error = ?,
                last_worker = ?,
                next_retry_at = NULL,
                failed_at = ?,
                dead_lettered_at = ?,
                status = 'dead_lettered'
            WHERE id = ? AND project_id = ?
            """,
            (next_attempt, error, worker, now, now, intent_id, project_id),
        )
        conn.execute(
            """
            UPDATE coverage_items
            SET execution_status = CASE
                    WHEN EXISTS (
                        SELECT 1
                        FROM coverage_intents AS ci
                        JOIN intents AS i
                          ON i.project_id = ci.project_id AND i.id = ci.intent_id
                        WHERE ci.project_id = ?
                          AND ci.coverage_id = coverage_items.id
                          AND ci.intent_id <> ?
                          AND i.status = 'open'
                          AND i.to_fact_id IS NULL
                    ) THEN 'queued'
                    ELSE 'blocked'
                END,
                status = CASE
                    WHEN EXISTS (
                        SELECT 1
                        FROM coverage_intents AS ci
                        JOIN intents AS i
                          ON i.project_id = ci.project_id AND i.id = ci.intent_id
                        WHERE ci.project_id = ?
                          AND ci.coverage_id = coverage_items.id
                          AND ci.intent_id <> ?
                          AND i.status = 'open'
                          AND i.to_fact_id IS NULL
                    ) THEN 'untested'
                    ELSE 'failed'
                END,
                outcome = NULL,
                updated_at = ?
            WHERE project_id = ?
              AND id IN (
                  SELECT coverage_id FROM coverage_intents
                  WHERE project_id = ? AND intent_id = ?
              )
              AND execution_status <> 'completed'
            """,
            (
                project_id, intent_id, project_id, intent_id, now,
                project_id, project_id, intent_id,
            ),
        )
    else:
        conn.execute(
            """
            UPDATE intents
            SET worker = NULL,
                last_heartbeat_at = NULL,
                attempt_count = ?,
                last_error = ?,
                last_worker = ?,
                next_retry_at = ?,
                failed_at = ?,
                dead_lettered_at = NULL,
                status = 'open'
            WHERE id = ? AND project_id = ?
            """,
            (next_attempt, error, worker, utc_after_seconds(backoff_seconds), now, intent_id, project_id),
        )
        conn.execute(
            """
            UPDATE coverage_items
            SET execution_status = 'queued', status = 'untested', outcome = NULL, updated_at = ?
            WHERE project_id = ?
              AND id IN (
                  SELECT coverage_id FROM coverage_intents
                  WHERE project_id = ? AND intent_id = ?
              )
              AND execution_status <> 'completed'
            """,
            (now, project_id, project_id, intent_id),
        )
    if next_attempt >= max_attempts:
        conn.execute(
            """UPDATE hypotheses SET status = 'inconclusive', last_error = ?, updated_at = ?
               WHERE project_id = ? AND intent_id = ?
                 AND status NOT IN ('supported', 'refuted', 'waived')""",
            (error[:2000], now, project_id, intent_id),
        )
    else:
        conn.execute(
            """UPDATE hypotheses SET status = 'planned', last_error = ?, updated_at = ?
               WHERE project_id = ? AND intent_id = ?
                 AND status NOT IN ('supported', 'refuted', 'waived')""",
            (error[:2000], now, project_id, intent_id),
        )
    if next_attempt >= max_attempts:
        conclude_intent_with_failure_fact(
            conn,
            project_id,
            intent_id,
            worker=worker,
            error=error,
            attempt_count=next_attempt,
            failure_stage="execution_failed",
            now=now,
        )

    updated = conn.execute(
        "SELECT * FROM intents WHERE id = ? AND project_id = ?",
        (intent_id, project_id),
    ).fetchone()
    assert updated is not None
    return updated


def mark_reason_failure(
    conn: sqlite3.Connection,
    project_id: str,
    *,
    worker: str,
    error: str,
    max_attempts: int,
    backoff_seconds: int,
) -> sqlite3.Row:
    row = get_project_or_404(conn, project_id)
    now = utcnow()
    next_attempt = min((_row_get(row, "reason_attempt_count") or 0) + 1, max_attempts)
    exhausted = next_attempt >= max_attempts
    dead_lettered_at = now if exhausted else None
    next_retry_at = None if exhausted else utc_after_seconds(backoff_seconds)
    last_error = f"{worker}: {error}"
    conn.execute(
        """
        UPDATE projects
        SET reason_worker = NULL,
            reason_trigger = NULL,
            reason_started_at = NULL,
            reason_last_heartbeat_at = NULL,
            reason_attempt_count = ?,
            reason_last_error = ?,
            reason_next_retry_at = ?,
            reason_dead_lettered_at = ?,
            reason_last_outcome = ?,
            status = CASE WHEN ? THEN 'stopped' ELSE status END,
            completion_outcome = CASE WHEN ? THEN 'needs_attention' ELSE completion_outcome END,
            stop_reason_code = CASE WHEN ? THEN 'reason_retry_exhausted' ELSE stop_reason_code END,
            stop_reason_detail = CASE WHEN ? THEN ? ELSE stop_reason_detail END
        WHERE id = ?
        """,
        (
            next_attempt,
            last_error,
            next_retry_at,
            dead_lettered_at,
            "dead_lettered" if exhausted else "failed",
            exhausted,
            exhausted,
            exhausted,
            exhausted,
            f"Reason failed {next_attempt} times without advancing the Fact鈥揑ntent graph: {last_error}",
            project_id,
        ),
    )
    updated = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    assert updated is not None
    return updated


def clear_reason_failure(conn: sqlite3.Connection, project_id: str) -> sqlite3.Row:
    conn.execute(
        """
        UPDATE projects
        SET reason_attempt_count = 0,
            reason_last_error = NULL,
            reason_next_retry_at = NULL,
            reason_dead_lettered_at = NULL,
            reason_state_fingerprint = NULL,
            reason_last_outcome = NULL
        WHERE id = ?
        """,
        (project_id,),
    )
    updated = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    assert updated is not None
    return updated


def mark_reason_success(conn: sqlite3.Connection, project_id: str) -> sqlite3.Row:
    conn.execute(
        """UPDATE projects
        SET reason_attempt_count = 0,
            reason_last_error = NULL,
            reason_next_retry_at = NULL,
            reason_dead_lettered_at = NULL,
            reason_last_outcome = 'success'
        WHERE id = ?""",
        (project_id,),
    )
    updated = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    assert updated is not None
    return updated


def clear_completion_blocked(conn: sqlite3.Connection, project_id: str) -> sqlite3.Row:
    conn.execute(
        "UPDATE projects SET completion_blocked_at = NULL WHERE id = ?",
        (project_id,),
    )
    updated = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    assert updated is not None
    return updated

def get_completion_intent_or_409(conn: sqlite3.Connection, project_id: str) -> sqlite3.Row:
    rows = conn.execute(
        "SELECT * FROM intents WHERE project_id = ? AND to_fact_id = 'goal'",
        (project_id,),
    ).fetchall()
    if not rows:
        raise HTTPException(409, "Completed project is missing its completion intent")
    if len(rows) != 1:
        raise HTTPException(409, "Completed project has multiple completion intents")
    return rows[0]


def intent_to_model(conn: sqlite3.Connection, row: sqlite3.Row, project_id: str) -> Intent:
    sources = conn.execute(
        "SELECT fact_id FROM intent_sources WHERE intent_id = ? AND project_id = ? ORDER BY rowid",
        (row["id"], project_id),
    ).fetchall()
    coverage_rows = conn.execute(
        """
        SELECT coverage_id FROM coverage_intents
        WHERE project_id = ? AND intent_id = ?
        ORDER BY coverage_id
        """,
        (project_id, row["id"]),
    ).fetchall()
    return _intent_model(
        row,
        [source["fact_id"] for source in sources],
        [item["coverage_id"] for item in coverage_rows],
    )


def _intent_model(
    row: sqlite3.Row,
    source_ids: list[str],
    coverage_refs: list[str],
) -> Intent:
    return Intent(
        id=row["id"],
        **{"from": source_ids},
        to=row["to_fact_id"],
        description=row["description"],
        creator=row["creator"],
        worker=row["worker"],
        last_heartbeat_at=row["last_heartbeat_at"],
        created_at=row["created_at"],
        concluded_at=row["concluded_at"],
        target=_row_get(row, "target"),
        port=_row_get(row, "port"),
        path=_row_get(row, "path"),
        surface_type=_row_get(row, "surface_type"),
        action_kind=_row_get(row, "action_kind"),
        test_variant=_row_get(row, "test_variant"),
        priority=_row_get(row, "priority"),
        suggested_tools=_json_list(_row_get(row, "suggested_tools")),
        attempt_count=_row_get(row, "attempt_count") or 0,
        last_error=_row_get(row, "last_error"),
        last_worker=_row_get(row, "last_worker"),
        next_retry_at=_row_get(row, "next_retry_at"),
        failed_at=_row_get(row, "failed_at"),
        dead_lettered_at=_row_get(row, "dead_lettered_at"),
        status=_row_get(row, "status") or "open",
        work_key=_row_get(row, "work_key"),
        coverage_refs=coverage_refs,
        hypothesis_id=_row_get(row, "hypothesis_id"),
        execution_status=_row_get(row, "execution_status") or "pending",
        execution_artifact_ref=_row_get(row, "execution_artifact_ref"),
        execution_completed_at=_row_get(row, "execution_completed_at"),
        conclusion_attempt_count=_row_get(row, "conclusion_attempt_count") or 0,
        conclusion_last_error=_row_get(row, "conclusion_last_error"),
        commit_status=_row_get(row, "commit_status") or "pending",
    )


def build_intents(conn: sqlite3.Connection, project_id: str) -> list[Intent]:
    rows = conn.execute(
        "SELECT * FROM intents WHERE project_id = ? ORDER BY created_at",
        (project_id,),
    ).fetchall()
    source_ids: dict[str, list[str]] = {}
    for source in conn.execute(
        """SELECT intent_id, fact_id FROM intent_sources
        WHERE project_id = ? ORDER BY rowid""",
        (project_id,),
    ).fetchall():
        source_ids.setdefault(source["intent_id"], []).append(source["fact_id"])
    coverage_refs: dict[str, list[str]] = {}
    for link in conn.execute(
        """SELECT intent_id, coverage_id FROM coverage_intents
        WHERE project_id = ? ORDER BY coverage_id""",
        (project_id,),
    ).fetchall():
        coverage_refs.setdefault(link["intent_id"], []).append(link["coverage_id"])
    return [
        _intent_model(
            row,
            source_ids.get(row["id"], []),
            coverage_refs.get(row["id"], []),
        )
        for row in rows
    ]


def get_intent_timeout(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT intent_timeout FROM settings WHERE rowid = 1").fetchone()
    return row["intent_timeout"]


def get_reason_timeout(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT reason_timeout FROM settings WHERE rowid = 1").fetchone()
    return row["reason_timeout"]


def project_reason_from_row(row: sqlite3.Row) -> ProjectReason | None:
    if row["reason_worker"] is None:
        return None
    return ProjectReason(
        worker=row["reason_worker"],
        trigger=row["reason_trigger"],
        started_at=row["reason_started_at"],
        last_heartbeat_at=row["reason_last_heartbeat_at"],
    )


def project_meta_from_row(
    row: sqlite3.Row,
    conn: sqlite3.Connection | None = None,
    *,
    include_completion_blockers: bool = True,
) -> ProjectMeta:
    phase = row["phase"] if "phase" in row.keys() else "explore"
    mode = _row_get(row, "mode")
    if mode not in ("ctf", "real_website"):
        mode = "real_website" if (not bool(row["bootstrap_enabled"]) or phase == "recon") else "ctf"
    runtime_fields = (
        project_runtime_fields(
            conn,
            row,
            include_completion_blockers=include_completion_blockers,
        )
        if conn is not None
        else {}
    )
    return ProjectMeta(
        id=row["id"],
        title=row["title"],
        status=row["status"],
        bootstrap_enabled=bool(row["bootstrap_enabled"]),
        phase=phase,
        mode=mode,
        planning_version=int(_row_get(row, "planning_version") or 1),
        scope_policy=_json_model(_row_get(row, "scope_policy"), ScopePolicy),
        recon_profile=_json_model(_row_get(row, "recon_profile"), ReconProfile),
        reason_attempt_count=_row_get(row, "reason_attempt_count") or 0,
        reason_last_error=_row_get(row, "reason_last_error"),
        reason_next_retry_at=_row_get(row, "reason_next_retry_at"),
        reason_dead_lettered_at=_row_get(row, "reason_dead_lettered_at"),
        reason_state_fingerprint=_row_get(row, "reason_state_fingerprint"),
        reason_last_outcome=_row_get(row, "reason_last_outcome"),
        completion_outcome=_row_get(row, "completion_outcome"),
        stop_reason_code=_row_get(row, "stop_reason_code"),
        stop_reason_detail=_row_get(row, "stop_reason_detail"),
        phase_transition_last_error=_row_get(row, "phase_transition_last_error"),
        phase_transition_attempted_at=_row_get(row, "phase_transition_attempted_at"),
        completion_blocked_at=_row_get(row, "completion_blocked_at"),
        **runtime_fields,
        created_at=row["created_at"],
        reason=project_reason_from_row(row),
    )


def _row_get(row: sqlite3.Row, key: str):
    return row[key] if key in row.keys() else None


def _json_list(value: str | None) -> list[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, str)]


def _json_dict(value: str | None) -> dict:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _json_model(value: str | None, model_type):
    if not value:
        return model_type()
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return model_type()
    if not isinstance(parsed, dict):
        return model_type()
    return model_type.model_validate(parsed)


def clear_project_reason(conn: sqlite3.Connection, project_id: str) -> None:
    conn.execute(
        """
        UPDATE projects
        SET reason_worker = NULL,
            reason_trigger = NULL,
            reason_started_at = NULL,
            reason_last_heartbeat_at = NULL
        WHERE id = ?
        """,
        (project_id,),
    )


def expire_workers(conn: sqlite3.Connection, project_id: str | None = None) -> None:
    timeout = get_intent_timeout(conn)
    now = utcnow()
    where_clause = """
        WHERE to_fact_id IS NULL
          AND worker IS NOT NULL
          AND last_heartbeat_at IS NOT NULL
          AND (julianday(?) - julianday(last_heartbeat_at)) * 86400 > ?
    """
    params: tuple = (now, timeout)
    if project_id is not None:
        where_clause = where_clause.replace("WHERE ", "WHERE project_id = ? AND ", 1)
        params = (project_id, now, timeout)

    # Project reads call lease expiry frequently. Avoid opening a write
    # transaction when there is nothing stale to clean up.
    if conn.execute(f"SELECT 1 FROM intents {where_clause} LIMIT 1", params).fetchone() is None:
        return
    conn.execute(
        f"UPDATE intents SET worker = NULL {where_clause}",
        params,
    )


def expire_reason_leases(conn: sqlite3.Connection, project_id: str | None = None) -> None:
    timeout = get_reason_timeout(conn)
    now = utcnow()
    where_clause = """
        WHERE reason_worker IS NOT NULL
          AND reason_last_heartbeat_at IS NOT NULL
          AND (julianday(?) - julianday(reason_last_heartbeat_at)) * 86400 > ?
    """
    params: tuple = (now, timeout)
    if project_id is not None:
        where_clause = where_clause.replace("WHERE ", "WHERE id = ? AND ", 1)
        params = (project_id, now, timeout)
    if conn.execute(f"SELECT 1 FROM projects {where_clause} LIMIT 1", params).fetchone() is None:
        return
    conn.execute(
        f"""
        UPDATE projects
        SET reason_worker = NULL,
            reason_trigger = NULL,
            reason_started_at = NULL,
            reason_last_heartbeat_at = NULL
        {where_clause}
        """,
        params,
    )

def next_log_id(conn, project_id: str) -> str:
    return _next_scoped_id(conn, "task_log", "log", project_id)
@dataclass(slots=True)
class CoverageModelIndex:
    intents_by_coverage: dict[str, list[sqlite3.Row]]
    evidence_by_coverage: dict[str, list[sqlite3.Row]]
    task_logs_by_intent: dict[str, list[str]]

from __future__ import annotations

import sqlite3
import hashlib
import json
import re
from contextlib import contextmanager
from pathlib import Path
from typing import Generator
from urllib.parse import urlparse

DEFAULT_DB = Path.home() / ".local" / "share" / "skidc" / "skidc.db"

_db_path: Path | None = None

SCHEMA = """\
CREATE TABLE IF NOT EXISTS settings (
    intent_timeout INTEGER NOT NULL DEFAULT 15,
    reason_timeout INTEGER NOT NULL DEFAULT 15
);

INSERT OR IGNORE INTO settings (rowid, intent_timeout, reason_timeout) VALUES (1, 15, 15);

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    bootstrap_enabled INTEGER NOT NULL DEFAULT 1,
    phase TEXT NOT NULL DEFAULT 'explore',
    mode TEXT,
    planning_version INTEGER NOT NULL DEFAULT 1,
    scope_policy TEXT,
    recon_profile TEXT,
    reason_attempt_count INTEGER NOT NULL DEFAULT 0,
    reason_last_error TEXT,
    reason_next_retry_at TEXT,
    reason_dead_lettered_at TEXT,
    reason_state_fingerprint TEXT,
    reason_last_outcome TEXT,
    completion_outcome TEXT,
    stop_reason_code TEXT,
    stop_reason_detail TEXT,
    phase_transition_last_error TEXT,
    phase_transition_attempted_at TEXT,
    completion_blocked_at TEXT,
    created_at TEXT NOT NULL,
    reason_worker TEXT,
    reason_trigger TEXT,
    reason_started_at TEXT,
    reason_last_heartbeat_at TEXT
);

CREATE TABLE IF NOT EXISTS facts (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    description TEXT NOT NULL,
    scope TEXT,
    vuln_type TEXT,
    severity TEXT,
    parent_fact TEXT,
    verification_of TEXT,
    goal_type TEXT,
    status TEXT,
    recon_category TEXT,
    recon_executed INTEGER,
    recon_found_results INTEGER,
    recon_tool TEXT,
    recon_target TEXT,
    recon_evidence_ref TEXT,
    schema_version INTEGER NOT NULL DEFAULT 1,
    kind TEXT NOT NULL DEFAULT 'legacy_text',
    summary TEXT,
    subject TEXT NOT NULL DEFAULT '{}',
    data TEXT NOT NULL DEFAULT '{}',
    parent_fact_ids TEXT NOT NULL DEFAULT '[]',
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    confidence REAL,
    created_by TEXT,
    created_at TEXT,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE IF NOT EXISTS intents (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    to_fact_id TEXT,
    description TEXT NOT NULL,
    creator TEXT NOT NULL,
    worker TEXT,
    last_heartbeat_at TEXT,
    created_at TEXT NOT NULL,
    concluded_at TEXT,
    target TEXT,
    port INTEGER,
    path TEXT,
    surface_type TEXT,
    action_kind TEXT,
    test_variant TEXT,
    priority INTEGER,
    suggested_tools TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    last_worker TEXT,
    next_retry_at TEXT,
    failed_at TEXT,
    dead_lettered_at TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    work_key TEXT,
    hypothesis_id TEXT,
    execution_status TEXT NOT NULL DEFAULT 'pending',
    execution_artifact_ref TEXT,
    execution_completed_at TEXT,
    conclusion_attempt_count INTEGER NOT NULL DEFAULT 0,
    conclusion_last_error TEXT,
    commit_status TEXT NOT NULL DEFAULT 'pending',
    PRIMARY KEY (id, project_id)
);
CREATE TABLE IF NOT EXISTS intent_sources (
    intent_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    fact_id TEXT NOT NULL,
    PRIMARY KEY (intent_id, project_id, fact_id),
    FOREIGN KEY (intent_id, project_id) REFERENCES intents(id, project_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS hints (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    creator TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE IF NOT EXISTS counters (
    name TEXT PRIMARY KEY,
    value INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO counters (name, value) VALUES ('project', 0);

CREATE TABLE IF NOT EXISTS scoped_counters (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, kind)
);

CREATE TABLE IF NOT EXISTS attack_paths (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    fact_chain TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'hypothesis',
    suggested_status TEXT NOT NULL DEFAULT 'hypothesis',
    status_reason TEXT,
    signature TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE IF NOT EXISTS attack_path_steps (
    project_id TEXT NOT NULL,
    path_id TEXT NOT NULL,
    fact_id TEXT NOT NULL,
    required INTEGER NOT NULL DEFAULT 1,
    step_order INTEGER NOT NULL,
    PRIMARY KEY (project_id, path_id, fact_id),
    UNIQUE (project_id, path_id, step_order),
    FOREIGN KEY (path_id, project_id) REFERENCES attack_paths(id, project_id) ON DELETE CASCADE,
    FOREIGN KEY (fact_id, project_id) REFERENCES facts(id, project_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_attack_path_steps_fact
ON attack_path_steps (project_id, fact_id);

CREATE TABLE IF NOT EXISTS coverage_items (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    item_type TEXT NOT NULL,
    target TEXT,
    port INTEGER,
    method TEXT,
    path TEXT,
    param TEXT,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'untested',
    priority INTEGER,
    evidence_ref TEXT,
    source_fact_id TEXT,
    intent_id TEXT,
    surface_group TEXT,
    surface_fingerprint TEXT,
    test_family TEXT,
    test_variants TEXT,
    auth_context TEXT,
    roles TEXT,
    applicability_reason TEXT,
    required INTEGER NOT NULL DEFAULT 1,
    disposition TEXT NOT NULL DEFAULT 'required',
    disposition_reason TEXT,
    standard_refs TEXT,
    execution_status TEXT NOT NULL DEFAULT 'untested',
    outcome TEXT,
    applicability_status TEXT NOT NULL DEFAULT 'applicable',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE IF NOT EXISTS surface_inventory (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    surface_group TEXT NOT NULL,
    target TEXT,
    port INTEGER,
    method TEXT,
    path_template TEXT,
    params TEXT,
    surface_type TEXT,
    auth_context TEXT,
    roles TEXT,
    traits TEXT,
    source_fact_id TEXT,
    behavior_key TEXT,
    operation_type TEXT NOT NULL DEFAULT 'unknown',
    capabilities TEXT,
    evidence_fact_ids TEXT,
    planning_status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (id, project_id),
    UNIQUE (project_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_surface_inventory_group
ON surface_inventory (project_id, surface_group);

CREATE TABLE IF NOT EXISTS hypotheses (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    behavior_key TEXT NOT NULL,
    coverage_id TEXT,
    test_family TEXT NOT NULL,
    test_variant TEXT NOT NULL,
    rationale TEXT NOT NULL,
    trigger_fact_ids TEXT NOT NULL DEFAULT '[]',
    confidence REAL NOT NULL,
    impact REAL NOT NULL DEFAULT 1,
    goal_value REAL NOT NULL DEFAULT 1,
    novelty REAL NOT NULL DEFAULT 1,
    estimated_cost REAL NOT NULL DEFAULT 1,
    score REAL NOT NULL,
    required INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'candidate',
    intent_id TEXT,
    basis_fingerprint TEXT NOT NULL,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (id, project_id),
    UNIQUE (project_id, behavior_key, test_family, test_variant, basis_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_hypotheses_planning
ON hypotheses (project_id, status, score DESC);

CREATE TABLE IF NOT EXISTS coverage_intents (
    project_id TEXT NOT NULL,
    coverage_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, coverage_id, intent_id),
    FOREIGN KEY (coverage_id, project_id) REFERENCES coverage_items(id, project_id) ON DELETE CASCADE,
    FOREIGN KEY (intent_id, project_id) REFERENCES intents(id, project_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS coverage_evidence (
    project_id TEXT NOT NULL,
    coverage_id TEXT NOT NULL,
    fact_id TEXT NOT NULL,
    relation TEXT NOT NULL DEFAULT 'supports',
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, coverage_id, fact_id),
    FOREIGN KEY (coverage_id, project_id) REFERENCES coverage_items(id, project_id) ON DELETE CASCADE,
    FOREIGN KEY (fact_id, project_id) REFERENCES facts(id, project_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_coverage_intents_by_intent
ON coverage_intents (project_id, intent_id);

CREATE INDEX IF NOT EXISTS idx_coverage_evidence_by_fact
ON coverage_evidence (project_id, fact_id);

CREATE TABLE IF NOT EXISTS task_logs (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    task_type TEXT NOT NULL,
    intent_id TEXT,
    worker_name TEXT NOT NULL,
    phase TEXT NOT NULL,
    stdin TEXT,
    stdout TEXT,
    stderr TEXT,
    return_code INTEGER,
    timed_out INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER,
    stdout_truncated INTEGER NOT NULL DEFAULT 0,
    stderr_truncated INTEGER NOT NULL DEFAULT 0,
    artifact_ref TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (id, project_id)
);
"""


def configure(path: Path) -> None:
    global _db_path
    if _db_path is not None:
        return
    _db_path = path
    _db_path.parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
        _migrate(conn)


# Columns added after the initial release. CREATE TABLE IF NOT EXISTS will NOT add
# these to a table that predates them, so we introspect and ALTER only what is
# missing — idempotent across restarts and safe on a fresh DB (where SCHEMA already
# created them, so nothing is added).
_FACT_ADDED_COLUMNS = {
    "scope": "TEXT",
    "vuln_type": "TEXT",
    "severity": "TEXT",
    "parent_fact": "TEXT",
    "goal_type": "TEXT",
    "status": "TEXT",
    "recon_category": "TEXT",
    "recon_executed": "INTEGER",
    "recon_found_results": "INTEGER",
    "verification_of": "TEXT",
    "recon_tool": "TEXT",
    "recon_target": "TEXT",
    "recon_evidence_ref": "TEXT",
    "schema_version": "INTEGER NOT NULL DEFAULT 1",
    "kind": "TEXT NOT NULL DEFAULT 'legacy_text'",
    "summary": "TEXT",
    "subject": "TEXT NOT NULL DEFAULT '{}'",
    "data": "TEXT NOT NULL DEFAULT '{}'",
    "parent_fact_ids": "TEXT NOT NULL DEFAULT '[]'",
    "evidence_refs": "TEXT NOT NULL DEFAULT '[]'",
    "confidence": "REAL",
    "created_by": "TEXT",
    "created_at": "TEXT",
}


def _backfill_fact_envelopes(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        UPDATE facts
        SET schema_version = COALESCE(schema_version, 1),
            kind = CASE
                WHEN id = 'origin' THEN 'project_origin'
                WHEN id = 'goal' THEN 'project_goal'
                WHEN NULLIF(kind, '') IS NULL THEN 'legacy_text'
                ELSE kind
            END,
            summary = COALESCE(NULLIF(summary, ''), SUBSTR(description, 1, 320)),
            subject = COALESCE(NULLIF(subject, ''), '{}'),
            data = COALESCE(NULLIF(data, ''), '{}'),
            parent_fact_ids = CASE
                WHEN COALESCE(parent_fact_ids, '[]') = '[]' AND NULLIF(parent_fact, '') IS NOT NULL
                THEN json_array(parent_fact)
                ELSE COALESCE(NULLIF(parent_fact_ids, ''), '[]')
            END,
            evidence_refs = CASE
                WHEN COALESCE(evidence_refs, '[]') = '[]' AND NULLIF(recon_evidence_ref, '') IS NOT NULL
                THEN json_array(recon_evidence_ref)
                ELSE COALESCE(NULLIF(evidence_refs, ''), '[]')
            END,
            created_at = COALESCE(
                created_at,
                (SELECT projects.created_at FROM projects WHERE projects.id = facts.project_id)
            )
        """
    )


_PROJECT_ADDED_COLUMNS = {
    "phase": "TEXT NOT NULL DEFAULT 'explore'",
    "mode": "TEXT",
    "planning_version": "INTEGER NOT NULL DEFAULT 1",
    "scope_policy": "TEXT",
    "recon_profile": "TEXT",
    "reason_attempt_count": "INTEGER NOT NULL DEFAULT 0",
    "reason_last_error": "TEXT",
    "reason_next_retry_at": "TEXT",
    "reason_dead_lettered_at": "TEXT",
    "reason_state_fingerprint": "TEXT",
    "reason_last_outcome": "TEXT",
    "completion_outcome": "TEXT",
    "stop_reason_code": "TEXT",
    "stop_reason_detail": "TEXT",
    "phase_transition_last_error": "TEXT",
    "phase_transition_attempted_at": "TEXT",
    "completion_blocked_at": "TEXT",
}

_INTENT_ADDED_COLUMNS = {
    "target": "TEXT",
    "port": "INTEGER",
    "path": "TEXT",
    "surface_type": "TEXT",
    "action_kind": "TEXT",
    "test_variant": "TEXT",
    "priority": "INTEGER",
    "suggested_tools": "TEXT",
    "attempt_count": "INTEGER NOT NULL DEFAULT 0",
    "last_error": "TEXT",
    "last_worker": "TEXT",
    "next_retry_at": "TEXT",
    "failed_at": "TEXT",
    "dead_lettered_at": "TEXT",
    "status": "TEXT NOT NULL DEFAULT 'open'",
    "work_key": "TEXT",
    "hypothesis_id": "TEXT",
    "execution_status": "TEXT NOT NULL DEFAULT 'pending'",
    "execution_artifact_ref": "TEXT",
    "execution_completed_at": "TEXT",
    "conclusion_attempt_count": "INTEGER NOT NULL DEFAULT 0",
    "conclusion_last_error": "TEXT",
    "commit_status": "TEXT NOT NULL DEFAULT 'pending'",
}

_TASK_LOG_ADDED_COLUMNS = {
    "stdin": "TEXT",
    "stdout_truncated": "INTEGER NOT NULL DEFAULT 0",
    "stderr_truncated": "INTEGER NOT NULL DEFAULT 0",
    "artifact_ref": "TEXT",
}

_ATTACK_PATH_ADDED_COLUMNS = {
    "status": "TEXT NOT NULL DEFAULT 'hypothesis'",
    "suggested_status": "TEXT NOT NULL DEFAULT 'hypothesis'",
    "status_reason": "TEXT",
    "signature": "TEXT",
    "updated_at": "TEXT",
}

_COVERAGE_ADDED_COLUMNS = {
    "surface_group": "TEXT",
    "surface_fingerprint": "TEXT",
    "test_family": "TEXT",
    "test_variants": "TEXT",
    "auth_context": "TEXT",
    "roles": "TEXT",
    "applicability_reason": "TEXT",
    "required": "INTEGER NOT NULL DEFAULT 1",
    "disposition": "TEXT NOT NULL DEFAULT 'required'",
    "disposition_reason": "TEXT",
    "standard_refs": "TEXT",
    "execution_status": "TEXT NOT NULL DEFAULT 'untested'",
    "outcome": "TEXT",
    "applicability_status": "TEXT NOT NULL DEFAULT 'applicable'",
}

_SURFACE_ADDED_COLUMNS = {
    "behavior_key": "TEXT",
    "operation_type": "TEXT NOT NULL DEFAULT 'unknown'",
    "capabilities": "TEXT",
    "evidence_fact_ids": "TEXT",
    "planning_status": "TEXT NOT NULL DEFAULT 'pending'",
}

_DEFAULT_SCOPE_POLICY = {
    "allowed_targets": [],
    "blocked_targets": [],
    "allowed_ports": [],
    "blocked_ports": [],
    "allowed_paths": [],
    "blocked_paths": [],
    "support_ports": [],
    "allow_subdomains": True,
    "allow_domain_scan": True,
    "rate_limits": {},
    "passive_only": False,
}
_DEFAULT_RECON_PROFILE = {
    "target_type": "domain",
    "required_categories": ["port_scan", "subdomain", "directory", "asset"],
    "optional_categories": [],
    "disabled_categories": [],
    "max_coverage_intents": 200,
    "coverage_batch_size": 20,
    "hypothesis_batch_size": 3,
    "hypothesis_min_score": 1.0,
    "max_hypotheses": 24,
    "frontier_breadth_slots": 1,
    "branch_no_progress_limit": 2,
    "reason_context_limit": 80,
}


def _backfill_project_defaults(conn: sqlite3.Connection) -> None:
    for row in conn.execute(
        "SELECT id, bootstrap_enabled, phase, mode, scope_policy, recon_profile FROM projects"
    ).fetchall():
        phase = row["phase"] if row["phase"] in {"recon", "explore"} else "explore"
        mode = row["mode"]
        if mode not in {"ctf", "real_website"}:
            mode = "real_website" if (not bool(row["bootstrap_enabled"]) or phase == "recon") else "ctf"
        scope_policy = _canonical_json_object(row["scope_policy"], _DEFAULT_SCOPE_POLICY)
        recon_profile = _canonical_json_object(row["recon_profile"], _DEFAULT_RECON_PROFILE)
        conn.execute(
            """
            UPDATE projects
            SET phase = ?, mode = ?, scope_policy = ?, recon_profile = ?
            WHERE id = ?
            """,
            (phase, mode, scope_policy, recon_profile, row["id"]),
        )


def _canonical_json_object(value: str | None, default: dict) -> str:
    try:
        parsed = json.loads(value) if value else None
    except (TypeError, ValueError):
        parsed = None
    if not isinstance(parsed, dict):
        parsed = default
    return json.dumps(parsed, separators=(",", ":"), sort_keys=True)


def _backfill_intent_statuses(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        UPDATE intents
        SET status = CASE
                WHEN to_fact_id IS NOT NULL OR concluded_at IS NOT NULL THEN 'concluded'
                WHEN dead_lettered_at IS NOT NULL THEN 'dead_lettered'
                ELSE 'open'
            END
        WHERE status IS NULL
           OR status = ''
           OR (status = 'open' AND (to_fact_id IS NOT NULL OR concluded_at IS NOT NULL))
           OR (status = 'open' AND dead_lettered_at IS NOT NULL)
        """
    )


def _backfill_legacy_coverage_surfaces(conn: sqlite3.Connection) -> None:
    support_ports_by_project: dict[str, set[int]] = {}
    for project in conn.execute("SELECT id, scope_policy FROM projects").fetchall():
        try:
            policy = json.loads(project["scope_policy"] or "{}")
        except (TypeError, ValueError):
            policy = {}
        raw_ports = policy.get("support_ports", []) if isinstance(policy, dict) else []
        support_ports_by_project[project["id"]] = {
            int(port) for port in raw_ports
            if isinstance(port, int) or (isinstance(port, str) and port.isdigit())
        }

    rows = conn.execute(
        """
        SELECT * FROM coverage_items
        WHERE item_type IN ('route', 'param', 'form', 'upload_point', 'admin_route', 'service')
        ORDER BY project_id, created_at, id
        """
    ).fetchall()
    for row in rows:
        surface = _legacy_coverage_surface(
            row,
            support_ports=support_ports_by_project.get(row["project_id"], set()),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO surface_inventory (
                id, project_id, fingerprint, surface_group, target, port, method,
                path_template, params, surface_type, auth_context, roles, traits,
                source_fact_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"legacy:{row['id']}",
                row["project_id"],
                surface["fingerprint"],
                surface["surface_group"],
                surface["target"],
                surface["port"],
                surface["method"],
                surface["path_template"],
                json.dumps(surface["params"]),
                surface["surface_type"],
                surface["auth_context"],
                "[]",
                json.dumps(surface["traits"], sort_keys=True),
                row["source_fact_id"],
                row["created_at"],
                row["updated_at"],
            ),
        )
        conn.execute(
            """
            UPDATE coverage_items
            SET surface_group = COALESCE(NULLIF(surface_group, ''), ?),
                auth_context = COALESCE(NULLIF(auth_context, ''), ?),
                test_variants = COALESCE(test_variants, '[]'),
                roles = COALESCE(roles, '[]'),
                standard_refs = COALESCE(standard_refs, '[]')
            WHERE project_id = ? AND id = ?
            """,
            (surface["surface_group"], surface["auth_context"], row["project_id"], row["id"]),
        )
        if surface["traits"]["support_service"]:
            conn.execute(
                """
                UPDATE coverage_items
                SET test_family = 'support_service',
                    surface_group = ?,
                    required = 0,
                    applicability_reason = COALESCE(
                        NULLIF(applicability_reason, ''),
                        'Explicitly allowed support service; report separately from Web findings.'
                    ),
                    standard_refs = ?
                WHERE project_id = ? AND id = ?
                """,
                (
                    surface["surface_group"],
                    json.dumps(["WSTG-v4.2-CONF", "ASVS-v5.0.0-Chapter-13", "Scope-Policy-Support-Service"]),
                    row["project_id"],
                    row["id"],
                ),
            )


def _legacy_coverage_surface(row: sqlite3.Row, *, support_ports: set[int]) -> dict:
    target = row["target"]
    path = row["path"]
    port = row["port"]
    if target and "://" in target:
        parsed = urlparse(target)
        target = parsed.hostname or target
        port = port or parsed.port or (443 if parsed.scheme == "https" else 80)
        path = path or parsed.path or None
    path_template = (path.split("?", 1)[0] or "/") if path else None
    if path_template and not path_template.startswith("/"):
        path_template = f"/{path_template}"
    if path_template:
        path_template = re.sub(
            r"/(?:(?:\d+)|(?:[0-9a-f]{16,})|(?:[0-9a-f-]{32,}))(?=/|$)",
            "/{id}",
            path_template,
            flags=re.IGNORECASE,
        )
    method = (row["method"] or "GET").upper()
    params = sorted({part.strip() for part in (row["param"] or "").split(",") if part.strip()})
    surface_type = row["item_type"]
    text = " ".join(
        str(value or "")
        for value in (surface_type, target, path_template, row["param"], row["description"])
    ).casefold()
    support_service = surface_type == "service" and port in support_ports
    auth = any(token in text for token in ("login", "signin", "auth", "password", "register", "recover"))
    admin = "admin" in text or "manage" in text
    upload = surface_type == "upload_point" or "upload" in text
    api = any(token in text for token in ("/api/", "graphql", "application/json", "rest api"))
    writes = method in {"POST", "PUT", "PATCH", "DELETE"} or surface_type in {"form", "upload_point"}
    has_input = bool(params) or surface_type in {"form", "param", "upload_point"}
    auth_context = row["auth_context"] or ("anonymous" if auth else "admin" if admin else "anonymous")
    traits = {
        "support_service": support_service,
        "out_of_scope_support": surface_type == "service" and not support_service,
        "static": bool(path_template and re.search(r"\.(?:css|js|png|jpe?g|gif|svg|ico|woff2?)$", path_template, re.I)),
        "auth": auth,
        "admin": admin,
        "has_input": has_input,
        "writes": writes,
        "upload": upload,
        "download": any(token in text for token in ("download", "export", "attachment")),
        "api": api,
        "object_reference": bool(set(params) & {"id", "uid", "user_id", "cid", "pid", "order_id", "file_id"}),
        "url_input": any(token in text for token in ("url", "uri", "webhook", "callback", "remote", "fetch")),
        "xml_input": "xml" in text or "soap" in text,
        "template_input": any(token in text for token in ("template", "render", "view")),
        "reflects_input": has_input and any(token in text for token in ("search", "contact", "message", "name", "query")),
    }
    surface_group = row["surface_group"] or _legacy_surface_group(
        target, port, path_template, surface_type, traits
    )
    identity = {
        "target": (target or "").casefold(),
        "port": port,
        "method": method,
        "path": path_template,
        "params": params,
        "auth": auth_context.casefold(),
    }
    fingerprint = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:24]
    return {
        "fingerprint": fingerprint,
        "surface_group": surface_group,
        "target": target,
        "port": port,
        "method": method,
        "path_template": path_template,
        "params": params,
        "surface_type": surface_type,
        "auth_context": auth_context,
        "traits": traits,
    }


def _legacy_surface_group(
    target: str | None,
    port: int | None,
    path: str | None,
    surface_type: str,
    traits: dict,
) -> str:
    if traits["support_service"]:
        return f"support:{target or 'host'}:{port or 'unknown'}"
    if traits["static"]:
        parent = "/".join((path or "/static").split("/")[:-1]) or "/"
        return f"static:{parent}"
    if traits["auth"]:
        return f"auth:{path or '/'}"
    if traits["upload"]:
        return f"upload:{path or '/'}"
    if traits["api"]:
        segments = [part for part in (path or "/").split("/") if part]
        meaningful = [part for part in segments if part.casefold() not in {"api", "v1", "v2", "v3"}]
        return "api:" + (meaningful[0] if meaningful else "root")
    segments = [part for part in (path or "/").split("/") if part]
    if not segments:
        return f"web:{target or 'origin'}:{port or 'default'}"
    leaf = re.sub(r"\.[a-z0-9]+$", "", segments[-1], flags=re.IGNORECASE)
    prefix = "/".join(segments[:-1][-1:] + [leaf])
    return f"web:/{prefix}"


def _migrate(conn: sqlite3.Connection) -> None:
    existing_facts = {row["name"] for row in conn.execute("PRAGMA table_info(facts)")}
    for column, decl in _FACT_ADDED_COLUMNS.items():
        if column not in existing_facts:
            conn.execute(f"ALTER TABLE facts ADD COLUMN {column} {decl}")

    existing_projects = {row["name"] for row in conn.execute("PRAGMA table_info(projects)")}
    for column, decl in _PROJECT_ADDED_COLUMNS.items():
        if column not in existing_projects:
            conn.execute(f"ALTER TABLE projects ADD COLUMN {column} {decl}")
    _backfill_project_defaults(conn)
    _backfill_fact_envelopes(conn)

    existing_intents = {row["name"] for row in conn.execute("PRAGMA table_info(intents)")}
    for column, decl in _INTENT_ADDED_COLUMNS.items():
        if column not in existing_intents:
            conn.execute(f"ALTER TABLE intents ADD COLUMN {column} {decl}")
    _backfill_intent_statuses(conn)
    # Work identity prevents two workers from executing the same live job at
    # once. Terminal attempts must release that lock so bounded retries and
    # independent verification can create replacement Intents.
    conn.execute("DROP INDEX IF EXISTS idx_intents_project_work_key")
    conn.execute(
        """
        CREATE UNIQUE INDEX idx_intents_project_work_key
        ON intents (project_id, work_key)
        WHERE work_key IS NOT NULL AND status = 'open'
        """
    )

    conn.execute(
        """
        UPDATE intents
        SET test_variant = (
            SELECT vuln_type FROM facts
            WHERE facts.project_id = intents.project_id AND facts.id = intents.to_fact_id
        )
        WHERE test_variant IS NULL AND to_fact_id IS NOT NULL
        """
    )

    existing_task_logs = {row["name"] for row in conn.execute("PRAGMA table_info(task_logs)")}
    for column, decl in _TASK_LOG_ADDED_COLUMNS.items():
        if column not in existing_task_logs:
            conn.execute(f"ALTER TABLE task_logs ADD COLUMN {column} {decl}")

    existing_attack_paths = {row["name"] for row in conn.execute("PRAGMA table_info(attack_paths)")}
    preserve_legacy_attack_path_status = "suggested_status" not in existing_attack_paths
    for column, decl in _ATTACK_PATH_ADDED_COLUMNS.items():
        if column not in existing_attack_paths:
            conn.execute(f"ALTER TABLE attack_paths ADD COLUMN {column} {decl}")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS attack_path_steps (
            project_id TEXT NOT NULL,
            path_id TEXT NOT NULL,
            fact_id TEXT NOT NULL,
            required INTEGER NOT NULL DEFAULT 1,
            step_order INTEGER NOT NULL,
            PRIMARY KEY (project_id, path_id, fact_id),
            UNIQUE (project_id, path_id, step_order),
            FOREIGN KEY (path_id, project_id) REFERENCES attack_paths(id, project_id) ON DELETE CASCADE,
            FOREIGN KEY (fact_id, project_id) REFERENCES facts(id, project_id) ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_attack_path_steps_fact ON attack_path_steps (project_id, fact_id)"
    )
    _migrate_attack_paths(conn, preserve_legacy_status=preserve_legacy_attack_path_status)
    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_attack_paths_signature
        ON attack_paths (project_id, signature)
        WHERE signature IS NOT NULL
        """
    )

    existing_coverage = {row["name"] for row in conn.execute("PRAGMA table_info(coverage_items)")}
    for column, decl in _COVERAGE_ADDED_COLUMNS.items():
        if column not in existing_coverage:
            conn.execute(f"ALTER TABLE coverage_items ADD COLUMN {column} {decl}")

    existing_surfaces = {row["name"] for row in conn.execute("PRAGMA table_info(surface_inventory)")}
    for column, decl in _SURFACE_ADDED_COLUMNS.items():
        if column not in existing_surfaces:
            conn.execute(f"ALTER TABLE surface_inventory ADD COLUMN {column} {decl}")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_surface_inventory_behavior "
        "ON surface_inventory (project_id, behavior_key)"
    )
    conn.execute(
        "UPDATE surface_inventory SET behavior_key = COALESCE(behavior_key, surface_group, fingerprint), "
        "evidence_fact_ids = COALESCE(evidence_fact_ids, '[]'), "
        "capabilities = COALESCE(capabilities, '[]')"
    )

    conn.execute(
        """
        UPDATE coverage_items
        SET disposition = CASE
                WHEN required <> 0 THEN 'required'
                WHEN applicability_reason LIKE 'Deferred:%' THEN 'deferred'
                ELSE 'excluded'
            END,
            disposition_reason = CASE
                WHEN required = 0 THEN COALESCE(disposition_reason, applicability_reason)
                ELSE disposition_reason
            END
        WHERE disposition IS NULL OR disposition = ''
           OR (required = 0 AND disposition = 'required')
        """
    )

    conn.execute(
        """
        UPDATE coverage_items
        SET execution_status = CASE status
                WHEN 'untested' THEN 'untested'
                WHEN 'testing' THEN 'testing'
                WHEN 'failed' THEN 'blocked'
                ELSE 'completed'
            END,
            outcome = CASE status
                WHEN 'not_vulnerable' THEN 'not_vulnerable'
                WHEN 'inconclusive' THEN 'inconclusive'
                WHEN 'failed' THEN NULL
                WHEN 'confirmed' THEN COALESCE(outcome, 'inconclusive')
                ELSE outcome
            END
        WHERE execution_status IS NULL
           OR execution_status = ''
           OR (execution_status = 'untested' AND status <> 'untested')
        """
    )
    _backfill_legacy_coverage_surfaces(conn)

    migration_time = "1970-01-01T00:00:00Z"
    conn.execute(
        """
        INSERT OR IGNORE INTO coverage_intents (project_id, coverage_id, intent_id, created_at)
        SELECT project_id, id, intent_id, COALESCE(updated_at, created_at, ?)
        FROM coverage_items
        WHERE intent_id IS NOT NULL
        """,
        (migration_time,),
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO coverage_evidence (project_id, coverage_id, fact_id, relation, created_at)
        SELECT ci.project_id, ci.coverage_id, i.to_fact_id,
               CASE
                   WHEN LOWER(COALESCE(f.status, '')) IN ('not_vulnerable', 'refuted', 'false_positive') THEN 'refutes'
                   WHEN LOWER(COALESCE(f.status, '')) IN ('confirmed', 'verified') THEN 'supports'
                   ELSE 'limits'
               END,
               COALESCE(i.concluded_at, i.created_at, ?)
        FROM coverage_intents ci
        JOIN intents i ON i.project_id = ci.project_id AND i.id = ci.intent_id
        JOIN facts f ON f.project_id = i.project_id AND f.id = i.to_fact_id
        WHERE i.to_fact_id IS NOT NULL
        """,
        (migration_time,),
    )
    conn.execute(
        """
        UPDATE coverage_items
        SET execution_status = 'completed', outcome = 'vulnerable'
        WHERE status = 'confirmed'
          AND EXISTS (
              SELECT 1
              FROM coverage_evidence ce
              JOIN facts f ON f.project_id = ce.project_id AND f.id = ce.fact_id
              WHERE ce.project_id = coverage_items.project_id
                AND ce.coverage_id = coverage_items.id
                AND LOWER(COALESCE(f.status, '')) IN ('confirmed', 'verified')
          )
        """
    )


def _migrate_attack_paths(conn: sqlite3.Connection, *, preserve_legacy_status: bool) -> None:
    rows = conn.execute("SELECT * FROM attack_paths ORDER BY project_id, created_at, id").fetchall()
    used_signatures: set[tuple[str, str]] = set()
    for row in rows:
        try:
            raw_chain = json.loads(row["fact_chain"])
        except (TypeError, ValueError):
            raw_chain = []
        chain: list[str] = []
        for value in raw_chain if isinstance(raw_chain, list) else []:
            fact_id = str(value).strip()
            if fact_id and fact_id not in chain:
                chain.append(fact_id)
        signature = hashlib.sha256(
            json.dumps(chain, separators=(",", ":"), ensure_ascii=True).encode()
        ).hexdigest()[:24]
        key = (row["project_id"], signature)
        if key in used_signatures:
            signature = f"{signature}:legacy:{row['id']}"
        used_signatures.add((row["project_id"], signature))
        suggested = (
            row["status"] if preserve_legacy_status else row["suggested_status"]
        ) or "hypothesis"
        if suggested not in {"hypothesis", "confirmed", "inconclusive", "refuted"}:
            suggested = "hypothesis"
        suggested_expression = "?" if preserve_legacy_status else "COALESCE(NULLIF(suggested_status, ''), ?)"
        conn.execute(
            f"""
            UPDATE attack_paths
            SET signature = COALESCE(signature, ?),
                suggested_status = {suggested_expression},
                updated_at = COALESCE(updated_at, created_at)
            WHERE project_id = ? AND id = ?
            """,
            (signature, suggested, row["project_id"], row["id"]),
        )
        for order, fact_id in enumerate(chain):
            exists = conn.execute(
                "SELECT 1 FROM facts WHERE project_id = ? AND id = ?",
                (row["project_id"], fact_id),
            ).fetchone()
            if exists is None:
                continue
            conn.execute(
                """
                INSERT OR IGNORE INTO attack_path_steps (
                    project_id, path_id, fact_id, required, step_order
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (row["project_id"], row["id"], fact_id, int(fact_id not in {"origin", "goal"}), order),
            )


@contextmanager
def get_conn() -> Generator[sqlite3.Connection, None, None]:
    assert _db_path is not None
    conn = sqlite3.connect(str(_db_path), timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

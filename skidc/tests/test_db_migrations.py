from __future__ import annotations

import json
import sqlite3

from skidc.server import db


LEGACY_SCHEMA = """
CREATE TABLE projects (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    bootstrap_enabled INTEGER NOT NULL DEFAULT 1,
    scope_policy TEXT,
    created_at TEXT NOT NULL,
    reason_worker TEXT,
    reason_trigger TEXT,
    reason_started_at TEXT,
    reason_last_heartbeat_at TEXT
);

CREATE TABLE facts (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT,
    vuln_type TEXT,
    severity TEXT,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE intents (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    to_fact_id TEXT,
    description TEXT NOT NULL,
    creator TEXT NOT NULL,
    worker TEXT,
    last_heartbeat_at TEXT,
    created_at TEXT NOT NULL,
    concluded_at TEXT,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE attack_paths (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    fact_chain TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'hypothesis',
    created_at TEXT NOT NULL,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE coverage_items (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL,
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
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE task_logs (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    task_type TEXT NOT NULL,
    intent_id TEXT,
    worker_name TEXT NOT NULL,
    phase TEXT NOT NULL,
    stdout TEXT,
    stderr TEXT,
    return_code INTEGER,
    timed_out INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER,
    created_at TEXT NOT NULL,
    PRIMARY KEY (id, project_id)
);
"""


def test_legacy_database_migrates_and_backfills_idempotently(tmp_path, monkeypatch) -> None:
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.executescript(LEGACY_SCHEMA)
    conn.execute(
        """
        INSERT INTO projects (
            id, title, status, bootstrap_enabled, scope_policy, created_at
        ) VALUES (?, ?, 'active', 0, ?, ?)
        """,
        ("proj_legacy", "legacy", json.dumps({"support_ports": [3306]}), "2025-01-01T00:00:00Z"),
    )
    conn.executemany(
        """
        INSERT INTO facts (
            id, project_id, description, status, vuln_type, severity
        ) VALUES (?, 'proj_legacy', ?, ?, ?, ?)
        """,
        [
            ("origin", "http://legacy.test/", None, None, None),
            ("goal", "assess legacy site", None, None, None),
            ("f001", "MySQL 3306 accepted the authorized weak credential.", "confirmed", "weak_credentials", "high"),
        ],
    )
    conn.execute(
        """
        INSERT INTO intents (
            id, project_id, to_fact_id, description, creator, worker,
            last_heartbeat_at, created_at, concluded_at
        ) VALUES ('i001', 'proj_legacy', 'f001', 'verify MySQL', 'reasoner', 'worker', ?, ?, ?)
        """,
        ("2025-01-01T00:01:00Z", "2025-01-01T00:00:30Z", "2025-01-01T00:01:00Z"),
    )
    conn.execute(
        """
        INSERT INTO coverage_items (
            id, project_id, item_type, target, port, description, status,
            priority, intent_id, created_at, updated_at
        ) VALUES (
            'cov001', 'proj_legacy', 'service', 'legacy.test', 3306,
            'Legacy MySQL support service check', 'confirmed', 9, 'i001', ?, ?
        )
        """,
        ("2025-01-01T00:00:20Z", "2025-01-01T00:01:00Z"),
    )
    conn.execute(
        """
        INSERT INTO attack_paths (
            id, project_id, name, fact_chain, description, severity, status, created_at
        ) VALUES ('ap001', 'proj_legacy', 'legacy chain', ?, 'legacy evidence chain', 'high', 'confirmed', ?)
        """,
        (json.dumps(["origin", "f001"]), "2025-01-01T00:01:10Z"),
    )
    conn.execute(
        """
        INSERT INTO task_logs (
            id, project_id, task_type, intent_id, worker_name, phase,
            stdout, stderr, return_code, created_at
        ) VALUES (
            'log001', 'proj_legacy', 'explore', 'i001', 'worker', 'explore_execute',
            'credential accepted', '', 0, '2025-01-01T00:01:00Z'
        )
        """
    )
    conn.commit()
    conn.close()

    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)

    with db.get_conn() as migrated:
        project = migrated.execute("SELECT * FROM projects WHERE id = 'proj_legacy'").fetchone()
        assert project["mode"] == "real_website"
        assert project["phase"] == "explore"
        assert json.loads(project["scope_policy"])["support_ports"] == [3306]
        assert json.loads(project["recon_profile"])["target_type"] == "domain"

        intent = migrated.execute("SELECT * FROM intents WHERE id = 'i001'").fetchone()
        assert intent["status"] == "concluded"
        assert intent["test_variant"] == "weak_credentials"

        coverage = migrated.execute("SELECT * FROM coverage_items WHERE id = 'cov001'").fetchone()
        assert coverage["test_family"] == "support_service"
        assert coverage["surface_group"] == "support:legacy.test:3306"
        assert coverage["required"] == 0
        assert coverage["execution_status"] == "completed"
        assert coverage["outcome"] == "vulnerable"

        assert migrated.execute("SELECT COUNT(*) FROM coverage_intents").fetchone()[0] == 1
        evidence = migrated.execute("SELECT * FROM coverage_evidence").fetchone()
        assert evidence["fact_id"] == "f001"
        assert evidence["relation"] == "supports"

        surface = migrated.execute("SELECT * FROM surface_inventory").fetchone()
        assert surface["surface_group"] == "support:legacy.test:3306"
        assert json.loads(surface["traits"])["support_service"] is True
        assert migrated.execute("SELECT COUNT(*) FROM surface_inventory").fetchone()[0] == 1

        path_row = migrated.execute("SELECT * FROM attack_paths WHERE id = 'ap001'").fetchone()
        assert path_row["suggested_status"] == "confirmed"
        assert path_row["signature"]
        assert migrated.execute("SELECT COUNT(*) FROM attack_path_steps").fetchone()[0] == 2

        task_log_columns = {
            row["name"] for row in migrated.execute("PRAGMA table_info(task_logs)").fetchall()
        }
        assert "stdin" in task_log_columns
        fact_columns = {
            row["name"] for row in migrated.execute("PRAGMA table_info(facts)").fetchall()
        }
        intent_columns = {
            row["name"] for row in migrated.execute("PRAGMA table_info(intents)").fetchall()
        }
        assert "verification_of" in fact_columns
        assert "test_variant" in intent_columns


def test_pre_v2_surface_inventory_adds_behavior_column_before_index(tmp_path, monkeypatch) -> None:
    path = tmp_path / "pre-v2-surface.db"
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE surface_inventory (
            id TEXT NOT NULL,
            project_id TEXT NOT NULL,
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
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (id, project_id),
            UNIQUE (project_id, fingerprint)
        );
        """
    )
    conn.execute(
        """
        INSERT INTO surface_inventory (
            id, project_id, fingerprint, surface_group, target, port, method,
            path_template, params, auth_context, roles, traits, created_at, updated_at
        ) VALUES (
            'surf001', 'proj_old', 'legacy-fingerprint', 'auth:/login',
            'legacy.test', 443, 'POST', '/login', '[\"username\"]',
            'anonymous', '[]', '{}', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z'
        )
        """
    )
    conn.commit()
    conn.close()

    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)

    with db.get_conn() as migrated:
        columns = {
            row["name"] for row in migrated.execute("PRAGMA table_info(surface_inventory)")
        }
        indexes = {
            row["name"] for row in migrated.execute("PRAGMA index_list(surface_inventory)")
        }
        surface = migrated.execute(
            "SELECT * FROM surface_inventory WHERE id = 'surf001'"
        ).fetchone()
        assert "behavior_key" in columns
        assert "idx_surface_inventory_behavior" in indexes
        assert surface["behavior_key"] == "auth:/login"
        assert json.loads(surface["capabilities"]) == []
        assert json.loads(surface["evidence_fact_ids"]) == []

"""Idempotent account / data_scope migration. Does not change owner_id or duplicate events."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv
from sqlalchemy import inspect, text

load_dotenv()

from backend.database.connection import get_engine
from backend.database.scope import YOGESH_ACCOUNT_ID, YOGESH_ACCOUNT_NAME

SNAPSHOT_SQL = """
SELECT
  (SELECT count(*) FROM events) AS events,
  (SELECT count(*) FROM events WHERE source_type='LINUX') AS linux,
  (SELECT count(*) FROM events WHERE source_type='CLOUD') AS cloud,
  (SELECT count(*) FROM events WHERE source_type='HPC') AS hpc,
  (SELECT count(*) FROM events WHERE source_type='BEHAVIORAL') AS behavioral,
  (SELECT count(*) FROM events WHERE data_origin='LIVE_LINUX') AS live_linux,
  (SELECT count(*) FROM events WHERE data_origin='PUBLIC_DATASET') AS public_dataset,
  (SELECT count(*) FROM events WHERE data_origin='SYNTHETIC') AS synthetic,
  (SELECT count(*) FROM events WHERE data_origin='SYNTHETIC_CLOUD_DEMO') AS synthetic_cloud_demo
"""


def _table_exists(conn, name: str) -> bool:
    return inspect(conn).has_table(name)


def _column_exists(conn, table: str, column: str) -> bool:
    return any(col["name"] == column for col in inspect(conn).get_columns(table))


def _snapshot(conn) -> dict:
    row = conn.execute(text(SNAPSHOT_SQL)).mappings().one()
    return dict(row)


def migrate() -> dict:
    engine = get_engine()
    report: dict = {}
    with engine.begin() as conn:
        before = _snapshot(conn) if _table_exists(conn, "events") else {}
        report["before"] = before

        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS accounts (
                id VARCHAR(36) PRIMARY KEY,
                name VARCHAR(80) NOT NULL UNIQUE,
                created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMP NOT NULL DEFAULT NOW()
            )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_accounts_name ON accounts(name)"))

        if _table_exists(conn, "users") and not _column_exists(conn, "users", "account_id"):
            conn.execute(text("ALTER TABLE users ADD COLUMN account_id VARCHAR(36)"))
        if _table_exists(conn, "users"):
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_users_account_id ON users(account_id)"))

        if _table_exists(conn, "servers") and not _column_exists(conn, "servers", "account_id"):
            conn.execute(text("ALTER TABLE servers ADD COLUMN account_id VARCHAR(36)"))
        if _table_exists(conn, "servers"):
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_servers_account_id ON servers(account_id)"))

        if _table_exists(conn, "events"):
            if not _column_exists(conn, "events", "account_id"):
                conn.execute(text("ALTER TABLE events ADD COLUMN account_id VARCHAR(36)"))
            if not _column_exists(conn, "events", "data_scope"):
                conn.execute(text("ALTER TABLE events ADD COLUMN data_scope VARCHAR(20) NOT NULL DEFAULT 'PRIVATE'"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_account_id ON events(account_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_data_scope ON events(data_scope)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_account_scope ON events(account_id, data_scope)"))

        for table in ("behavior_profiles", "alerts", "detections", "incidents", "risk_history"):
            if _table_exists(conn, table) and not _column_exists(conn, table, "account_id"):
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN account_id VARCHAR(36)"))
            if _table_exists(conn, table):
                conn.execute(text(f"CREATE INDEX IF NOT EXISTS ix_{table}_account_id ON {table}(account_id)"))

        if _table_exists(conn, "incidents") and not _column_exists(conn, "incidents", "intelligence_refs"):
            conn.execute(text("ALTER TABLE incidents ADD COLUMN intelligence_refs TEXT"))
        if _table_exists(conn, "risk_history") and not _column_exists(conn, "risk_history", "entity_type"):
            conn.execute(text("ALTER TABLE risk_history ADD COLUMN entity_type VARCHAR(40) NOT NULL DEFAULT 'identity'"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_risk_history_entity_type ON risk_history(entity_type)"))

        conn.execute(text("""
            INSERT INTO accounts (id, name, created_at, updated_at)
            VALUES (:id, :name, NOW(), NOW())
            ON CONFLICT (name) DO NOTHING
        """), {"id": YOGESH_ACCOUNT_ID, "name": YOGESH_ACCOUNT_NAME})
        existing = conn.execute(
            text("SELECT id FROM accounts WHERE name = :name"),
            {"name": YOGESH_ACCOUNT_NAME},
        ).scalar()
        yogesh_id = existing or YOGESH_ACCOUNT_ID
        report["yogesh_account_id"] = yogesh_id

        conn.execute(text("""
            UPDATE users
            SET account_id = :aid
            WHERE username = 'yogesh23' AND account_id IS NULL
        """), {"aid": yogesh_id})

        conn.execute(text("""
            UPDATE servers
            SET account_id = :aid
            WHERE account_id IS NULL
              AND (
                owner_id IN (SELECT id FROM users WHERE username = 'yogesh23')
                OR created_by IN (SELECT id FROM users WHERE username = 'yogesh23')
                OR server_name IN ('Yogesh_Linux', 'New OS')
              )
        """), {"aid": yogesh_id})

        if _table_exists(conn, "events"):
            conn.execute(text("""
                UPDATE events
                SET data_scope = 'GLOBAL'
                WHERE data_origin IN ('PUBLIC_DATASET', 'SYNTHETIC', 'SYNTHETIC_CLOUD_DEMO')
            """))
            conn.execute(text("""
                UPDATE events
                SET data_scope = 'PRIVATE'
                WHERE data_origin = 'LIVE_LINUX' OR data_origin IS NULL OR data_origin = ''
            """))
            conn.execute(text("""
                UPDATE events
                SET account_id = NULL
                WHERE data_scope = 'GLOBAL'
            """))
            conn.execute(text("""
                UPDATE events e
                SET account_id = s.account_id
                FROM servers s
                WHERE e.server_id = s.id
                  AND e.data_scope = 'PRIVATE'
                  AND e.account_id IS NULL
                  AND s.account_id IS NOT NULL
            """))
            conn.execute(text("""
                UPDATE events e
                SET account_id = u.account_id
                FROM users u
                WHERE e.owner_id = u.id
                  AND e.data_scope = 'PRIVATE'
                  AND e.account_id IS NULL
                  AND u.account_id IS NOT NULL
            """))

        if _table_exists(conn, "behavior_profiles"):
            conn.execute(text("""
                UPDATE behavior_profiles p
                SET account_id = u.account_id
                FROM users u
                WHERE p.owner_id = u.id AND p.account_id IS NULL AND u.account_id IS NOT NULL
            """))
        for table in ("alerts", "detections", "incidents", "risk_history"):
            if _table_exists(conn, table):
                conn.execute(text(f"""
                    UPDATE {table} t
                    SET account_id = u.account_id
                    FROM users u
                    WHERE t.owner_id = u.id AND t.account_id IS NULL AND u.account_id IS NOT NULL
                """))

        after = _snapshot(conn)
        report["after"] = after
        report["events_unchanged"] = before.get("events") == after.get("events")
        report["global_null_account"] = conn.execute(text(
            "SELECT count(*) FROM events WHERE data_scope='GLOBAL' AND account_id IS NOT NULL"
        )).scalar()
        report["yogesh_private"] = conn.execute(text(
            "SELECT count(*) FROM events WHERE data_scope='PRIVATE' AND account_id=:aid"
        ), {"aid": yogesh_id}).scalar()
        report["mapping"] = {
            "users": [tuple(r) for r in conn.execute(text("SELECT username, account_id, role FROM users ORDER BY username"))],
            "servers": [tuple(r) for r in conn.execute(text("SELECT server_name, account_id, owner_id FROM servers"))],
        }

    print(json.dumps(report, default=str, indent=2))
    if before and after and before.get("events") != after.get("events"):
        raise SystemExit("Migration changed event counts; aborting conceptually (already committed).")
    print("Account/data_scope migration complete.")
    return report


if __name__ == "__main__":
    try:
        migrate()
    except Exception as exc:
        print(f"Migration failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

"""Local DB smoke check. Does not print passwords or DSNs."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy import create_engine, inspect, text

from backend.core.config import ENV_FILE, get_settings


def main() -> int:
    settings = get_settings()
    print("env_file", ENV_FILE)
    print("env_file_exists", ENV_FILE.is_file())
    print("host", settings.DB_HOST)
    print("port", settings.DB_PORT)
    print("name", settings.DB_NAME)
    print("user", settings.DB_USER)
    print("password_set", bool(settings.DB_PASSWORD))
    engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True)
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
        row = conn.execute(text("SELECT current_database(), current_user")).one()
        print("connected_db", row[0])
        print("connected_user", row[1])
        tables = sorted(inspect(engine).get_table_names())
        print("tables", tables)
        if "events" in tables:
            print("event_count", conn.execute(text("SELECT count(*) FROM events")).scalar())
        else:
            print("event_count", "no-events-table")
    print("ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

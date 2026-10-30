"""Apply DefenSync schema updates (multi-server platform)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv
from sqlalchemy import inspect, text

load_dotenv()

from backend.database.connection import get_engine
from backend.database.models import Base


def _table_exists(conn, name: str) -> bool:
    return inspect(conn).has_table(name)


def migrate() -> None:
    engine = get_engine()
    with engine.begin() as conn:
        if _table_exists(conn, "security_events") and not _table_exists(conn, "events"):
            conn.execute(text("ALTER TABLE security_events RENAME TO events"))
        if _table_exists(conn, "ml_predictions") and not _table_exists(conn, "detections"):
            conn.execute(text("ALTER TABLE ml_predictions RENAME TO detections"))

        if _table_exists(conn, "events"):
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS hash VARCHAR(64)"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS server_id VARCHAR(36)"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS owner_id VARCHAR(36)"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS risk_level VARCHAR(20)"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS command TEXT"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS normalized_data TEXT"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS cpu_usage DOUBLE PRECISION"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS memory_usage DOUBLE PRECISION"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS disk_usage DOUBLE PRECISION"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS login_time TIMESTAMP"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS logout_time TIMESTAMP"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS failed_login_count INTEGER"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS session_duration DOUBLE PRECISION"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS commands_executed INTEGER"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS network_connections INTEGER"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS source_type VARCHAR(20) NOT NULL DEFAULT 'LINUX'"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS provider VARCHAR(30)"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS data_origin VARCHAR(30) NOT NULL DEFAULT 'LIVE_LINUX'"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS dataset_name VARCHAR(80)"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS is_labelled BOOLEAN NOT NULL DEFAULT FALSE"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS original_label VARCHAR(30)"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS actor_id VARCHAR(255)"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS resource_id VARCHAR(255)"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS resource_type VARCHAR(80)"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS operation TEXT"))
            conn.execute(text("ALTER TABLE events ALTER COLUMN operation TYPE TEXT"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS parser_status VARCHAR(20) NOT NULL DEFAULT 'PARSED'"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS session_id VARCHAR(120)"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS typing_speed_cpm DOUBLE PRECISION"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS command_rate_per_minute DOUBLE PRECISION"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS command_error_rate DOUBLE PRECISION"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS idle_time_seconds DOUBLE PRECISION"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS repeated_command_ratio DOUBLE PRECISION"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS session_duration_minutes DOUBLE PRECISION"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS login_hour INTEGER"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS behavioral_risk_score INTEGER"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS behavioral_classification VARCHAR(40)"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS risk_reasons TEXT"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS collection_timestamp TIMESTAMP"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS timestamp_source VARCHAR(40)"))
            conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS created_at TIMESTAMP"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_collection_timestamp ON events(collection_timestamp)"))
            conn.execute(text("UPDATE events SET hash = md5(raw_log || event_id) WHERE hash IS NULL"))
            conn.execute(text("UPDATE events SET source_type = 'LINUX' WHERE source_type IS NULL"))
            conn.execute(text("UPDATE events SET data_origin = 'LIVE_LINUX' WHERE data_origin IS NULL"))
            conn.execute(text("UPDATE events SET is_labelled = FALSE WHERE is_labelled IS NULL"))
            conn.execute(text("UPDATE events SET parser_status = 'PARSED' WHERE parser_status IS NULL"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_source_type ON events(source_type)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_provider ON events(provider)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_dataset_name ON events(dataset_name)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_original_label ON events(original_label)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_parser_status ON events(parser_status)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_cloud_dataset_time ON events(source_type, provider, dataset_name, timestamp)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_session_id ON events(session_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_behavioral_risk_score ON events(behavioral_risk_score)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_behavioral_classification ON events(behavioral_classification)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_behavior_identity_time ON events(actor_id, server_id, timestamp)"))

        if not _table_exists(conn, "dataset_imports"):
            conn.execute(text("""
                CREATE TABLE dataset_imports (
                    id VARCHAR(36) PRIMARY KEY,
                    owner_id VARCHAR(36) NOT NULL,
                    dataset_name VARCHAR(80) NOT NULL,
                    dataset_version VARCHAR(80),
                    source_file VARCHAR(500) NOT NULL,
                    source_file_hash VARCHAR(64) NOT NULL,
                    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
                    total_records_discovered INTEGER NOT NULL DEFAULT 0,
                    records_processed INTEGER NOT NULL DEFAULT 0,
                    records_imported INTEGER NOT NULL DEFAULT 0,
                    records_skipped INTEGER NOT NULL DEFAULT 0,
                    records_failed INTEGER NOT NULL DEFAULT 0,
                    batch_size INTEGER NOT NULL DEFAULT 500,
                    import_limit INTEGER,
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    error_message TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    CONSTRAINT uq_dataset_import_owner_file UNIQUE(owner_id, dataset_name, source_file_hash)
                )
            """))
        if _table_exists(conn, "dataset_imports"):
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_dataset_imports_owner_id ON dataset_imports(owner_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_dataset_imports_dataset_name ON dataset_imports(dataset_name)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_dataset_imports_status ON dataset_imports(status)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_dataset_imports_source_file_hash ON dataset_imports(source_file_hash)"))

        if not _table_exists(conn, "behavior_profiles"):
            conn.execute(text("""
                CREATE TABLE behavior_profiles (
                    id VARCHAR(36) PRIMARY KEY,
                    owner_id VARCHAR(36) NOT NULL,
                    identity_key VARCHAR(255) NOT NULL,
                    user_id VARCHAR(255),
                    linux_username VARCHAR(255),
                    server_id VARCHAR(36),
                    average_typing_speed DOUBLE PRECISION,
                    std_typing_speed DOUBLE PRECISION,
                    average_command_rate DOUBLE PRECISION,
                    std_command_rate DOUBLE PRECISION,
                    average_command_error_rate DOUBLE PRECISION,
                    std_command_error_rate DOUBLE PRECISION,
                    average_idle_time DOUBLE PRECISION,
                    std_idle_time DOUBLE PRECISION,
                    average_repeated_command_ratio DOUBLE PRECISION,
                    std_repeated_command_ratio DOUBLE PRECISION,
                    average_session_duration DOUBLE PRECISION,
                    std_session_duration DOUBLE PRECISION,
                    usual_login_start INTEGER,
                    usual_login_end INTEGER,
                    profile_sample_count INTEGER NOT NULL DEFAULT 0,
                    baseline_version INTEGER NOT NULL DEFAULT 0,
                    status VARCHAR(30) NOT NULL DEFAULT 'INSUFFICIENT_DATA',
                    last_updated TIMESTAMP,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    CONSTRAINT uq_behavior_profile_owner_identity_server UNIQUE(owner_id, identity_key, server_id)
                )
            """))
        if _table_exists(conn, "behavior_profiles"):
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_behavior_profiles_owner_id ON behavior_profiles(owner_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_behavior_profiles_identity_key ON behavior_profiles(identity_key)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_behavior_profiles_user_id ON behavior_profiles(user_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_behavior_profiles_server_id ON behavior_profiles(server_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_behavior_profiles_status ON behavior_profiles(status)"))

            conn.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS explanation TEXT"))
            conn.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS recommendation TEXT"))
            conn.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS risk_factors TEXT"))
            conn.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS incident_id VARCHAR(36)"))
            conn.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS event_timestamp TIMESTAMP"))
            conn.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS confidence DOUBLE PRECISION"))
        if _table_exists(conn, "users"):
            conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS name VARCHAR(50)"))
            conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255)"))
            conn.execute(text("UPDATE users SET name = username WHERE name IS NULL"))
            conn.execute(text("UPDATE users SET password_hash = hashed_password WHERE password_hash IS NULL"))
            conn.execute(text("UPDATE users SET role = upper(role) WHERE role IS NOT NULL"))
        if _table_exists(conn, "servers"):
            conn.execute(text("ALTER TABLE servers ADD COLUMN IF NOT EXISTS environment VARCHAR(20) DEFAULT 'production'"))
            conn.execute(text("ALTER TABLE servers ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP"))
            conn.execute(text("ALTER TABLE servers ADD COLUMN IF NOT EXISTS owner_id VARCHAR(36)"))
            conn.execute(text("ALTER TABLE servers ADD COLUMN IF NOT EXISTS health_status VARCHAR(30) DEFAULT 'unknown'"))
            conn.execute(text("ALTER TABLE servers ADD COLUMN IF NOT EXISTS connection_latency_ms INTEGER"))
            conn.execute(text("ALTER TABLE servers ADD COLUMN IF NOT EXISTS last_health_check TIMESTAMP"))
            conn.execute(text("ALTER TABLE servers ADD COLUMN IF NOT EXISTS last_successful_collection TIMESTAMP"))
            conn.execute(text("ALTER TABLE servers ADD COLUMN IF NOT EXISTS health_error_message TEXT"))
            conn.execute(text("ALTER TABLE servers ADD COLUMN IF NOT EXISTS consecutive_failures INTEGER DEFAULT 0"))
            conn.execute(text("UPDATE servers SET environment = 'production' WHERE environment IS NULL"))
            conn.execute(text("UPDATE servers SET owner_id = created_by WHERE owner_id IS NULL"))
            conn.execute(text("UPDATE servers SET last_seen = last_connected WHERE last_seen IS NULL AND last_connected IS NOT NULL"))
            conn.execute(text("""
                UPDATE servers
                SET health_status = CASE
                    WHEN status = 'online' THEN 'online'
                    WHEN status IN ('offline', 'error') THEN status
                    WHEN status = 'inactive' THEN 'unknown'
                    ELSE COALESCE(health_status, 'unknown')
                END
            """))
            conn.execute(text("""
                UPDATE servers
                SET status = CASE
                    WHEN status = 'inactive' THEN 'inactive'
                    ELSE 'active'
                END
            """))
            conn.execute(text("UPDATE servers SET consecutive_failures = 0 WHERE consecutive_failures IS NULL"))
        if _table_exists(conn, "detections"):
            conn.execute(text("ALTER TABLE detections ADD COLUMN IF NOT EXISTS owner_id VARCHAR(36)"))
            conn.execute(text("ALTER TABLE detections ADD COLUMN IF NOT EXISTS classification VARCHAR(20)"))
            conn.execute(text("ALTER TABLE detections ADD COLUMN IF NOT EXISTS confidence DOUBLE PRECISION"))
            conn.execute(text("ALTER TABLE detections ADD COLUMN IF NOT EXISTS detection_type VARCHAR(50)"))
            conn.execute(text("ALTER TABLE detections ADD COLUMN IF NOT EXISTS message TEXT"))
        if _table_exists(conn, "servers") and _table_exists(conn, "events"):
            conn.execute(text("""
                UPDATE events e
                SET owner_id = s.owner_id
                FROM servers s
                WHERE e.server_id = s.id AND e.owner_id IS NULL
            """))
        if _table_exists(conn, "servers") and _table_exists(conn, "alerts"):
            conn.execute(text("""
                UPDATE alerts a
                SET owner_id = s.owner_id
                FROM servers s
                WHERE a.server_id = s.id AND a.owner_id IS NULL
            """))

        if not _table_exists(conn, "incidents"):
            conn.execute(text("""
                CREATE TABLE incidents (
                    id VARCHAR(36) PRIMARY KEY,
                    owner_id VARCHAR(36),
                    incident_id VARCHAR(80) NOT NULL UNIQUE,
                    title VARCHAR(240) NOT NULL,
                    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
                    risk_score INTEGER NOT NULL DEFAULT 0,
                    confidence INTEGER NOT NULL DEFAULT 0,
                    actor VARCHAR(255),
                    source VARCHAR(80),
                    start_time TIMESTAMP,
                    end_time TIMESTAMP,
                    event_ids TEXT,
                    evidence TEXT,
                    explanation TEXT,
                    recommendation TEXT,
                    status VARCHAR(30) NOT NULL DEFAULT 'open',
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
                )
            """))
        if _table_exists(conn, "incidents"):
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_incidents_owner_id ON incidents(owner_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_incidents_actor ON incidents(actor)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_incidents_start_time ON incidents(start_time)"))
        if not _table_exists(conn, "risk_history"):
            conn.execute(text("""
                CREATE TABLE risk_history (
                    id VARCHAR(36) PRIMARY KEY,
                    owner_id VARCHAR(36),
                    entity_key VARCHAR(255) NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    risk_score INTEGER NOT NULL DEFAULT 0,
                    source VARCHAR(40),
                    reason TEXT,
                    event_id VARCHAR(36),
                    created_at TIMESTAMP NOT NULL DEFAULT NOW()
                )
            """))
        if _table_exists(conn, "risk_history"):
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_risk_history_owner_id ON risk_history(owner_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_risk_history_entity_key ON risk_history(entity_key)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_risk_history_timestamp ON risk_history(timestamp)"))

        if _table_exists(conn, "users"):
            conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS device_limit INTEGER NOT NULL DEFAULT 3"))

        if not _table_exists(conn, "trusted_devices"):
            conn.execute(text("""
                CREATE TABLE trusted_devices (
                    id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(36) NOT NULL,
                    account_id VARCHAR(36),
                    display_name VARCHAR(120) NOT NULL DEFAULT 'Trusted device',
                    public_key_jwk TEXT NOT NULL,
                    public_key_thumbprint VARCHAR(64) NOT NULL,
                    key_algorithm VARCHAR(20) NOT NULL DEFAULT 'ES256',
                    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    enrolled_at TIMESTAMP,
                    last_seen_at TIMESTAMP,
                    revoked_at TIMESTAMP,
                    enroll_source_ip VARCHAR(45),
                    enroll_user_agent VARCHAR(512),
                    last_source_ip VARCHAR(45),
                    last_user_agent VARCHAR(512)
                )
            """))
        if _table_exists(conn, "trusted_devices"):
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_trusted_devices_user_id ON trusted_devices(user_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_trusted_devices_account_id ON trusted_devices(account_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_trusted_devices_status ON trusted_devices(status)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_trusted_devices_public_key_thumbprint ON trusted_devices(public_key_thumbprint)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_trusted_devices_user_status ON trusted_devices(user_id, status)"))
            conn.execute(text("""
                CREATE UNIQUE INDEX IF NOT EXISTS uq_trusted_device_user_thumbprint
                ON trusted_devices(user_id, public_key_thumbprint)
            """))

        if not _table_exists(conn, "device_challenges"):
            conn.execute(text("""
                CREATE TABLE device_challenges (
                    id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(36) NOT NULL,
                    device_id VARCHAR(36),
                    purpose VARCHAR(20) NOT NULL,
                    nonce_hash VARCHAR(64) NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    used_at TIMESTAMP,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW()
                )
            """))
        if _table_exists(conn, "device_challenges"):
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_device_challenges_user_id ON device_challenges(user_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_device_challenges_device_id ON device_challenges(device_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_device_challenges_purpose ON device_challenges(purpose)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_device_challenges_expires_at ON device_challenges(expires_at)"))

        if _table_exists(conn, "monitored_servers") and not _table_exists(conn, "servers"):
            conn.execute(text("""
                CREATE TABLE servers (
                    id VARCHAR(36) PRIMARY KEY,
                    server_name VARCHAR(100) NOT NULL,
                    host VARCHAR(255) NOT NULL,
                    port INTEGER NOT NULL DEFAULT 22,
                    username VARCHAR(100) NOT NULL,
                    authentication_type VARCHAR(20) NOT NULL DEFAULT 'password',
                    encrypted_password TEXT,
                    encrypted_private_key TEXT,
                    operating_system VARCHAR(50) DEFAULT 'linux',
                    environment VARCHAR(20) NOT NULL DEFAULT 'production',
                    description TEXT,
                    status VARCHAR(20) NOT NULL DEFAULT 'active',
                    last_seen TIMESTAMP,
                    last_connected TIMESTAMP,
                    owner_id VARCHAR(36),
                    created_by VARCHAR(36),
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
                )
            """))
            conn.execute(text("""
                INSERT INTO servers (
                    id, server_name, host, port, username, authentication_type,
                    encrypted_password, encrypted_private_key, operating_system,
                    environment, description, status, last_seen, last_connected, owner_id, created_by, created_at, updated_at
                )
                SELECT
                    id,
                    name,
                    host,
                    port,
                    username,
                    CASE WHEN auth_type = 'private_key' THEN 'ssh_key' ELSE 'password' END,
                    CASE WHEN auth_type = 'password' THEN encrypted_credential ELSE NULL END,
                    CASE WHEN auth_type = 'private_key' THEN encrypted_credential ELSE NULL END,
                    operating_system,
                    'production',
                    description,
                    CASE
                        WHEN is_active = FALSE THEN 'inactive'
                        WHEN connection_status = 'online' THEN 'online'
                        WHEN connection_status = 'offline' THEN 'offline'
                        WHEN connection_status = 'error' THEN 'error'
                        ELSE 'active'
                    END,
                    last_connected_at,
                    last_connected_at,
                    created_by,
                    created_by,
                    created_at,
                    updated_at
                FROM monitored_servers
            """))
            conn.execute(text("DROP TABLE monitored_servers"))

        # Alternate-success collection → n8n outbox (also created by create_all for new installs).
        conn.execute(text(
            """
            CREATE TABLE IF NOT EXISTS collection_n8n_sequences (
                id VARCHAR(36) PRIMARY KEY,
                scope_key VARCHAR(80) NOT NULL,
                source_type VARCHAR(20) NOT NULL,
                owner_id VARCHAR(36),
                account_id VARCHAR(36),
                success_count INTEGER NOT NULL DEFAULT 0,
                last_counted_run_id VARCHAR(36),
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL,
                CONSTRAINT uq_collection_n8n_sequence_scope_source UNIQUE (scope_key, source_type)
            )
            """
        ))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_collection_n8n_sequences_scope_key ON collection_n8n_sequences(scope_key)"))
        conn.execute(text(
            """
            CREATE TABLE IF NOT EXISTS collection_n8n_dispatches (
                id VARCHAR(36) PRIMARY KEY,
                event_id VARCHAR(36) NOT NULL,
                source_type VARCHAR(20) NOT NULL,
                collection_run_id VARCHAR(36) NOT NULL,
                scope_key VARCHAR(80) NOT NULL,
                owner_id VARCHAR(36),
                account_id VARCHAR(36),
                sequence_number INTEGER NOT NULL,
                outcome VARCHAR(32) NOT NULL,
                collection_completed_at TIMESTAMP,
                status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
                attempt_count INTEGER NOT NULL DEFAULT 0,
                last_attempt_at TIMESTAMP,
                sent_at TIMESTAMP,
                last_http_status INTEGER,
                last_error VARCHAR(240),
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL,
                CONSTRAINT uq_collection_n8n_dispatch_event_id UNIQUE (event_id),
                CONSTRAINT uq_collection_n8n_dispatch_run UNIQUE (source_type, collection_run_id)
            )
            """
        ))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_collection_n8n_dispatches_event_id ON collection_n8n_dispatches(event_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_collection_n8n_dispatches_status ON collection_n8n_dispatches(status)"))

    print(f"SQLAlchemy metadata tables before create_all: {sorted(Base.metadata.tables.keys())}")
    Base.metadata.create_all(bind=engine)
    print(f"SQLAlchemy metadata tables after create_all: {sorted(Base.metadata.tables.keys())}")
    from scripts.migrate_accounts import migrate as migrate_accounts
    migrate_accounts()
    print("DefenSync schema migration complete.")


if __name__ == "__main__":
    try:
        migrate()
    except Exception as exc:
        print(f"Migration failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

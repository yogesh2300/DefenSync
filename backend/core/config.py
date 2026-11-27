"""
DefenSync System Configuration.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote_plus

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_ROOT / ".env"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # ==========================================================================
    # Application
    # ==========================================================================

    APP_NAME: str = "DefenSync - Behavioral Log Intelligence System"
    APP_DESCRIPTION: str = (
        "Multi-server behavioral log intelligence and security event analysis platform"
    )

    API_VERSION: str = "v1"
    API_PREFIX: str = "/api/v1"

    DEBUG: bool = False

    ENVIRONMENT: str = "development"

    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # ==========================================================================
    # Database
    # ==========================================================================

    DB_HOST: str = "127.0.0.1"
    DB_PORT: int = 5432
    DB_NAME: str = "cloudsync_db"
    DB_USER: str = "postgres"
    DB_PASSWORD: str = "postgres"

    @property
    def DATABASE_URL(self) -> str:
        """Return SQLAlchemy PostgreSQL connection URL (password URL-encoded)."""
        return (
            f"postgresql+psycopg://"
            f"{quote_plus(self.DB_USER)}:{quote_plus(self.DB_PASSWORD)}"
            f"@{self.DB_HOST}:{self.DB_PORT}/{quote_plus(self.DB_NAME)}"
        )

    # ==========================================================================
    # JWT Security
    # ==========================================================================

    SECRET_KEY: SecretStr

    ALGORITHM: str = "HS256"

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # ==========================================================================
    # Admin Bootstrap (local .env only; the admin signs in with ADMIN_EMAIL)
    # Empty values skip bootstrap. The password is only ever stored as a hash.
    # ==========================================================================

    ADMIN_USERNAME: str = ""
    ADMIN_EMAIL: str = ""
    ADMIN_PASSWORD: SecretStr = SecretStr("")

    # ==========================================================================
    # CORS
    # ==========================================================================

    ALLOWED_ORIGINS: str = "http://localhost:5173,http://localhost:5174,http://127.0.0.1:5173,http://127.0.0.1:5174"
    @property
    def cors_origins(self) -> list[str]:
        """
        Return allowed CORS origins as a list.
        Accepts either a comma-separated string or a JSON list.
        """
        value = self.ALLOWED_ORIGINS
        if value.startswith("["):
            return json.loads(value)
        return [origin.strip() for origin in value.split(",") if origin.strip()]

    # ==========================================================================
    # Logging
    # ==========================================================================

    LOG_LEVEL: str = "INFO"

    # ==========================================================================
    # Background Scheduler (multi-server collection)
    # ==========================================================================

    SCHEDULER_ENABLED: bool = False
    COLLECTION_INTERVAL_MINUTES: int = 15
    COLLECTION_TAIL_LINES: int = 500
    # Upper bound of journal entries read per run; the rest is read on the next run from the cursor.
    JOURNAL_MAX_ENTRIES_PER_RUN: int = 10000

    # ==========================================================================
    # Server Health Monitoring
    # ==========================================================================

    HEALTH_CHECK_ENABLED: bool = True
    HEALTH_CHECK_INTERVAL_SECONDS: int = 30
    HEALTH_CHECK_TIMEOUT_SECONDS: float = 3.0
    HEALTH_CHECK_MAX_WORKERS: int = 20
    HEALTH_RECENT_WINDOW_SECONDS: int = 300

    # ==========================================================================
    # Public Dataset Imports
    # ==========================================================================

    DATASET_ROOT: str = "datasets"
    OPENSTACK_DATASET_PATH: str = "OpenStack"
    BGL_DATASET_PATH: str = "BGL"
    HDFS_DATASET_PATH: str = "HDFS"
    DATASET_IMPORT_BATCH_SIZE: int = 500
    DATASET_IMPORT_MAX_RECORDS: int = 10000
    DATASET_IMPORT_ENABLED: bool = True
    BEHAVIORAL_DATASET_PATH: str = "behavioral"
    BEHAVIORAL_IMPORT_BATCH_SIZE: int = 500
    BEHAVIORAL_IMPORT_MAX_RECORDS: int = 10000
    BEHAVIORAL_MIN_BASELINE_SAMPLES: int = 10
    BEHAVIORAL_BASELINE_UPDATE_MAX_RISK: int = 29
    MODEL_DIR: str = "models"
    CORRELATION_WINDOW_MINUTES: int = 15

    # ==========================================================================
    # Azure telemetry collector (read-only, Log Analytics Query API)
    # Empty values leave the collector NOT_CONFIGURED; the app still runs.
    # ==========================================================================

    AZURE_TENANT_ID: str = ""
    AZURE_CLIENT_ID: str = ""
    AZURE_CLIENT_SECRET: SecretStr = SecretStr("")
    AZURE_LOG_ANALYTICS_WORKSPACE_ID: str = ""
    # Explicit start/end collections (historical backfill): longest single window, and how far back it may start.
    CLOUD_COLLECTION_MAX_WINDOW_HOURS: int = 168
    CLOUD_COLLECTION_MAX_HISTORY_DAYS: int = 90

    # ==========================================================================
    # n8n incident notification (outbound webhook, notification only)
    # Blank URL leaves notifications NOT_CONFIGURED; incidents are stored as usual.
    # ==========================================================================

    N8N_WEBHOOK_URL: SecretStr = SecretStr("")
    N8N_WEBHOOK_AUTH_HEADER: str = ""
    N8N_WEBHOOK_AUTH_TOKEN: SecretStr = SecretStr("")
    N8N_WEBHOOK_TIMEOUT_SECONDS: float = 3.0
    # Comma-separated addresses for n8n Send Email mapping
    # ({{$json.body.notification.recipient_emails[0]}}). Never commit real values.
    # When blank, collection/demo webhooks fall back to the collecting owner's registered email.
    N8N_NOTIFICATION_RECIPIENT_EMAILS: str = ""

    # ==========================================================================
    # Presentation telemetry (comma-separated owner emails; blank = disabled)
    # Cloud sources owned by a listed email get clearly marked presentation records
    # after a successful "Collect now" by that owner.
    # ==========================================================================

    PRESENTATION_TELEMETRY_EMAILS: str = ""
    # When true (default), each successful Cloud collect for a presentation owner creates
    # exactly one DEMO privilege incident (not the 1–3 collection interval).
    CLOUD_DEMO_EVERY_SUCCESS: bool = True
    # When true (default), each of those demo incidents triggers one logical n8n webhook
    # (Cloud alternate every-2nd milestone is skipped while this is enabled).
    # Linux alternate-collection (every 2nd) is unchanged.
    CLOUD_DEMO_N8N_EVERY_SUCCESS: bool = True

    # ==========================================================================
    # Multi-factor authentication (OTP after password login)
    # Without a configured delivery channel, password login is refused.
    # ==========================================================================

    OTP_EXPIRE_MINUTES: int = 5
    OTP_MAX_ATTEMPTS: int = 5
    OTP_RESEND_COOLDOWN_SECONDS: int = 120
    OTP_MAX_SENDS: int = 3

    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: SecretStr = SecretStr("")
    SMTP_FROM: str = ""
    SMTP_SECURITY: str = "starttls"

    SMS_PROVIDER: str = ""

    # ==========================================================================
    # Pydantic Settings Configuration
    # ==========================================================================

    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE) if ENV_FILE.is_file() else ".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """
    Return a cached Settings instance.

    Using lru_cache ensures the configuration is loaded only once
    during the application's lifetime.
    """
    return Settings()
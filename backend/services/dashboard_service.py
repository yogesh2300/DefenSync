"""Business logic service layer for dashboard intelligence and telemetry analytics."""
from __future__ import annotations

import logging
import time
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.database import crud, server_crud

logger = logging.getLogger(__name__)


class DashboardService:
    """Service layer providing aggregated security telemetry and metrics for dashboards."""

    def __init__(self, session: Session) -> None:
        """Initialize the dashboard service with a database session."""
        self._session = session

    def dashboard_summary(
        self,
        *,
        owner_id: str | None = None,
        server_id: str | None = None,
    ) -> dict[str, int]:
        """Calculate and return overall SIEM summary statistics across collected security logs."""
        started = time.perf_counter()
        logger.debug(
            "Generating dashboard summary metrics owner_id=%s server_id=%s",
            owner_id,
            server_id,
        )
        try:
            self._apply_statement_timeout()
            summary = crud.dashboard_summary(
                self._session,
                owner_id=owner_id,
                server_id=server_id,
            )
            summary.update(
                server_crud.server_summary(
                    self._session,
                    owner_id=owner_id,
                    server_id=server_id,
                )
            )
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            if elapsed_ms > 750:
                logger.warning("Dashboard summary query was slow: %sms owner_id=%s", elapsed_ms, owner_id)
            return self._with_defaults(summary)
        except Exception:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            logger.exception("Dashboard summary failed after %sms; returning zero defaults", elapsed_ms)
            self._session.rollback()
            return self.empty_summary()

    def _apply_statement_timeout(self) -> None:
        """Bound PostgreSQL dashboard reads; ignored on engines that do not support it."""
        try:
            bind = self._session.get_bind()
            if bind.dialect.name == "postgresql":
                self._session.execute(text("SET LOCAL statement_timeout = 750"))
        except Exception:
            logger.debug("Dashboard statement timeout setup skipped", exc_info=True)
            self._session.rollback()

    @classmethod
    def empty_summary(cls) -> dict[str, int]:
        return cls._with_defaults({})

    @staticmethod
    def _with_defaults(summary: dict[str, Any]) -> dict[str, int]:
        keys = (
            "total_events",
            "high_risk",
            "successful_logins",
            "failed_logins",
            "unique_users",
            "unique_ips",
            "average_risk_score",
            "total_servers",
            "active_servers",
            "online_servers",
            "offline_servers",
        )
        return {key: int(summary.get(key) or 0) for key in keys}

    def count_events(self) -> int:
        """Return the total number of recorded security events."""
        logger.debug("Counting total security events")
        return crud.count_events(self._session)

    def count_high_risk_events(self, min_score: int = 70) -> int:
        """Return the number of high-risk events meeting or exceeding the threshold."""
        logger.debug("Counting high-risk events with min_score=%d", min_score)
        return crud.count_high_risk_events(self._session, min_score=min_score)

    def count_successful_logins(self) -> int:
        """Return the number of successful authentication events."""
        logger.debug("Counting successful login events")
        return crud.count_successful_logins(self._session)

    def count_failed_logins(self) -> int:
        """Return the number of failed authentication events."""
        logger.debug("Counting failed login events")
        return crud.count_failed_logins(self._session)
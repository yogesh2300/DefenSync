"""Alert management for detected security threats."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import case, desc, func, select
from sqlalchemy.orm import Session

from backend.database.models import Alert, SecurityEvent

logger = logging.getLogger(__name__)

HIGH_RISK_THRESHOLD = 70


class AlertService:
    """Create and manage alerts from security events."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def sync_from_events(self, *, min_score: int = HIGH_RISK_THRESHOLD, owner_id: str | None = None) -> int:
        """Create alerts for high-risk events not yet alerted."""
        existing = set(self._session.scalars(select(Alert.event_id)).all())
        stmt = (
            select(SecurityEvent)
            .where(SecurityEvent.risk_score >= min_score)
            .order_by(desc(SecurityEvent.timestamp))
        )
        if owner_id:
            stmt = stmt.where(SecurityEvent.owner_id == owner_id)
        events = self._session.scalars(stmt).all()
        created = 0
        for event in events:
            if event.event_id in existing:
                continue
            self._session.add(
                Alert(
                    event_id=event.event_id,
                    server_id=getattr(event, "server_id", None),
                    owner_id=getattr(event, "owner_id", None),
                    title=f"{event.event_type} on {event.hostname}",
                    message=event.message,
                    severity=event.severity,
                    risk_score=event.risk_score,
                    risk_level=getattr(event, "risk_level", None),
                    detection_type="rule_based",
                )
            )
            created += 1
        if created:
            self._session.commit()
        return created

    def create_ml_alert(self, event: SecurityEvent, *, score: float) -> Alert | None:
        """Create an ML anomaly alert if one does not already exist."""
        existing = self._session.scalar(
            select(Alert).where(Alert.event_id == event.event_id)
        )
        if existing:
            if existing.detection_type == "rule_based":
                existing.detection_type = "hybrid"
                self._session.commit()
            return existing

        alert = Alert(
            event_id=event.event_id,
            server_id=getattr(event, "server_id", None),
            owner_id=getattr(event, "owner_id", None),
            title=f"ML Anomaly: {event.event_type}",
            message=f"Behavioral anomaly detected (score={score:.2f}): {event.message}",
            severity=event.severity if event.severity in {"high", "critical"} else "high",
            risk_score=max(event.risk_score, 75),
            risk_level=getattr(event, "risk_level", None),
            detection_type="ml_anomaly",
        )
        self._session.add(alert)
        self._session.commit()
        return alert

    def list_alerts(
        self,
        *,
        limit: int = 50,
        acknowledged: bool | None = None,
        owner_id: str | None = None,
        server_id: str | None = None,
    ) -> list[Alert]:
        """Return alerts newest first."""
        stmt = select(Alert).order_by(desc(Alert.created_at)).limit(limit)
        if acknowledged is not None:
            stmt = stmt.where(Alert.acknowledged == acknowledged)
        if owner_id:
            stmt = stmt.where(Alert.owner_id == owner_id)
        if server_id:
            stmt = stmt.where(Alert.server_id == server_id)
        return list(self._session.scalars(stmt).all())

    def acknowledge(self, alert_id: str, *, owner_id: str | None = None) -> Alert:
        """Mark an alert as acknowledged."""
        alert = self._session.get(Alert, alert_id)
        if alert is None:
            raise ValueError(f"Alert {alert_id} not found.")
        if owner_id and alert.owner_id != owner_id:
            raise ValueError(f"Alert {alert_id} not found.")
        alert.acknowledged = True
        self._session.commit()
        return alert

    def summary(
        self,
        *,
        owner_id: str | None = None,
        server_id: str | None = None,
    ) -> dict[str, Any]:
        """Return alert counts for dashboard widgets."""
        stmt = select(
            func.count(Alert.id),
            func.sum(case((Alert.acknowledged.is_(False), 1), else_=0)),
            func.sum(case((Alert.detection_type == "rule_based", 1), else_=0)),
            func.sum(case((Alert.detection_type.ilike("%ml%"), 1), else_=0)),
            func.sum(case((Alert.severity == "critical", 1), else_=0)),
        )
        if owner_id:
            stmt = stmt.where(Alert.owner_id == owner_id)
        if server_id:
            stmt = stmt.where(Alert.server_id == server_id)
        row = self._session.execute(stmt).one()
        return {
            "total": int(row[0] or 0),
            "unacknowledged": int(row[1] or 0),
            "rule_based": int(row[2] or 0),
            "ml_anomaly": int(row[3] or 0),
            "critical": int(row[4] or 0),
        }

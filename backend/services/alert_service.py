"""Alert management for detected security threats."""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import case, desc, func, or_, select
from sqlalchemy.orm import Session

from backend.database.models import DATA_SCOPE_PRIVATE, Alert, CollectionN8nDispatch, Detection, SecurityEvent
from backend.database.scope import with_environment
from backend.risk.levels import risk_level_from_score
from backend.core.environments import CLOUD

logger = logging.getLogger(__name__)

HIGH_RISK_THRESHOLD = 70
AUTH_SOURCE_TYPE = "AUTH"  # Maps to UNKNOWN analytics family — not Linux/Cloud telemetry.


def _normalize_severity(value: str | None, *, fallback_score: int = 0) -> str:
    label = (value or "").strip().lower()
    if label in {"critical", "high", "medium", "low", "info"}:
        return label
    return risk_level_from_score(int(fallback_score))


def _is_ml_detection(detection_type: str | None) -> bool:
    label = (detection_type or "").lower()
    return (
        "ml" in label
        or "isolation_forest" in label
        or label in {"hybrid"}
    )


def alert_priority_for(alert: Alert, event: SecurityEvent | None) -> str:
    """Priority-board severity: never invent HIGH for ML merely because an alert row exists.

    Rule-based alerts keep their stored severity. ML / hybrid alerts derive priority from the
    linked event's severity/risk so historical rows that stored severity=high with risk_score=75
    still display correctly when the event risk is low (presentation-layer correction).
    """
    if event is not None and _is_ml_detection(alert.detection_type):
        return _normalize_severity(getattr(event, "severity", None), fallback_score=int(event.risk_score or 0))
    return _normalize_severity(alert.severity, fallback_score=int(alert.risk_score or 0))


def serialize_alert(
    session: Session,
    alert: Alert,
    *,
    event: SecurityEvent | None = None,
    detection: Detection | None = None,
) -> dict[str, Any]:
    """API view: keep stored alert fields, expose linked event risk and ML anomaly separately."""
    if event is None:
        event = session.scalar(select(SecurityEvent).where(SecurityEvent.event_id == alert.event_id))
    if detection is None and alert.event_id:
        detection = session.scalar(
            select(Detection)
            .where(Detection.event_id == alert.event_id, Detection.is_anomaly.is_(True))
            .order_by(desc(Detection.created_at), desc(Detection.id))
            .limit(1)
        )
    event_risk = int(event.risk_score) if event is not None and event.risk_score is not None else None
    event_severity = _normalize_severity(getattr(event, "severity", None), fallback_score=event_risk or 0) if event else None
    anomaly_score = None
    if detection is not None and detection.isolation_score is not None:
        anomaly_score = float(detection.isolation_score)
    elif _is_ml_detection(alert.detection_type) and alert.confidence is not None:
        # New ML alerts store raw anomaly strength in confidence; legacy rows may hold a 0.5–0.99 transform.
        anomaly_score = float(alert.confidence)
    priority = alert_priority_for(alert, event)
    demo_label = None
    collection_id = None
    collection_run_id = None
    is_demo = False
    if event is not None:
        try:
            meta = json.loads(getattr(event, "normalized_data", None) or "{}")
        except (TypeError, ValueError):
            meta = {}
        is_demo = bool(meta.get("presentation_generated")) or (getattr(event, "data_origin", None) == "PRESENTATION_SIMULATED")
        if is_demo:
            demo_label = "DEMO"
        collection_id = meta.get("collection_id")
        collection_run_id = meta.get("collection_run_id")
    n8n_status = None
    n8n_http_status = None
    if collection_run_id:
        dispatch = session.scalar(
            select(CollectionN8nDispatch).where(
                CollectionN8nDispatch.source_type == CLOUD,
                CollectionN8nDispatch.collection_run_id == collection_run_id,
            )
        )
        if dispatch is not None:
            n8n_status = dispatch.status
            n8n_http_status = dispatch.last_http_status
    return {
        "id": alert.id,
        "event_id": alert.event_id,
        "server_id": alert.server_id,
        "owner_id": alert.owner_id,
        "account_id": getattr(alert, "account_id", None),
        "title": alert.title,
        "message": alert.message,
        "severity": alert.severity,
        "risk_score": int(alert.risk_score),
        "detection_type": alert.detection_type,
        "acknowledged": bool(alert.acknowledged),
        "created_at": alert.created_at,
        "explanation": alert.explanation,
        "recommendation": alert.recommendation,
        "risk_factors": alert.risk_factors,
        "incident_id": alert.incident_id,
        "event_timestamp": alert.event_timestamp,
        "confidence": alert.confidence,
        "risk_level": alert.risk_level,
        "event_risk_score": event_risk,
        "event_severity": event_severity,
        "anomaly_score": anomaly_score,
        "alert_priority": priority,
        "demo_label": demo_label,
        "is_demo": is_demo,
        "collection_id": collection_id,
        "collection_run_id": collection_run_id,
        # Webhook outbox only — SENT means n8n accepted HTTP, not that email arrived.
        "notification_status": n8n_status,
        "notification_http_status": n8n_http_status,
        "email_delivery": "unknown" if n8n_status else None,
    }


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
                    explanation=event.risk_reasons or event.message,
                    recommendation="Advisory only: review the actor, host, and related cloud activity. DefenSync does not block, isolate, or terminate sessions.",
                    risk_factors=event.risk_reasons,
                    event_timestamp=event.timestamp,
                )
            )
            created += 1
        if created:
            self._session.commit()
        return created

    def create_ml_alert(
        self,
        event: SecurityEvent,
        *,
        score: float,
        explanation: str | None = None,
        detection_type: str = "ml_anomaly",
    ) -> Alert | None:
        """Create an ML anomaly alert if one does not already exist.

        Preserves the event's stored risk_score and severity. Isolation Forest strength is stored
        separately in `confidence` (raw anomaly score) and must not inflate event risk.
        """
        existing = self._session.scalar(
            select(Alert).where(Alert.event_id == event.event_id)
        )
        if existing:
            if existing.detection_type == "rule_based":
                existing.detection_type = "hybrid"
                self._session.commit()
            return existing

        event_score = int(getattr(event, "risk_score", 0) or 0)
        event_severity = _normalize_severity(getattr(event, "severity", None), fallback_score=event_score)
        alert = Alert(
            event_id=event.event_id,
            server_id=getattr(event, "server_id", None),
            owner_id=getattr(event, "owner_id", None),
            account_id=getattr(event, "account_id", None),
            title=f"ML Anomaly: {event.event_type}",
            message=f"Behavioral anomaly detected (anomaly_score={float(score):.2f}): {event.message}",
            severity=event_severity,
            risk_score=event_score,
            risk_level=getattr(event, "risk_level", None) or risk_level_from_score(event_score),
            detection_type=detection_type,
            explanation=explanation,
            recommendation="Advisory only: review the actor, host, and related cloud activity. DefenSync does not block, isolate, or terminate sessions.",
            event_timestamp=event.timestamp,
            confidence=float(score),
        )
        self._session.add(alert)
        self._session.commit()
        return alert

    def create_auth_security_alert(
        self,
        *,
        owner_id: str,
        account_id: str | None,
        reason_code: str,
        outcome: str,
        title: str,
        message: str,
        source_ip: str | None = None,
        user_agent: str | None = None,
        device_ref: str | None = None,
        dedupe_seconds: int = 900,
    ) -> Alert | None:
        """Persist an AUTH-scoped event + alert for account security (e.g. device-limit denial).

        Never stores passwords, OTPs, or private keys. source_type=AUTH stays out of Linux/Cloud
        environment filters. Deduplicates recent identical reason_code alerts for the same owner.
        """
        now = datetime.now(timezone.utc)
        if dedupe_seconds > 0:
            since = now - timedelta(seconds=dedupe_seconds)
            recent = self._session.scalar(
                select(Alert)
                .where(
                    Alert.owner_id == owner_id,
                    Alert.detection_type == "auth_security",
                    Alert.created_at >= since,
                    Alert.risk_factors == reason_code,
                )
                .order_by(desc(Alert.created_at))
            )
            if recent is not None:
                recent.message = message
                recent.explanation = json.dumps(
                    {
                        "reason_code": reason_code,
                        "outcome": outcome,
                        "device_ref": device_ref,
                        "source_ip": source_ip,
                        "user_agent": (user_agent or "")[:200] or None,
                    },
                    separators=(",", ":"),
                )
                self._session.commit()
                return recent

        event_id = str(uuid.uuid4())
        evidence = {
            "reason_code": reason_code,
            "outcome": outcome,
            "device_ref": device_ref,
            "source_ip": source_ip,
            "user_agent": (user_agent or "")[:200] or None,
            "user_id": owner_id,
            "account_id": account_id,
        }
        raw = json.dumps(evidence, separators=(",", ":"), sort_keys=True)
        event_hash = hashlib.sha256(f"auth:{event_id}:{raw}".encode("utf-8")).hexdigest()
        event = SecurityEvent(
            event_id=event_id,
            owner_id=owner_id,
            account_id=account_id,
            data_scope=DATA_SCOPE_PRIVATE,
            timestamp=now,
            created_at=now,
            hostname="defensync-auth",
            username=None,
            source_ip=source_ip,
            event_type=reason_code,
            category="authentication",
            severity="high",
            risk_score=80,
            risk_level="high",
            message=message,
            raw_log=raw,
            hash=event_hash,
            source_type=AUTH_SOURCE_TYPE,
            provider="DEFENSYNC",
            data_origin="AUTH_SECURITY",
            normalized_data=raw,
            risk_reasons=reason_code,
        )
        alert = Alert(
            event_id=event_id,
            owner_id=owner_id,
            account_id=account_id,
            title=title[:200],
            message=message,
            severity="high",
            risk_score=80,
            risk_level="high",
            detection_type="auth_security",
            explanation=raw,
            recommendation=(
                "Review trusted devices for this user. Revoke unknown devices or raise the "
                "per-user limit only through an authorized administrator. Use MFA/password reset "
                "for account recovery; do not treat IP or user-agent as device identity."
            ),
            risk_factors=reason_code,
            event_timestamp=now,
            confidence=0.95,
        )
        self._session.add(event)
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
        account_id: str | None = None,
        environment: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return enriched alert views newest first. `environment` keeps alerts whose event belongs to it."""
        stmt = select(Alert).order_by(desc(Alert.created_at)).limit(limit)
        event_filter = with_environment(None, environment)
        if event_filter is not None:
            stmt = stmt.join(SecurityEvent, SecurityEvent.event_id == Alert.event_id).where(event_filter)
        if acknowledged is not None:
            stmt = stmt.where(Alert.acknowledged == acknowledged)
        if account_id:
            stmt = stmt.where(Alert.account_id == account_id)
        elif owner_id:
            stmt = stmt.where(Alert.owner_id == owner_id)
        if server_id:
            stmt = stmt.where(Alert.server_id == server_id)
        rows = list(self._session.scalars(stmt).all())
        return [serialize_alert(self._session, alert) for alert in rows]

    def acknowledge(self, alert_id: str, *, owner_id: str | None = None) -> dict[str, Any]:
        """Mark an alert as acknowledged."""
        alert = self._session.get(Alert, alert_id)
        if alert is None:
            raise ValueError(f"Alert {alert_id} not found.")
        if owner_id and alert.owner_id != owner_id:
            raise ValueError(f"Alert {alert_id} not found.")
        alert.acknowledged = True
        self._session.commit()
        return serialize_alert(self._session, alert)

    def summary(
        self,
        *,
        owner_id: str | None = None,
        server_id: str | None = None,
        environment: str | None = None,
        visibility=None,
    ) -> dict[str, Any]:
        """Return alert counts for dashboard widgets.

        `environment` and `visibility` restrict counts to alerts whose event is in
        that environment and visible in that event scope.

        Priority counts use linked event risk for ML alerts so legacy rows that stored
        severity=high / risk_score=75 do not inflate the Priority metric.
        """
        ml_like = or_(
            Alert.detection_type.ilike("%ml%"),
            Alert.detection_type.ilike("%isolation_forest%"),
            Alert.detection_type == "hybrid",
        )
        priority_expr = case(
            (ml_like & (SecurityEvent.risk_score >= HIGH_RISK_THRESHOLD), 1),
            ((~ml_like) & (func.lower(Alert.severity).in_(("critical", "high"))), 1),
            else_=0,
        )
        stmt = select(
            func.count(Alert.id),
            func.sum(case((Alert.acknowledged.is_(False), 1), else_=0)),
            func.sum(case((Alert.detection_type == "rule_based", 1), else_=0)),
            func.sum(case((ml_like, 1), else_=0)),
            func.sum(case((Alert.severity == "critical", 1), else_=0)),
            func.sum(priority_expr),
        ).select_from(Alert).join(SecurityEvent, SecurityEvent.event_id == Alert.event_id, isouter=True)
        event_filter = with_environment(visibility, environment)
        if event_filter is not None:
            stmt = stmt.where(event_filter)
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
            "priority": int(row[5] or 0),
        }

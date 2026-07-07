"""ML-based behavioral anomaly detection for security events."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from backend.database.models import MLPrediction, SecurityEvent
from backend.services.alert_service import AlertService

logger = logging.getLogger(__name__)

SEVERITY_MAP = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SUSPICIOUS_TYPES = {"Failed Login", "Invalid User", "User Creation", "Sudo Command"}


class DetectionService:
    """Hybrid detection: rule-based risk scores + Isolation Forest + Random Forest."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._alert_service = AlertService(session)

    def _load_events(self, limit: int = 2000, server_id: str | None = None, owner_id: str | None = None) -> list[SecurityEvent]:
        stmt = select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(limit)
        if server_id:
            stmt = stmt.where(SecurityEvent.server_id == server_id)
        if owner_id:
            stmt = stmt.where(SecurityEvent.owner_id == owner_id)
        events = list(reversed(self._session.scalars(stmt).all()))
        return events

    @staticmethod
    def _server_feature(server_id: str | None) -> float:
        if not server_id:
            return 0.0
        return float(abs(hash(server_id)) % 1000) / 1000.0

    @staticmethod
    def _features(events: list[SecurityEvent]) -> np.ndarray:
        rows: list[list[float]] = []
        for event in events:
            ts = event.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            login_hour = float(ts.hour)
            if getattr(event, "login_time", None):
                lt = event.login_time
                if lt.tzinfo is None:
                    lt = lt.replace(tzinfo=timezone.utc)
                login_hour = float(lt.hour)
            rows.append(
                [
                    login_hour,
                    float(getattr(event, "session_duration", 0) or 0),
                    float(getattr(event, "failed_login_count", 0) or 0),
                    float(getattr(event, "cpu_usage", 0) or 0),
                    float(getattr(event, "memory_usage", 0) or 0),
                    float(getattr(event, "disk_usage", 0) or 0),
                    float(getattr(event, "commands_executed", 0) or 0),
                    float(getattr(event, "network_connections", 0) or 0),
                    float(event.risk_score),
                    float(SEVERITY_MAP.get(event.severity, 0)),
                    1.0 if event.event_type in SUSPICIOUS_TYPES else 0.0,
                    1.0 if event.event_type == "Failed Login" else 0.0,
                    1.0 if event.username and event.username.lower() == "root" else 0.0,
                    1.0 if event.source_ip and not event.source_ip.startswith("127.") else 0.0,
                    DetectionService._server_feature(getattr(event, "server_id", None)),
                ]
            )
        return np.array(rows, dtype=float)

    @staticmethod
    def _labels(events: list[SecurityEvent]) -> np.ndarray:
        return np.array(
            [1 if e.risk_score >= 70 or e.event_type in SUSPICIOUS_TYPES else 0 for e in events],
            dtype=int,
        )

    def run_detection(
        self,
        *,
        owner_id: str | None = None,
        server_id: str | None = None,
    ) -> dict[str, Any]:
        """Run hybrid detection pipeline and sync alerts."""
        events = self._load_events(owner_id=owner_id, server_id=server_id)
        rule_created = self._alert_service.sync_from_events(owner_id=owner_id)

        if len(events) < 10:
            return {
                "success": True,
                "events_analyzed": len(events),
                "rule_alerts_created": rule_created,
                "ml_anomalies": 0,
                "ml_classified_suspicious": 0,
                "normal": len([e for e in events if e.risk_score < 70]),
                "suspicious": len([e for e in events if 70 <= e.risk_score < 85]),
                "malicious": len([e for e in events if e.risk_score >= 85]),
                "predictions_stored": 0,
                "message": "Need at least 10 events for ML detection. Rule-based alerts synced.",
            }

        features = self._features(events)
        labels = self._labels(events)

        iso = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
        iso.fit(features)
        anomaly_flags = iso.predict(features) == -1
        anomaly_scores = -iso.score_samples(features)

        unique_labels = len(set(labels.tolist()))
        rf_suspicious = np.zeros(len(events), dtype=bool)
        if unique_labels >= 2:
            rf = RandomForestClassifier(n_estimators=50, random_state=42, max_depth=6)
            rf.fit(features, labels)
            rf_suspicious = rf.predict(features) == 1

        ml_count = 0
        rf_count = int(rf_suspicious.sum())
        normal_count = 0
        suspicious_count = 0
        malicious_count = 0
        prediction_rows: list[MLPrediction] = []
        for idx, event in enumerate(events):
            score = float(anomaly_scores[idx])
            is_anomaly = bool(anomaly_flags[idx])
            is_rf_suspicious = bool(rf_suspicious[idx])
            if event.risk_score >= 85 or (is_anomaly and is_rf_suspicious):
                classification = "Malicious"
                malicious_count += 1
            elif event.risk_score >= 70 or is_anomaly or is_rf_suspicious:
                classification = "Suspicious"
                suspicious_count += 1
            else:
                classification = "Normal"
                normal_count += 1

            detection_type = "normal"
            if is_anomaly and is_rf_suspicious:
                detection_type = "hybrid"
            elif is_anomaly:
                detection_type = "isolation_forest"
            elif is_rf_suspicious:
                detection_type = "random_forest"
            elif event.risk_score >= 70:
                detection_type = "rule_based"

            prediction_rows.append(
                MLPrediction(
                    server_id=getattr(event, "server_id", None) or "unassigned",
                    owner_id=getattr(event, "owner_id", None),
                    event_id=event.event_id,
                    isolation_score=score,
                    random_forest_label="suspicious" if is_rf_suspicious else "normal",
                    classification=classification,
                    confidence=round(min(0.99, max(0.5, score / (score + 1.0))), 3),
                    detection_type=detection_type,
                    message=f"{classification}: {event.event_type}",
                    is_anomaly=is_anomaly,
                    risk_score=event.risk_score,
                )
            )
            if anomaly_flags[idx] or rf_suspicious[idx]:
                self._alert_service.create_ml_alert(event, score=score)
                ml_count += 1

        delete_stmt = delete(MLPrediction)
        if owner_id:
            delete_stmt = delete_stmt.where(MLPrediction.owner_id == owner_id)
        if server_id:
            delete_stmt = delete_stmt.where(MLPrediction.server_id == server_id)
        elif events:
            event_ids = [event.event_id for event in events]
            delete_stmt = delete_stmt.where(MLPrediction.event_id.in_(event_ids))
        else:
            delete_stmt = None
        if delete_stmt is not None:
            self._session.execute(delete_stmt)
        self._session.add_all(prediction_rows)
        self._session.commit()

        return {
            "success": True,
            "events_analyzed": len(events),
            "rule_alerts_created": rule_created,
            "ml_anomalies": int(anomaly_flags.sum()),
            "ml_classified_suspicious": rf_count,
            "total_flagged": ml_count,
            "normal": normal_count,
            "suspicious": suspicious_count,
            "malicious": malicious_count,
            "predictions_stored": len(prediction_rows),
            "message": "Hybrid detection complete (Isolation Forest + Random Forest).",
        }

    def get_anomalies(self, *, limit: int = 20, server_id: str | None = None, owner_id: str | None = None) -> list[dict[str, Any]]:
        """Return recently flagged high-risk and ML-detected events."""
        stored = self._stored_anomalies(limit=limit, server_id=server_id, owner_id=owner_id)
        if stored:
            return stored

        events = self._load_events(limit=max(limit * 5, 50), server_id=server_id, owner_id=owner_id)
        if len(events) < 5:
            high_risk = [e for e in events if e.risk_score >= 70]
            return [self._event_summary(e, "rule_based") for e in high_risk[:limit]]

        features = self._features(events)
        iso = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
        iso.fit(features)
        flags = iso.predict(features) == -1
        scores = -iso.score_samples(features)

        results: list[dict[str, Any]] = []
        for idx, event in enumerate(events):
            if flags[idx] or event.risk_score >= 70:
                detection = "ml_anomaly" if flags[idx] else "rule_based"
                if flags[idx] and event.risk_score >= 70:
                    detection = "hybrid"
                results.append(
                    {
                        **self._event_summary(event, detection),
                        "anomaly_score": round(float(scores[idx]), 3),
                        "classification": "Malicious" if event.risk_score >= 85 else "Suspicious",
                    }
                )
        results.sort(key=lambda r: (r["anomaly_score"], r["risk_score"]), reverse=True)
        return results[:limit]

    def _stored_anomalies(
        self,
        *,
        limit: int,
        server_id: str | None = None,
        owner_id: str | None = None,
    ) -> list[dict[str, Any]]:
        stmt = (
            select(MLPrediction, SecurityEvent)
            .join(SecurityEvent, SecurityEvent.event_id == MLPrediction.event_id)
            .where(MLPrediction.classification.in_(("Suspicious", "Malicious")))
            .order_by(MLPrediction.created_at.desc())
            .limit(limit)
        )
        if server_id:
            stmt = stmt.where(MLPrediction.server_id == server_id)
        if owner_id:
            stmt = stmt.where(MLPrediction.owner_id == owner_id)
        rows = self._session.execute(stmt).all()
        return [
            {
                **self._event_summary(event, prediction.detection_type or "ml_anomaly"),
                "classification": prediction.classification,
                "anomaly_score": round(float(prediction.isolation_score or 0), 3),
                "confidence": prediction.confidence,
                "message": prediction.message or event.message,
            }
            for prediction, event in rows
        ]

    @staticmethod
    def _event_summary(event: SecurityEvent, detection_type: str) -> dict[str, Any]:
        return {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
            "hostname": event.hostname,
            "username": event.username,
            "source_ip": event.source_ip,
            "event_type": event.event_type,
            "severity": event.severity,
            "risk_score": event.risk_score,
            "risk_level": getattr(event, "risk_level", None),
            "server_id": getattr(event, "server_id", None),
            "message": event.message,
            "detection_type": detection_type,
            "classification": "Malicious" if event.risk_score >= 85 else "Suspicious" if event.risk_score >= 70 else "Normal",
        }

    def status(
        self,
        *,
        owner_id: str | None = None,
        server_id: str | None = None,
    ) -> dict[str, Any]:
        """Detection engine status for dashboard."""
        from sqlalchemy import func

        stmt = select(func.count(SecurityEvent.id))
        if owner_id:
            stmt = stmt.where(SecurityEvent.owner_id == owner_id)
        if server_id:
            stmt = stmt.where(SecurityEvent.server_id == server_id)
        event_count = self._session.scalar(stmt) or 0
        alert_summary = self._alert_service.summary(owner_id=owner_id, server_id=server_id)
        return {
            "engine": "DefenSync Hybrid Detection",
            "models": ["Isolation Forest", "Random Forest", "Rule Engine"],
            "events_in_db": event_count,
            "ready": event_count >= 10,
            "alerts": alert_summary,
        }

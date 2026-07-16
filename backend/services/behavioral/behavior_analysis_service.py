"""Behavioral telemetry deviation analysis service."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from backend.core.exceptions import ResourceNotFoundError
from backend.database.models import BehaviorProfile, SecurityEvent
from backend.services.behavioral.baseline_service import BehavioralBaselineService
from backend.services.behavioral.over_efficiency_detector import OverEfficiencyDetector
from backend.services.behavioral.schemas import DATASET_NAME, EVENT_TYPE, SOURCE_TYPE


class BehavioralAnalysisService:
    def __init__(self, session: Session) -> None:
        self._session = session
        self._baselines = BehavioralBaselineService(session)
        self._detector = OverEfficiencyDetector()

    def analyze_all(self, *, owner_id: str | None = None, limit: int | None = None) -> dict[str, Any]:
        stmt = select(SecurityEvent).where(SecurityEvent.source_type == SOURCE_TYPE, SecurityEvent.event_type == EVENT_TYPE)
        if owner_id:
            stmt = stmt.where(SecurityEvent.owner_id == owner_id)
        stmt = stmt.order_by(SecurityEvent.timestamp.asc())
        if limit:
            stmt = stmt.limit(limit)
        events = list(self._session.scalars(stmt).all())
        analyzed = 0
        insufficient = 0
        for event in events:
            result = self.analyze_event(event.event_id, owner_id=owner_id, commit=False)
            if result["status"] == "ANALYZED":
                analyzed += 1
            else:
                insufficient += 1
        self._session.commit()
        return {"events_seen": len(events), "events_analyzed": analyzed, "insufficient_baseline": insufficient}

    def analyze_event(self, event_id: str, *, owner_id: str | None = None, commit: bool = True) -> dict[str, Any]:
        stmt = select(SecurityEvent).where(SecurityEvent.event_id == event_id)
        if owner_id:
            stmt = stmt.where(SecurityEvent.owner_id == owner_id)
        event = self._session.scalar(stmt)
        if event is None:
            raise ResourceNotFoundError(f"Behavioral event '{event_id}' not found.")
        profile = self._baselines.get_profile(identity_key=event.actor_id or "", server_id=event.server_id, owner_id=event.owner_id)
        if profile is None or profile.status != "ACTIVE":
            event.behavioral_classification = "INSUFFICIENT_BASELINE"
            event.behavioral_risk_score = 0
            event.risk_reasons = json.dumps(["Insufficient baseline samples for this user/server."])
            if commit:
                self._session.commit()
            return {"status": "INSUFFICIENT_BASELINE", "event_id": event.event_id}

        result = self._detector.evaluate(event, profile)
        event.behavioral_risk_score = result.risk_score
        event.behavioral_classification = result.classification
        event.risk_score = result.risk_score
        event.risk_level = _risk_level(result.risk_score)
        event.risk_reasons = json.dumps(result.reasons)
        event.baseline_version = profile.baseline_version
        event.normalized_data = _merge_json(
            event.normalized_data,
            {
                "behavioral_analysis": {
                    "triggered_signals": result.triggered_signals,
                    "reasons": result.reasons,
                    "baseline_values": result.baseline_values,
                    "observed_values": result.observed_values,
                    "deviations": result.deviations,
                }
            },
        )
        if commit:
            self._session.commit()
        return {
            "status": "ANALYZED",
            "event_id": event.event_id,
            "risk_score": result.risk_score,
            "classification": result.classification,
            "reasons": result.reasons,
            "triggered_signals": result.triggered_signals,
        }

    def anomalies(self, *, owner_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        stmt = (
            select(SecurityEvent)
            .where(SecurityEvent.source_type == SOURCE_TYPE, SecurityEvent.behavioral_risk_score >= 50)
            .order_by(desc(SecurityEvent.behavioral_risk_score), desc(SecurityEvent.timestamp))
            .limit(limit)
        )
        if owner_id:
            stmt = stmt.where(SecurityEvent.owner_id == owner_id)
        return [_event_summary(event) for event in self._session.scalars(stmt).all()]

    def summary(self, *, owner_id: str | None = None) -> dict[str, Any]:
        base = [
            SecurityEvent.source_type == SOURCE_TYPE,
            SecurityEvent.dataset_name == DATASET_NAME,
            SecurityEvent.event_type == EVENT_TYPE,
        ]
        if owner_id:
            base.append(SecurityEvent.owner_id == owner_id)

        def count(*extra: Any) -> int:
            return self._session.scalar(select(func.count(SecurityEvent.id)).where(*base, *extra)) or 0

        avg = self._session.scalar(select(func.avg(SecurityEvent.behavioral_risk_score)).where(*base)) or 0
        profiles = self._session.scalar(select(func.count(BehaviorProfile.id)).where(*( [BehaviorProfile.owner_id == owner_id] if owner_id else [] ))) or 0
        insufficient = self._session.scalar(select(func.count(BehaviorProfile.id)).where(BehaviorProfile.status == "INSUFFICIENT_DATA", *( [BehaviorProfile.owner_id == owner_id] if owner_id else [] ))) or 0
        highest = self._session.scalars(
            select(SecurityEvent).where(*base).order_by(desc(SecurityEvent.behavioral_risk_score)).limit(5)
        ).all()
        signal_counter: Counter[str] = Counter()
        for event in highest:
            try:
                analysis = json.loads(event.normalized_data or "{}").get("behavioral_analysis", {})
                signal_counter.update(analysis.get("triggered_signals", []))
            except Exception:
                pass
        return {
            "total_behavioral_events": count(),
            "normal_events": count(SecurityEvent.behavioral_classification == "NORMAL"),
            "anomalous_events": count(SecurityEvent.behavioral_classification != "NORMAL"),
            "over_efficiency_events": count(SecurityEvent.behavioral_classification == "OVER_EFFICIENCY"),
            "automated_activity_events": count(SecurityEvent.behavioral_classification == "AUTOMATED_ACTIVITY"),
            "users_profiled": profiles,
            "profiles_with_insufficient_data": insufficient,
            "average_behavioral_risk": round(float(avg), 2),
            "highest_risk_users": [_event_summary(event) for event in highest],
            "most_common_triggered_signals": signal_counter.most_common(10),
        }


def _merge_json(existing: str | None, patch: dict[str, Any]) -> str:
    try:
        payload = json.loads(existing or "{}")
    except Exception:
        payload = {}
    payload.update(patch)
    return json.dumps(payload, default=str)


def _risk_level(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 50:
        return "medium"
    if score >= 30:
        return "low"
    return "info"


def _event_summary(event: SecurityEvent) -> dict[str, Any]:
    return {
        "event_id": event.event_id,
        "actor_id": event.actor_id,
        "linux_username": event.username,
        "server_id": event.server_id,
        "session_id": event.session_id,
        "timestamp": event.timestamp,
        "behavioral_risk_score": event.behavioral_risk_score,
        "behavioral_classification": event.behavioral_classification,
        "risk_reasons": json.loads(event.risk_reasons or "[]"),
    }

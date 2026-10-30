"""Cloud identity behavioral baseline v0: observed activity aggregates only.

Groups PRIVATE CLOUD events by cloud `actor_id` (Entra object ID / UPN / caller),
never by DefenSync owner_id or account_id. Default data origin is real Azure
telemetry (AZURE_LOG_ANALYTICS); public, synthetic, presentation, Linux, and HPC
rows are excluded. A baseline describes observed activity — it does not assert
compromise or malice.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from backend.core.environments import CLOUD
from backend.core.exceptions import ValidationException
from backend.core.timestamps import ensure_aware
from backend.database.models import SecurityEvent, User
from backend.database.scope import environment_clause, event_visibility_clause, with_environment
from backend.services.cloud.azure_normalizer import DATA_ORIGIN as AZURE_LOG_ANALYTICS_ORIGIN

# Real Azure live telemetry only for v0. Dataset / demo / presentation origins stay out.
ALLOWED_DATA_ORIGINS = frozenset({AZURE_LOG_ANALYTICS_ORIGIN})
DEFAULT_DATA_ORIGINS = (AZURE_LOG_ANALYTICS_ORIGIN,)
MAX_WINDOW = timedelta(days=30)
MIN_WINDOW = timedelta(minutes=1)
DISCLAIMER = (
    "Observed activity baseline only; not a determination of compromise or malicious behavior."
)


def _parse_cloud_identity(normalized_data: str | None) -> dict[str, Any] | None:
    if not normalized_data:
        return None
    try:
        payload = json.loads(normalized_data)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    identity = payload.get("cloud_identity")
    if not isinstance(identity, dict):
        return None
    keys = ("tenant_id", "object_id", "user_principal_name", "display_name", "identity_type", "caller", "application_id")
    view = {key: identity.get(key) for key in keys if identity.get(key) not in (None, "")}
    return view or None


class CloudIdentityBaselineService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def build(
        self,
        *,
        user: User,
        start_time: datetime,
        end_time: datetime,
        actor_id: str | None = None,
        data_origins: list[str] | None = None,
    ) -> dict[str, Any]:
        if start_time is None or end_time is None:
            raise ValidationException("start_time and end_time are required.")
        start = ensure_aware(start_time)
        end = ensure_aware(end_time)
        if end <= start:
            raise ValidationException("end_time must be after start_time.")
        duration = end - start
        if duration < MIN_WINDOW:
            raise ValidationException("Time window is too short.")
        if duration > MAX_WINDOW:
            raise ValidationException(f"Time window must be at most {int(MAX_WINDOW.total_seconds() // 3600)} hours.")

        origins = self._origins(data_origins)
        visibility = with_environment(event_visibility_clause(scope="private", user=user), CLOUD)
        clauses = [
            environment_clause(CLOUD),
            SecurityEvent.data_origin.in_(tuple(origins)),
            SecurityEvent.timestamp >= start,
            SecurityEvent.timestamp < end,
        ]
        if visibility is not None:
            clauses.insert(0, visibility)
        wanted_actor = (actor_id or "").strip() or None
        if wanted_actor:
            clauses.append(SecurityEvent.actor_id == wanted_actor)

        rows = list(
            self._session.scalars(
                select(SecurityEvent)
                .where(and_(*clauses))
                .order_by(SecurityEvent.timestamp.asc())
            ).all()
        )

        by_actor: dict[str, list[SecurityEvent]] = defaultdict(list)
        skipped_missing_identity = 0
        for event in rows:
            key = (event.actor_id or "").strip()
            if not key:
                skipped_missing_identity += 1
                continue
            by_actor[key].append(event)

        duration_hours = max(duration.total_seconds() / 3600.0, MIN_WINDOW.total_seconds() / 3600.0)
        identities = [
            self._identity_baseline(actor, events, duration_hours=duration_hours)
            for actor, events in sorted(by_actor.items(), key=lambda item: (-len(item[1]), item[0]))
        ]
        event_count = sum(item["event_count"] for item in identities)
        return {
            "environment": CLOUD,
            "data_origins": sorted(origins),
            "window": {
                "start_time": start.isoformat(),
                "end_time": end.isoformat(),
                "duration_hours": round(duration_hours, 4),
            },
            "disclaimer": DISCLAIMER,
            "identities": identities,
            "summary": {
                "identity_count": len(identities),
                "event_count": event_count,
                "events_skipped_missing_identity": skipped_missing_identity,
            },
        }

    @staticmethod
    def _origins(requested: list[str] | None) -> frozenset[str]:
        if not requested:
            return frozenset(DEFAULT_DATA_ORIGINS)
        cleaned = {(value or "").strip() for value in requested if (value or "").strip()}
        if not cleaned:
            raise ValidationException("data_origins cannot be empty.")
        unknown = sorted(cleaned - ALLOWED_DATA_ORIGINS)
        if unknown:
            raise ValidationException(
                "Unsupported data_origins for cloud identity baselines: "
                + ", ".join(unknown)
                + f". Allowed: {', '.join(sorted(ALLOWED_DATA_ORIGINS))}."
            )
        return frozenset(cleaned)

    @staticmethod
    def _identity_baseline(actor: str, events: list[SecurityEvent], *, duration_hours: float) -> dict[str, Any]:
        operations: set[str] = set()
        resources: set[str] = set()
        hourly = {str(hour): 0 for hour in range(24)}
        missing_ts = 0
        identity_view: dict[str, Any] | None = None
        for event in events:
            operation = (event.operation or "").strip()
            if operation:
                operations.add(operation)
            resource = (event.resource_id or "").strip()
            if resource:
                resources.add(resource)
            if identity_view is None:
                identity_view = _parse_cloud_identity(event.normalized_data)
            if event.timestamp is None:
                missing_ts += 1
                continue
            ts = ensure_aware(event.timestamp)
            hourly[str(ts.astimezone(timezone.utc).hour)] += 1

        count = len(events)
        return {
            "actor_id": actor,
            "cloud_identity": identity_view,
            "event_count": count,
            "activity_rate_per_hour": round(count / duration_hours, 4),
            "distinct_operations": len(operations),
            "distinct_resources": len(resources),
            "hourly_distribution": hourly,
            "events_missing_timestamp": missing_ts,
        }

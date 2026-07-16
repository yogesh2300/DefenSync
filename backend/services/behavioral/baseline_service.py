"""Behavioral baseline construction from normal aggregate telemetry."""

from __future__ import annotations

import statistics
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.core.config import get_settings
from backend.database.models import BehaviorProfile, SecurityEvent
from backend.services.behavioral.schemas import DATASET_NAME, EVENT_TYPE, SOURCE_TYPE, identity_key

METRICS = {
    "typing": ("typing_speed_cpm", "average_typing_speed", "std_typing_speed"),
    "command_rate": ("command_rate_per_minute", "average_command_rate", "std_command_rate"),
    "error_rate": ("command_error_rate", "average_command_error_rate", "std_command_error_rate"),
    "idle": ("idle_time_seconds", "average_idle_time", "std_idle_time"),
    "repetition": ("repeated_command_ratio", "average_repeated_command_ratio", "std_repeated_command_ratio"),
    "duration": ("session_duration_minutes", "average_session_duration", "std_session_duration"),
}


class BehavioralBaselineService:
    def __init__(self, session: Session) -> None:
        self._session = session
        self._settings = get_settings()

    def build_all(self, *, owner_id: str | None = None) -> dict[str, Any]:
        identities = self._session.execute(
            select(SecurityEvent.actor_id, SecurityEvent.server_id)
            .where(SecurityEvent.source_type == SOURCE_TYPE, SecurityEvent.event_type == EVENT_TYPE)
            .where(*( [SecurityEvent.owner_id == owner_id] if owner_id else [] ))
            .distinct()
        ).all()
        profiles = [self.build(identity_key=row[0], server_id=row[1], owner_id=owner_id) for row in identities if row[0]]
        return {"profiles_processed": len(profiles), "profiles": [profile_to_dict(p) for p in profiles]}

    def build(self, *, identity_key: str, server_id: str | None = None, owner_id: str | None = None) -> BehaviorProfile:
        rows = self._normal_events(identity_key=identity_key, server_id=server_id, owner_id=owner_id)
        effective_owner = owner_id or (rows[0].owner_id if rows else None)
        profile = self._get_or_create(identity_key=identity_key, server_id=server_id, owner_id=effective_owner)
        profile.profile_sample_count = len(rows)
        if len(rows) < self._settings.BEHAVIORAL_MIN_BASELINE_SAMPLES:
            profile.status = "INSUFFICIENT_DATA"
            profile.updated_at = datetime.now(timezone.utc)
            self._session.add(profile)
            self._session.commit()
            return profile

        for source_field, field, std_field in METRICS.values():
            values = [float(getattr(row, source_field, 0) or 0) for row in rows]
            setattr(profile, field, round(statistics.mean(values), 4))
            setattr(profile, std_field, round(statistics.pstdev(values), 4))

        hours = sorted(int(row.login_hour or 0) for row in rows)
        profile.usual_login_start = max(0, min(hours))
        profile.usual_login_end = min(23, max(hours))
        sample = rows[0]
        profile.user_id = sample.actor_id
        profile.linux_username = sample.username
        profile.status = "ACTIVE"
        profile.baseline_version = (profile.baseline_version or 0) + 1
        profile.last_updated = datetime.now(timezone.utc)
        profile.updated_at = datetime.now(timezone.utc)
        self._session.add(profile)
        self._session.commit()
        return profile

    def list_profiles(self, *, owner_id: str | None = None) -> list[BehaviorProfile]:
        stmt = select(BehaviorProfile).order_by(BehaviorProfile.identity_key)
        if owner_id:
            stmt = stmt.where(BehaviorProfile.owner_id == owner_id)
        return list(self._session.scalars(stmt).all())

    def get_profile(self, *, identity_key: str, server_id: str | None = None, owner_id: str | None = None) -> BehaviorProfile | None:
        stmt = select(BehaviorProfile).where(BehaviorProfile.identity_key == identity_key)
        if server_id:
            stmt = stmt.where(BehaviorProfile.server_id == server_id)
        if owner_id:
            stmt = stmt.where(BehaviorProfile.owner_id == owner_id)
        return self._session.scalar(stmt)

    def _normal_events(self, *, identity_key: str, server_id: str | None, owner_id: str | None) -> list[SecurityEvent]:
        stmt = select(SecurityEvent).where(
            SecurityEvent.source_type == SOURCE_TYPE,
            SecurityEvent.dataset_name == DATASET_NAME,
            SecurityEvent.event_type == EVENT_TYPE,
            SecurityEvent.actor_id == identity_key,
            SecurityEvent.original_label == "NORMAL",
            SecurityEvent.risk_score <= self._settings.BEHAVIORAL_BASELINE_UPDATE_MAX_RISK,
        )
        if server_id:
            stmt = stmt.where(SecurityEvent.server_id == server_id)
        if owner_id:
            stmt = stmt.where(SecurityEvent.owner_id == owner_id)
        return list(self._session.scalars(stmt).all())

    def _get_or_create(self, *, identity_key: str, server_id: str | None, owner_id: str | None) -> BehaviorProfile:
        profile = self.get_profile(identity_key=identity_key, server_id=server_id, owner_id=owner_id)
        if profile:
            return profile
        return BehaviorProfile(owner_id=owner_id or "unknown", identity_key=identity_key, server_id=server_id)


def profile_to_dict(profile: BehaviorProfile) -> dict[str, Any]:
    return {
        "id": profile.id,
        "owner_id": profile.owner_id,
        "identity_key": profile.identity_key,
        "user_id": profile.user_id,
        "linux_username": profile.linux_username,
        "server_id": profile.server_id,
        "status": profile.status,
        "profile_sample_count": profile.profile_sample_count,
        "baseline_version": profile.baseline_version,
        "average_typing_speed": profile.average_typing_speed,
        "std_typing_speed": profile.std_typing_speed,
        "average_command_rate": profile.average_command_rate,
        "std_command_rate": profile.std_command_rate,
        "average_command_error_rate": profile.average_command_error_rate,
        "std_command_error_rate": profile.std_command_error_rate,
        "average_idle_time": profile.average_idle_time,
        "std_idle_time": profile.std_idle_time,
        "average_repeated_command_ratio": profile.average_repeated_command_ratio,
        "std_repeated_command_ratio": profile.std_repeated_command_ratio,
        "average_session_duration": profile.average_session_duration,
        "std_session_duration": profile.std_session_duration,
        "usual_login_start": profile.usual_login_start,
        "usual_login_end": profile.usual_login_end,
        "last_updated": profile.last_updated,
    }

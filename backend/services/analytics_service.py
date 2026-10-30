"""Analytics service for aggregating and generating security metrics."""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any
from sqlalchemy import select, func, text, desc
from sqlalchemy.orm import Session

from backend.database.models import SecurityEvent

logger = logging.getLogger(__name__)


class AnalyticsService:
    """Service layer handling security statistics, aggregations, and metrics."""

    def __init__(self, session: Session) -> None:
        """Initialize the AnalyticsService with a database session."""
        self._session = session

    def get_event_stats(
        self,
        *,
        owner_id: str | None = None,
        server_id: str | None = None,
        visibility=None,
    ) -> dict[str, Any]:
        """Aggregate security event statistics for SIEM dashboards."""
        logger.info("Calculating security event statistics server_id=%s", server_id)

        def scoped(stmt):
            if visibility is not None:
                stmt = stmt.where(visibility)
            elif owner_id:
                stmt = stmt.where(SecurityEvent.owner_id == owner_id)
            if server_id:
                stmt = stmt.where(SecurityEvent.server_id == server_id)
            return stmt

        total_stmt = scoped(select(func.count(SecurityEvent.id)))
        total_events = self._session.scalar(total_stmt) or 0

        severity_stmt = scoped(select(SecurityEvent.severity, func.count(SecurityEvent.id)).group_by(SecurityEvent.severity))
        severity_rows = self._session.execute(severity_stmt).all()
        severity_counts = {row[0]: row[1] for row in severity_rows}

        type_stmt = scoped(select(SecurityEvent.event_type, func.count(SecurityEvent.id)).group_by(SecurityEvent.event_type))
        type_rows = self._session.execute(type_stmt).all()
        type_counts = {row[0]: row[1] for row in type_rows}

        top_ips_stmt = scoped(
            select(SecurityEvent.source_ip, func.count(SecurityEvent.id))
            .where(SecurityEvent.source_ip.is_not(None), SecurityEvent.source_ip != "")
            .group_by(SecurityEvent.source_ip)
            .order_by(desc(func.count(SecurityEvent.id)))
            .limit(5)
        )
        top_ips_rows = self._session.execute(top_ips_stmt).all()
        top_source_ips = {row[0]: row[1] for row in top_ips_rows}

        top_users_stmt = scoped(
            select(SecurityEvent.username, func.count(SecurityEvent.id))
            .where(SecurityEvent.username.is_not(None), SecurityEvent.username != "")
            .group_by(SecurityEvent.username)
            .order_by(desc(func.count(SecurityEvent.id)))
            .limit(5)
        )
        top_users_rows = self._session.execute(top_users_stmt).all()
        top_usernames = {row[0]: row[1] for row in top_users_rows}

        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        hourly_counts = []

        try:
            hourly_stmt = scoped(
                select(
                    func.date_trunc("hour", SecurityEvent.timestamp).label("hour"),
                    func.count(SecurityEvent.id).label("count")
                )
                .where(SecurityEvent.timestamp >= cutoff)
                .group_by(text("hour"))
                .order_by(text("hour"))
            )
            hourly_rows = self._session.execute(hourly_stmt).all()
            for row in hourly_rows:
                hour_dt = row[0]
                if isinstance(hour_dt, datetime):
                    hour_str = hour_dt.strftime("%Y-%m-%d %H:00")
                else:
                    hour_str = str(hour_dt)
                hourly_counts.append({"hour": hour_str, "count": row[1]})
        except Exception as e:
            logger.warning("Failed SQL hourly aggregation, falling back to Python grouping: %s", str(e))
            self._session.rollback()
            all_events_stmt = scoped(select(SecurityEvent.timestamp).where(SecurityEvent.timestamp >= cutoff))
            events_ts = self._session.scalars(all_events_stmt).all()
            buckets: dict[str, int] = {}
            for i in range(24):
                slot = cutoff + timedelta(hours=i)
                buckets[slot.strftime("%Y-%m-%d %H:00")] = 0
            for ts in events_ts:
                if ts:
                    ts_utc = ts.astimezone(timezone.utc) if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
                    bucket_key = ts_utc.strftime("%Y-%m-%d %H:00")
                    if bucket_key in buckets:
                        buckets[bucket_key] += 1
                    else:
                        buckets[bucket_key] = 1
            hourly_counts = [{"hour": k, "count": v} for k, v in sorted(buckets.items())]

        return {
            "total_events": total_events,
            "by_severity": severity_counts,
            "by_event_type": type_counts,
            "top_source_ips": top_source_ips,
            "top_usernames": top_usernames,
            "hourly_trends": hourly_counts,
        }
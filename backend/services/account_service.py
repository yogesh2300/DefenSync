"""Account-scoped aggregation using COUNT queries (never payload length).

Every summary is computed for exactly one environment (LINUX by default). Linux
and cloud events, alerts, detections, incidents, and risk series never contribute
to each other's aggregates; unknown source types belong to no environment.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from backend.core.environments import LINUX, normalize_environment
from backend.database import crud, server_crud
from backend.database.models import (
    DATA_SCOPE_PRIVATE,
    Account,
    Alert,
    BehaviorProfile,
    Detection,
    Incident,
    RiskHistory,
    SecurityEvent,
    Server,
    User,
)
from backend.database.scope import environment_clause, event_visibility_clause, is_admin, resolve_account_id, with_environment
from backend.services.correlation_service import account_entity_type, environment_from_source


class AccountService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def list_accounts(self) -> list[dict[str, Any]]:
        rows = list(self._session.scalars(select(Account).order_by(Account.name)).all())
        out = []
        for account in rows:
            users = self._session.scalar(select(func.count(User.id)).where(User.account_id == account.id)) or 0
            servers = self._session.scalar(select(func.count(Server.id)).where(Server.account_id == account.id)) or 0
            linux = self._session.scalar(
                select(func.count(SecurityEvent.id)).where(
                    SecurityEvent.account_id == account.id,
                    SecurityEvent.data_scope == DATA_SCOPE_PRIVATE,
                    environment_clause(LINUX),
                )
            ) or 0
            risk = self._latest_account_risk(account.id, LINUX)
            out.append({
                "id": account.id,
                "name": account.name,
                "users": int(users),
                "servers": int(servers),
                "linux_events": int(linux),
                "account_risk": risk,
            })
        return out

    def summary(
        self,
        user: User,
        *,
        selected_account_id: str | None = None,
        server_id: str | None = None,
        environment: str = LINUX,
    ) -> dict[str, Any]:
        environment = normalize_environment(environment)
        account_id = selected_account_id if is_admin(user) else resolve_account_id(user)
        account = self._session.get(Account, account_id) if account_id else None
        visibility = with_environment(
            event_visibility_clause(scope="private", user=user, selected_account_id=account_id),
            environment,
        )
        dash = crud.dashboard_summary(self._session, visibility=visibility, server_id=server_id, environment=environment)
        high_risk = crud.count_high_risk_events(
            self._session,
            min_score=70,
            server_id=server_id,
            visibility=visibility,
        )
        health = server_crud.health_summary(self._session, account_id=account_id, owner_id=None if account_id else (None if is_admin(user) else user.id), server_id=server_id)
        users = 0
        if account_id:
            users = int(self._session.scalar(select(func.count(User.id)).where(User.account_id == account_id)) or 0)
        else:
            users = 1
        anomalies = self._anomaly_count(user, visibility, account_id=account_id, server_id=server_id)
        alerts = self._alert_count(visibility, server_id=server_id)
        incidents = self._incident_count(user, account_id=account_id, environment=environment)
        trend = self._risk_trend(account_id, environment)
        risk = self._compute_account_risk(dash, high_risk, anomalies)
        return {
            "account_id": account_id,
            "account_name": account.name if account else None,
            "scope": "account" if account_id else ("platform" if is_admin(user) else "user"),
            "environment": environment,
            "events": dash.get("total_events", 0),
            "linux_events": dash.get("total_events", 0) if environment == LINUX else None,
            "high_risk_events": high_risk,
            "anomalies": anomalies,
            "anomaly_scope": "account" if account_id else "owner",
            "anomaly_note": "Stored detections are windowed ML scores, not a full-population census.",
            "alerts": alerts,
            "incidents": incidents,
            "servers": health.get("total_servers", 0),
            "users": users,
            "profiles": self._profile_count(user, account_id) if environment == LINUX else 0,
            "profile_scope": "account_local" if environment == LINUX else "no_baseline_for_environment",
            "failed_logins": dash.get("failed_logins", 0),
            "unique_users": dash.get("unique_users", 0),
            "average_risk_score": dash.get("average_risk_score", 0),
            "max_risk_score": dash.get("max_risk_score", 0),
            "account_risk": risk,
            "recent_risk": trend[-1]["risk_score"] if trend else None,
            "risk_trend": trend,
            "servers_health": health,
        }

    def _profile_count(self, user: User, account_id: str | None) -> int:
        stmt = select(func.count(BehaviorProfile.id))
        if account_id:
            stmt = stmt.where(BehaviorProfile.account_id == account_id)
        else:
            stmt = stmt.where(BehaviorProfile.owner_id == user.id)
        return int(self._session.scalar(stmt) or 0)

    def _anomaly_count(self, user: User, visibility, *, account_id: str | None, server_id: str | None) -> int:
        stmt = (
            select(func.count(Detection.id))
            .join(SecurityEvent, SecurityEvent.event_id == Detection.event_id)
            .where(Detection.is_anomaly.is_(True), visibility)
        )
        if account_id:
            stmt = stmt.where(Detection.account_id == account_id)
        elif not is_admin(user):
            stmt = stmt.where(Detection.owner_id == user.id)
        if server_id:
            stmt = stmt.where(Detection.server_id == server_id)
        return int(self._session.scalar(stmt) or 0)

    def _alert_count(self, visibility, *, server_id: str | None) -> int:
        stmt = select(func.count(Alert.id)).join(SecurityEvent, SecurityEvent.event_id == Alert.event_id).where(visibility)
        if server_id:
            stmt = stmt.where(SecurityEvent.server_id == server_id)
        return int(self._session.scalar(stmt) or 0)

    def _incident_count(self, user: User, *, account_id: str | None, environment: str) -> int:
        stmt = select(Incident.source, func.count(Incident.id)).group_by(Incident.source)
        if account_id:
            stmt = stmt.where(Incident.account_id == account_id)
        elif not is_admin(user):
            stmt = stmt.where(Incident.owner_id == user.id)
        return sum(int(count) for source, count in self._session.execute(stmt).all() if environment_from_source(source) == environment)

    def _latest_account_risk(self, account_id: str, environment: str) -> int:
        row = self._session.scalar(
            select(RiskHistory)
            .where(RiskHistory.entity_type == account_entity_type(environment), RiskHistory.account_id == account_id)
            .order_by(desc(RiskHistory.timestamp))
            .limit(1)
        )
        return int(row.risk_score) if row else 0

    def _risk_trend(self, account_id: str | None, environment: str) -> list[dict[str, Any]]:
        if not account_id:
            return []
        rows = list(
            self._session.scalars(
                select(RiskHistory)
                .where(RiskHistory.entity_type == account_entity_type(environment), RiskHistory.account_id == account_id)
                .order_by(desc(RiskHistory.timestamp))
                .limit(24)
            ).all()
        )
        rows.reverse()
        return [
            {
                "timestamp": row.timestamp.isoformat() if row.timestamp else None,
                "risk_score": row.risk_score,
                "reason": row.reason,
            }
            for row in rows
        ]

    @staticmethod
    def _compute_account_risk(dash: dict[str, Any], high_risk: int, anomalies: int) -> int:
        avg = int(dash.get("average_risk_score") or 0)
        high_component = min(40, int(high_risk / 50))
        anomaly_component = min(30, int(anomalies / 40))
        return max(0, min(100, round(avg * 0.4 + high_component + anomaly_component)))

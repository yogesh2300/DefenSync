"""Environment-scoped correlation using event occurrence time.

Events correlate only within one (tenant, environment, actor) partition: the
same actor name in Linux and in a cloud account is never merged into one
incident or one risk score. Cross-environment correlation is not implemented.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from backend.core.config import get_settings
from backend.core.logging import get_logger
from backend.core.environments import (
    BEHAVIORAL,
    CLOUD,
    HPC,
    LINUX,
    SOURCE_FAMILIES,
    UNKNOWN,
    source_family,
    source_types_for_family,
)
from backend.database.models import (
    DATA_SCOPE_GLOBAL,
    DATA_SCOPE_PRIVATE,
    PRESENTATION_DATA_ORIGIN,
    Incident,
    RiskHistory,
    SecurityEvent,
)
from backend.services import n8n_notifier

logger = get_logger(__name__)

INCIDENT_ID_MAX = 80
MIXED_LEGACY = "MIXED_LEGACY"
PRESENTATION_MARKER = "[presentation record]"
CLOUD_SIGN_IN_TYPES = {"CLOUD_LOGIN_SUCCESS", "CLOUD_LOGIN_FAILURE", "CLOUD_AUTHENTICATION"}
_ENVIRONMENT_LABEL = {LINUX: "Linux", CLOUD: "Cloud", HPC: "HPC", BEHAVIORAL: "Behavioral"}
_SOURCE_ENVIRONMENT = {"Linux": LINUX, "BGL": HPC, "Behavioral": BEHAVIORAL, "Unknown": UNKNOWN}


def _aware(value: datetime | None) -> datetime:
    if value is None:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _actor(event: SecurityEvent) -> str:
    return event.actor_id or event.username or event.source_ip or "unknown"


def _environment(event: SecurityEvent) -> str:
    return source_family(event.source_type)


def _source(event: SecurityEvent) -> str:
    family = _environment(event)
    provider = (event.provider or "").upper()
    if family == HPC or provider == "BGL":
        return "BGL"
    if provider == "HDFS":
        return "HDFS"
    if family == CLOUD:
        if provider == "AZURE":
            return "Azure"
        return "OpenStack" if provider == "OPENSTACK" else (event.provider or "Cloud")
    if family == BEHAVIORAL:
        return "Behavioral"
    if family == UNKNOWN:
        return "Unknown"
    return "Linux"


def _tenant(event: SecurityEvent) -> str:
    return getattr(event, "account_id", None) or getattr(event, "owner_id", None) or ""


def environment_from_source(source: str | None) -> str:
    """Environment of a stored incident, derived from its comma-joined source labels."""
    names = [name.strip() for name in (source or "").split(",") if name.strip()]
    environments = {_SOURCE_ENVIRONMENT.get(name, CLOUD) for name in names}
    if len(environments) == 1:
        return environments.pop()
    return MIXED_LEGACY if environments else UNKNOWN


def _incident_id(environment: str, actor: str, end: datetime) -> str:
    prefix = "" if environment == LINUX else f"{environment.lower()}:"
    stamp = int(end.timestamp())
    candidate = f"{prefix}{actor}-{stamp}"
    if len(candidate) <= INCIDENT_ID_MAX:
        return candidate
    digest = hashlib.sha256(actor.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}{digest}-{stamp}"


def _tenant_incident_id(incident_id: str, owner_id: str | None, account_id: str | None) -> str:
    """Stored id for a tenant whose correlation id is already held by another tenant.

    incidents.incident_id is globally unique in the schema, so the second tenant keeps the
    same correlation id plus a deterministic tenant suffix; reruns resolve to the same row.
    """
    tenant = f"account:{account_id}" if account_id else f"owner:{owner_id or ''}"
    suffix = hashlib.sha256(tenant.encode("utf-8")).hexdigest()[:12]
    candidate = f"{incident_id}~{suffix}"
    if len(candidate) <= INCIDENT_ID_MAX:
        return candidate
    digest = hashlib.sha256(f"{tenant}|{incident_id}".encode("utf-8")).hexdigest()[:24]
    return f"{incident_id[:40]}~{digest}"


def _cluster_tenant(rows: list[SecurityEvent]) -> tuple[str | None, str | None]:
    """(owner_id, account_id) shared by every event of a cluster; None where they differ or are unset."""
    owners = {event.owner_id for event in rows if getattr(event, "owner_id", None)}
    accounts = {event.account_id for event in rows if getattr(event, "account_id", None)}
    return (
        next(iter(owners)) if len(owners) == 1 else None,
        next(iter(accounts)) if len(accounts) == 1 else None,
    )


def _identity_entity_type(environment: str) -> str:
    return "identity" if environment == LINUX else f"{environment.lower()}_identity"


def account_entity_type(environment: str) -> str:
    """Linux keeps the existing "account" risk series; other environments never write into it."""
    return "account" if environment == LINUX else f"{environment.lower()}_account"


def _risk(event: SecurityEvent) -> int:
    return int(event.behavioral_risk_score if event.behavioral_risk_score is not None else event.risk_score or 0)


class CorrelationService:
    def __init__(self, session: Session, notifier: n8n_notifier.N8nNotifier | None = None) -> None:
        self._session = session
        self._notifier = notifier
        self._pending_notifications: list[tuple[Incident, str, str, dict[str, Any] | None]] = []
        self._claimed: set[Incident] = set()
        minutes = 15
        try:
            minutes = get_settings().CORRELATION_WINDOW_MINUTES
        except Exception:
            minutes = 15
        self._window = timedelta(minutes=minutes)

    def correlate_and_store(self, *, owner_id: str | None = None, account_id: str | None = None, limit: int = 1000) -> list[dict[str, Any]]:
        incidents: list[dict[str, Any]] = []
        for environment in SOURCE_FAMILIES:
            stmt = (
                select(SecurityEvent)
                .where(
                    SecurityEvent.data_scope == DATA_SCOPE_PRIVATE,
                    func.upper(SecurityEvent.source_type).in_(source_types_for_family(environment)),
                )
                .order_by(SecurityEvent.timestamp.desc())
                .limit(limit)
            )
            if account_id:
                stmt = stmt.where(SecurityEvent.account_id == account_id)
            elif owner_id:
                stmt = stmt.where(SecurityEvent.owner_id == owner_id)
            # The most recent `limit` events, correlated in occurrence order.
            incidents.extend(self._build(list(reversed(self._session.scalars(stmt).all()))))
        incidents.sort(key=lambda item: item["risk_score"], reverse=True)
        intelligence = self._global_pattern_index()
        self._pending_notifications = []
        self._claimed = set()
        stored = []
        for item in incidents:
            item = self._attach_intelligence(item, intelligence)
            tenant_owner, tenant_account = self._incident_tenant(item, owner_id=owner_id, account_id=account_id)
            row = self._upsert(item, owner_id=tenant_owner, account_id=tenant_account)
            if row is None:
                continue
            stored.append(row)
            self._history(item, owner_id=tenant_owner, account_id=tenant_account)
        if account_id:
            for environment in SOURCE_FAMILIES:
                top = next((row for row in stored if row.get("environment") == environment), None)
                if top is None:
                    continue
                self._session.add(
                    RiskHistory(
                        owner_id=owner_id,
                        account_id=account_id,
                        entity_type=account_entity_type(environment),
                        entity_key=f"account:{account_id}",
                        timestamp=datetime.now(timezone.utc),
                        risk_score=int(top.get("risk_score") or 0),
                        source="account_risk",
                        reason=top.get("explanation"),
                    )
                )
        self._session.commit()
        self._notify_qualifying()
        return stored

    def _notify_qualifying(self) -> None:
        """Hand newly stored or escalated HIGH/CRITICAL incidents to n8n; never raises."""
        pending, self._pending_notifications = self._pending_notifications, []
        if not pending:
            return
        try:
            items: list[tuple[dict[str, Any], str, list[str]]] = []
            for row, environment, event, security_demo in pending:
                recipients = n8n_notifier.resolve_owner_recipient_emails(
                    self._session,
                    owner_id=row.owner_id,
                    account_id=row.account_id,
                )
                if not recipients:
                    logger.info(
                        "n8n notification skipped for incident %s (%s)",
                        row.incident_id,
                        n8n_notifier.REASON_NO_VERIFIED_RECIPIENT,
                    )
                    continue
                body = {**self._to_dict(row), "environment": environment}
                if security_demo:
                    body["security_demo"] = security_demo
                items.append((body, event, recipients))
            if not items:
                return
            notifier = self._notifier or n8n_notifier.N8nNotifier.from_settings()
            notifier.notify_incidents(items)
        except Exception:
            logger.exception("n8n incident notification dispatch failed; incidents are stored")

    def list_incidents(self, *, owner_id: str | None = None, account_id: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
        stmt = select(Incident).order_by(desc(Incident.risk_score)).limit(limit)
        if account_id:
            stmt = stmt.where(Incident.account_id == account_id)
        elif owner_id:
            stmt = stmt.where(Incident.owner_id == owner_id)
        return [self._to_dict(row) for row in self._session.scalars(stmt).all()]

    def behavior_history(
        self,
        *,
        owner_id: str | None = None,
        account_id: str | None = None,
        actor: str | None = None,
        limit: int = 50,
        environment: str = LINUX,
    ) -> dict[str, Any]:
        stmt = (
            select(SecurityEvent)
            .where(
                SecurityEvent.data_scope == DATA_SCOPE_PRIVATE,
                func.upper(SecurityEvent.source_type).in_(source_types_for_family(environment)),
            )
            .order_by(SecurityEvent.timestamp.asc())
            .limit(2000)
        )
        if account_id:
            stmt = stmt.where(SecurityEvent.account_id == account_id)
        elif owner_id:
            stmt = stmt.where(SecurityEvent.owner_id == owner_id)
        events = list(self._session.scalars(stmt).all())
        if actor:
            events = [event for event in events if _actor(event) == actor]
        buckets: dict[str, dict[str, Any]] = {}
        for event in events:
            key = _aware(event.timestamp).strftime("%Y-%m-%d %H:00")
            bucket = buckets.setdefault(key, {
                "hour": key,
                "activity": 0,
                "failed_logins": 0,
                "privileged": 0,
                "max_risk": 0,
            })
            bucket["activity"] += 1
            if event.event_type == "Failed Login":
                bucket["failed_logins"] += 1
            if event.event_type in {"Sudo Command", "User Creation"} or (event.username or "").lower() == "root":
                bucket["privileged"] += 1
            bucket["max_risk"] = max(bucket["max_risk"], _risk(event))
        series = list(buckets.values())[-limit:]
        return {
            "actor": actor,
            "environment": environment,
            "points": series,
            "totals": {
                "activity": sum(item["activity"] for item in series),
                "failed_logins": sum(item["failed_logins"] for item in series),
                "privileged": sum(item["privileged"] for item in series),
            },
        }

    def _build(self, events: list[SecurityEvent]) -> list[dict[str, Any]]:
        """Correlate per (tenant, environment, actor). Each environment keeps its own top-12."""
        groups: dict[tuple[str, str, str], list[SecurityEvent]] = {}
        for event in events:
            actor = _actor(event)
            environment = _environment(event)
            if actor == "unknown" or environment == UNKNOWN:
                continue
            groups.setdefault((_tenant(event), environment, actor), []).append(event)
        by_environment: dict[str, list[dict[str, Any]]] = {}
        for (_tenant_key, environment, actor), rows in groups.items():
            sorted_rows = sorted(rows, key=lambda item: _aware(item.timestamp))
            clusters: list[list[SecurityEvent]] = []
            current: list[SecurityEvent] = []
            for event in sorted_rows:
                if not current:
                    current = [event]
                    continue
                gap = _aware(event.timestamp) - _aware(current[-1].timestamp)
                if gap <= self._window:
                    current.append(event)
                else:
                    clusters.append(current)
                    current = [event]
            if current:
                clusters.append(current)
            for cluster in clusters:
                incident = self._incident_from_cluster(actor, cluster, environment)
                if incident:
                    incident["owner_id"], incident["account_id"] = _cluster_tenant(cluster)
                    by_environment.setdefault(environment, []).append(incident)
        incidents: list[dict[str, Any]] = []
        for rows in by_environment.values():
            rows.sort(key=lambda item: item["risk_score"], reverse=True)
            incidents.extend(rows[:12])
        incidents.sort(key=lambda item: item["risk_score"], reverse=True)
        return incidents

    @staticmethod
    def _evidence(environment: str, sorted_rows: list[SecurityEvent], high_risk: list[SecurityEvent]) -> list[str]:
        if environment == LINUX:
            flags = [
                any(re.search(r"login|ssh|auth", f"{e.event_type} {e.message}", re.I) for e in sorted_rows) and "Linux login/authentication activity",
                any(re.search(r"sudo|privilege|root|escalat|admin", f"{e.event_type} {e.message}", re.I) for e in sorted_rows) and "Privilege-related Linux activity",
            ]
        elif environment == CLOUD:
            types = {(e.event_type or "").upper() for e in sorted_rows}
            flags = [
                bool(types & CLOUD_SIGN_IN_TYPES) and "Cloud sign-in/authentication activity",
                "CLOUD_PRIVILEGE_CHANGE" in types and "Cloud privilege/role change",
                "CLOUD_RESOURCE_OPERATION" in types and "Cloud resource operation",
            ]
        elif environment == HPC:
            flags = ["HPC/BGL operational log activity"]
        elif environment == BEHAVIORAL:
            flags = [any(_risk(e) >= 50 for e in sorted_rows) and "Behavioral anomaly or over-efficiency"]
        else:
            flags = []
        flags.append(high_risk and f"{len(high_risk)} high-risk record(s)")
        return [item for item in flags if item]

    def _incident_from_cluster(self, actor: str, sorted_rows: list[SecurityEvent], environment: str | None = None) -> dict[str, Any] | None:
            environment = environment or _environment(sorted_rows[0])
            if any(_environment(e) != environment for e in sorted_rows):
                raise ValueError("Correlation cluster spans more than one environment.")
            high_risk = [e for e in sorted_rows if _risk(e) >= 70 or (e.severity or "").lower() in {"critical", "high", "error"}]
            evidence = self._evidence(environment, sorted_rows, high_risk)
            if len(evidence) < 2:
                return None
            confidence = min(100, round((len(evidence) / 5) * 80 + min(len(high_risk), 4) * 5))
            max_risk = max((_risk(e) for e in sorted_rows), default=0)
            start = _aware(sorted_rows[0].timestamp)
            end = _aware(sorted_rows[-1].timestamp)
            chain = [
                {
                    "event_id": event.event_id,
                    "timestamp": _aware(event.timestamp).isoformat(),
                    "event_type": event.event_type,
                    "source": _source(event),
                    "risk_score": _risk(event),
                }
                for event in sorted_rows[:20]
            ]
            recommendation = "Investigate related host activity and compare with global security-intelligence patterns." if max_risk < 85 else "Escalate immediately and review identity, session, and correlated global patterns."
            title = f"Correlated activity for {actor}" if environment == LINUX else f"Correlated {_ENVIRONMENT_LABEL[environment]} activity for {actor}"
            presentation = sum(1 for e in sorted_rows if e.data_origin == PRESENTATION_DATA_ORIGIN)
            if presentation:
                title = f"{title} {PRESENTATION_MARKER}"
                evidence = [
                    *evidence,
                    f"{presentation} of {len(sorted_rows)} record(s) generated by DefenSync for a presentation, not collected from a live source",
                ]
            security_demo = None
            if presentation and environment == CLOUD:
                from backend.services.cloud.presentation_telemetry import security_demo_from_event

                for event in sorted_rows:
                    security_demo = security_demo_from_event(event)
                    if security_demo:
                        break
            item = {
                "incident_id": _incident_id(environment, actor, end),
                "title": title,
                "environment": environment,
                "actor": actor,
                "confidence": confidence,
                "risk_score": min(100, round((confidence * 0.45) + (max_risk * 0.55))),
                "severity": "critical" if max_risk >= 85 else "high" if max_risk >= 70 else "medium",
                "evidence": evidence,
                "event_ids": [event.event_id for event in sorted_rows],
                "start_time": start,
                "end_time": end,
                "explanation": "; ".join(evidence),
                "recommendation": recommendation,
                "source": ",".join(sorted({_source(e) for e in sorted_rows})),
                "timeline": chain,
                "presentation_records": presentation,
            }
            if security_demo:
                item["security_demo"] = security_demo
                item["recommendation"] = security_demo.get("recommended_action") or recommendation
            return item

    def _global_pattern_index(self) -> list[dict[str, Any]]:
        rows = list(
            self._session.execute(
                select(
                    SecurityEvent.dataset_name,
                    SecurityEvent.provider,
                    SecurityEvent.source_type,
                    SecurityEvent.event_type,
                    func.count(SecurityEvent.id),
                )
                .where(
                    SecurityEvent.data_scope == DATA_SCOPE_GLOBAL,
                    SecurityEvent.original_label.in_(("ANOMALOUS", "ABNORMAL", "ATTACK", "FAILURE")),
                )
                .group_by(
                    SecurityEvent.dataset_name,
                    SecurityEvent.provider,
                    SecurityEvent.source_type,
                    SecurityEvent.event_type,
                )
                .order_by(func.count(SecurityEvent.id).desc())
                .limit(40)
            ).all()
        )
        index = []
        for dataset_name, provider, source_type, event_type, count in rows:
            kind = "HPC" if (source_type or "").upper() == "HPC" or (provider or "").upper() == "BGL" else "CLOUD"
            index.append({
                "dataset_name": dataset_name,
                "provider": provider,
                "source_type": source_type,
                "type": kind,
                "event_type": event_type,
                "anomalous_count": int(count),
            })
        return index

    def _attach_intelligence(self, item: dict[str, Any], intelligence: list[dict[str, Any]]) -> dict[str, Any]:
        # The corpus references below are not similarity-matched and their wording claims
        # Linux session behavior, so they are only attached to genuine Linux incidents.
        if item.get("environment", LINUX) != LINUX or item.get("presentation_records"):
            item["intelligence_refs"] = []
            item["event_ids"] = item.get("event_ids") or []
            return item
        refs = []
        reasons = []
        for pattern in intelligence[:3]:
            refs.append({
                "dataset_name": pattern["dataset_name"],
                "event_type": pattern["event_type"],
                "type": pattern["type"],
                "provider": pattern["provider"],
            })
            corpus = pattern["dataset_name"] or pattern["provider"] or "global corpus"
            reasons.append(
                f"Linux session behavior resembles an anomaly pattern observed in the {corpus} security corpus "
                f"(reference event_type={pattern['event_type']})."
            )
        if not refs:
            reasons.append("No matching global intelligence pattern was attached; risk is based on private telemetry.")
        item["intelligence_refs"] = refs
        item["explanation"] = " ".join(reasons)
        item["event_ids"] = item.get("event_ids") or []
        return item

    @staticmethod
    def _incident_tenant(item: dict[str, Any], *, owner_id: str | None, account_id: str | None) -> tuple[str | None, str | None]:
        """A scoped caller keeps its own scope; an unscoped (ADMIN) run keeps the events' tenant."""
        if owner_id or account_id:
            return owner_id, account_id
        return item.get("owner_id"), item.get("account_id")

    def _find_tenant_incident(self, incident_id: str, owner_id: str | None, account_id: str | None) -> tuple[Incident | None, str | None]:
        """The tenant's own row for this correlation id, else the free id to insert it under (None if none is free)."""
        qualified = _tenant_incident_id(incident_id, owner_id, account_id)
        rows = list(self._session.scalars(select(Incident).where(Incident.incident_id.in_((incident_id, qualified)))))
        tenant_rows = [row for row in rows if self._same_tenant(row, owner_id, account_id)]
        if tenant_rows:
            return next((row for row in tenant_rows if row.incident_id == incident_id), tenant_rows[0]), None
        taken = {row.incident_id for row in rows}
        return None, next((candidate for candidate in (incident_id, qualified) if candidate not in taken), None)

    @staticmethod
    def _same_tenant(row: Incident, owner_id: str | None, account_id: str | None) -> bool:
        if account_id:
            return row.account_id == account_id
        if row.account_id:
            return False
        return (row.owner_id or None) == (owner_id or None)

    def _find_continued_incident(self, item: dict[str, Any], owner_id: str | None, account_id: str | None) -> Incident | None:
        """The tenant's stored incident for the same actor and environment that shares events with this cluster.

        The correlation id ends with the cluster's last event time, so a cluster that gained events
        has a new id while still being the same incident.
        """
        event_ids = set(item.get("event_ids") or [])
        if not event_ids:
            return None
        rows = self._session.scalars(
            select(Incident).where(Incident.actor == item["actor"]).order_by(desc(Incident.updated_at))
        )
        for row in rows:
            if row in self._claimed or not self._same_tenant(row, owner_id, account_id):
                continue
            if environment_from_source(row.source) != item.get("environment"):
                continue
            if event_ids & set(json.loads(row.event_ids or "[]")):
                return row
        return None

    def _upsert(self, item: dict[str, Any], *, owner_id: str | None, account_id: str | None = None) -> dict[str, Any] | None:
        existing, stored_id = self._find_tenant_incident(item["incident_id"], owner_id, account_id)
        if existing is None:
            existing = self._find_continued_incident(item, owner_id, account_id)
        if existing is None and stored_id is None:
            logger.warning("Incident id %s is held by other tenants; correlation result not stored.", item["incident_id"])
            return None
        event = n8n_notifier.notification_event(
            existing.severity if existing else None, item["severity"], is_new=existing is None,
        )
        payload = {
            "title": item["title"],
            "severity": item["severity"],
            "risk_score": item["risk_score"],
            "confidence": item["confidence"],
            "actor": item["actor"],
            "source": item["source"],
            "start_time": item["start_time"],
            "end_time": item["end_time"],
            "event_ids": json.dumps(item["event_ids"]),
            "evidence": json.dumps(item["evidence"]),
            "explanation": item["explanation"],
            "recommendation": item["recommendation"],
            "intelligence_refs": json.dumps(item.get("intelligence_refs") or []),
            "status": "open",
        }
        if existing:
            for key, value in payload.items():
                setattr(existing, key, value)
            existing.updated_at = datetime.now(timezone.utc)
            row = existing
        else:
            row = Incident(incident_id=stored_id, owner_id=owner_id, account_id=account_id, **payload)
            self._session.add(row)
        self._claimed.add(row)
        if event:
            self._pending_notifications.append(
                (
                    row,
                    item.get("environment") or environment_from_source(row.source),
                    event,
                    item.get("security_demo"),
                )
            )
        data = self._to_dict(row)
        data["environment"] = item.get("environment") or data["environment"]
        data["timeline"] = item.get("timeline") or []
        if item.get("security_demo"):
            data["security_demo"] = item["security_demo"]
        return data

    def _history(self, item: dict[str, Any], *, owner_id: str | None, account_id: str | None = None) -> None:
        self._session.add(
            RiskHistory(
                owner_id=owner_id,
                account_id=account_id,
                entity_type=_identity_entity_type(item.get("environment") or LINUX),
                entity_key=item["actor"],
                timestamp=item["end_time"],
                risk_score=item["risk_score"],
                source="correlation",
                reason=item["explanation"],
            )
        )

    @staticmethod
    def _to_dict(row: Incident) -> dict[str, Any]:
        return {
            "id": row.id,
            "incident_id": row.incident_id,
            "title": row.title,
            "severity": row.severity,
            "risk_score": row.risk_score,
            "confidence": row.confidence,
            "actor": row.actor,
            "source": row.source,
            "environment": environment_from_source(row.source),
            "start_time": row.start_time.isoformat() if row.start_time else None,
            "end_time": row.end_time.isoformat() if row.end_time else None,
            "event_ids": json.loads(row.event_ids or "[]"),
            "evidence": json.loads(row.evidence or "[]"),
            "explanation": row.explanation,
            "recommendation": row.recommendation,
            "intelligence_refs": json.loads(getattr(row, "intelligence_refs", None) or "[]"),
            "status": row.status,
        }

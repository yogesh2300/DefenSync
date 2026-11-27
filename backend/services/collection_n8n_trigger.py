"""Alternate-success n8n trigger for Linux and Cloud log collections.

After a collection has completed successfully and its run row is committed, this module:

1. Advances a durable per-tenant, per-source-type success counter (LINUX and CLOUD never share).
2. On even sequence numbers (2, 4, 6, …) inserts one outbox row with a stable event_id.
3. Posts once to the existing n8n webhook; retries update the same outbox row.

Odd successes are SKIPPED (no outbox row). Failed / partial collections never call this.
A webhook failure never changes the collection outcome. Delivery is at-least-once for the
logical event_id: n8n should treat duplicate POSTs with the same event_id as the same event.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.core.environments import CLOUD, LINUX
from backend.core.logging import get_logger
from backend.database.models import CollectionN8nDispatch, CollectionN8nSequence
from backend.services import n8n_notifier
from backend.services.presentation_trigger import scope_key as tenant_scope_key

logger = get_logger(__name__)

SOURCE_TYPES = frozenset({LINUX, CLOUD})
TRIGGER_EVERY = 2

STATUS_SKIPPED = "SKIPPED"
STATUS_PENDING = "PENDING"
STATUS_SENT = "SENT"
STATUS_FAILED = "FAILED"
STATUS_NOT_CONFIGURED = "NOT_CONFIGURED"

OUTCOME_LINUX_SUCCESS = "completed"
OUTCOME_CLOUD_SUCCESS = "SUCCESS"

_EVENT_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "defensync:collection-n8n-v1")


def event_id_for(source_type: str, collection_run_id: str) -> str:
    """Stable id for one qualifying collection; identical across retries and duplicate callbacks."""
    return str(uuid.uuid5(_EVENT_NAMESPACE, f"{source_type}|{collection_run_id}"))


def qualifies_for_trigger(sequence_number: int, every: int = TRIGGER_EVERY) -> bool:
    step = max(1, int(every or TRIGGER_EVERY))
    return sequence_number > 0 and sequence_number % step == 0


@dataclass(frozen=True)
class RecordResult:
    counted: bool
    sequence_number: int
    dispatch_status: str
    event_id: str | None = None
    reason: str | None = None
    trigger_every: int = TRIGGER_EVERY
    policy: str | None = None

    def as_dict(self) -> dict[str, Any]:
        view: dict[str, Any] = {
            "counted": self.counted,
            "sequence_number": self.sequence_number,
            "dispatch_status": self.dispatch_status,
            "trigger_every": int(self.trigger_every or TRIGGER_EVERY),
            # Webhook HTTP acceptance only — DefenSync cannot confirm mailbox delivery.
            "delivery_layer": "webhook",
            "email_delivery": "unknown",
        }
        if self.event_id:
            view["event_id"] = self.event_id
        if self.reason:
            view["reason"] = self.reason
        if self.policy:
            view["policy"] = self.policy
        return view


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _locked_sequence(
    session: Session,
    *,
    scope: str,
    source_type: str,
    owner_id: str | None,
    account_id: str | None,
    now: datetime,
) -> CollectionN8nSequence:
    stmt = (
        select(CollectionN8nSequence)
        .where(
            CollectionN8nSequence.scope_key == scope,
            CollectionN8nSequence.source_type == source_type,
        )
        .with_for_update()
    )
    state = session.scalar(stmt)
    if state is not None:
        return state
    state = CollectionN8nSequence(
        scope_key=scope,
        source_type=source_type,
        owner_id=owner_id,
        account_id=account_id,
        success_count=0,
        created_at=now,
        updated_at=now,
    )
    session.add(state)
    session.flush()
    # Re-select with lock so concurrent creators serialize on the unique row.
    locked = session.scalar(stmt)
    return locked or state


def _existing_dispatch(session: Session, *, source_type: str, collection_run_id: str) -> CollectionN8nDispatch | None:
    return session.scalar(
        select(CollectionN8nDispatch).where(
            CollectionN8nDispatch.source_type == source_type,
            CollectionN8nDispatch.collection_run_id == collection_run_id,
        )
    )


def _dispatch_view(row: CollectionN8nDispatch) -> dict[str, Any]:
    return {
        "event_id": row.event_id,
        "source_type": row.source_type,
        "collection_id": row.collection_run_id,
        "sequence_number": int(row.sequence_number),
        "status": row.status,
        "attempt_count": int(row.attempt_count or 0),
        "sent_at": row.sent_at.isoformat() if row.sent_at else None,
        "last_attempt_at": row.last_attempt_at.isoformat() if row.last_attempt_at else None,
        "last_http_status": row.last_http_status,
        "last_error": row.last_error,
        "outcome": row.outcome,
        "collection_completed_at": row.collection_completed_at.isoformat() if row.collection_completed_at else None,
    }


def status_for_scope(
    session: Session,
    *,
    owner_id: str | None,
    account_id: str | None,
) -> dict[str, Any]:
    """Read-only progress and recent dispatch outcomes for both source families."""
    scope = tenant_scope_key(owner_id, account_id)
    environments: dict[str, Any] = {}
    for source_type in (LINUX, CLOUD):
        seq = session.scalar(
            select(CollectionN8nSequence).where(
                CollectionN8nSequence.scope_key == scope,
                CollectionN8nSequence.source_type == source_type,
            )
        )
        latest = session.scalar(
            select(CollectionN8nDispatch)
            .where(
                CollectionN8nDispatch.scope_key == scope,
                CollectionN8nDispatch.source_type == source_type,
            )
            .order_by(CollectionN8nDispatch.created_at.desc(), CollectionN8nDispatch.id.desc())
            .limit(1)
        )
        count = int(seq.success_count) if seq else 0
        environments[source_type] = {
            "source_type": source_type,
            "success_count": count,
            "next_trigger_at": count + (TRIGGER_EVERY - (count % TRIGGER_EVERY)) if count % TRIGGER_EVERY else count + TRIGGER_EVERY,
            "collections_until_next_trigger": (TRIGGER_EVERY - (count % TRIGGER_EVERY)) % TRIGGER_EVERY or TRIGGER_EVERY,
            "last_dispatch": _dispatch_view(latest) if latest else None,
        }
    return {
        "trigger_every": TRIGGER_EVERY,
        "rule": "Trigger n8n on every alternate successful collection (2, 4, 6, …) per source type.",
        "environments": environments,
        "n8n": n8n_notifier.N8nNotifier.from_settings().status(include_last_delivery=False),
    }


def dispatch_for_run(session: Session, *, source_type: str, collection_run_id: str) -> dict[str, Any] | None:
    row = _existing_dispatch(session, source_type=source_type, collection_run_id=collection_run_id)
    return _dispatch_view(row) if row else None


def _ensure_outbox(
    session: Session,
    *,
    source_type: str,
    collection_run_id: str,
    scope: str,
    owner_id: str | None,
    account_id: str | None,
    sequence_number: int,
    outcome: str,
    completed_at: datetime | None,
    now: datetime,
) -> CollectionN8nDispatch:
    existing = _existing_dispatch(session, source_type=source_type, collection_run_id=collection_run_id)
    if existing is not None:
        return existing
    row = CollectionN8nDispatch(
        event_id=event_id_for(source_type, collection_run_id),
        source_type=source_type,
        collection_run_id=collection_run_id,
        scope_key=scope,
        owner_id=owner_id,
        account_id=account_id,
        sequence_number=sequence_number,
        outcome=outcome,
        collection_completed_at=completed_at,
        status=STATUS_PENDING,
        created_at=now,
        updated_at=now,
    )
    try:
        with session.begin_nested():
            session.add(row)
            session.flush()
    except IntegrityError:
        found = _existing_dispatch(session, source_type=source_type, collection_run_id=collection_run_id)
        if found is None:
            raise
        return found
    return row


def attempt_dispatch(
    session: Session,
    row: CollectionN8nDispatch,
    *,
    notifier: n8n_notifier.N8nNotifier | None = None,
    now: datetime | None = None,
    security_demo: dict[str, Any] | None = None,
) -> CollectionN8nDispatch:
    """Send or retry one outbox row. Never creates a second logical event."""
    when = now or _now()
    if row.status == STATUS_SENT:
        return row
    notifier = notifier or n8n_notifier.N8nNotifier.from_settings(background=False)
    recipients = n8n_notifier.resolve_collection_recipient_emails(
        session,
        owner_id=row.owner_id,
        account_id=row.account_id,
    )
    payload = n8n_notifier.build_collection_payload(
        event_id=row.event_id,
        source_type=row.source_type,
        collection_id=row.collection_run_id,
        sequence_number=int(row.sequence_number),
        completed_at=row.collection_completed_at,
        outcome=row.outcome,
        account_id=row.account_id,
        security_demo=security_demo,
        recipient_emails=recipients,
    )
    result = notifier.send_collection(payload)
    row.attempt_count = int(row.attempt_count or 0) + 1
    row.last_attempt_at = when
    row.updated_at = when
    row.last_http_status = result.http_status
    if result.status == n8n_notifier.STATUS_SENT:
        row.status = STATUS_SENT
        row.sent_at = when
        row.last_error = None
        logger.info(
            "collection n8n sent: source=%s collection=%s sequence=%s event_id=%s http=%s recipients=%d",
            row.source_type, row.collection_run_id, row.sequence_number, row.event_id, result.http_status,
            len(recipients),
        )
    elif result.status == n8n_notifier.STATUS_NOT_CONFIGURED:
        row.status = STATUS_NOT_CONFIGURED
        row.last_error = (result.reason or "not_configured")[:240]
        logger.info(
            "collection n8n not configured: source=%s collection=%s sequence=%s event_id=%s",
            row.source_type, row.collection_run_id, row.sequence_number, row.event_id,
        )
    elif result.status == n8n_notifier.STATUS_SKIPPED:
        # Missing recipients — do not POST an empty To field to n8n.
        row.status = STATUS_FAILED
        row.last_error = (result.reason or n8n_notifier.REASON_NO_VERIFIED_RECIPIENT)[:240]
        logger.warning(
            "collection n8n skipped (no recipients): source=%s collection=%s sequence=%s event_id=%s",
            row.source_type, row.collection_run_id, row.sequence_number, row.event_id,
        )
    else:
        row.status = STATUS_FAILED
        row.last_error = (result.reason or "failed")[:240]
        logger.warning(
            "collection n8n failed: source=%s collection=%s sequence=%s event_id=%s reason=%s",
            row.source_type, row.collection_run_id, row.sequence_number, row.event_id, row.last_error,
        )
    session.add(row)
    session.commit()
    return row


def record_successful_collection(
    session: Session,
    *,
    source_type: str,
    collection_run_id: str,
    owner_id: str | None,
    account_id: str | None,
    outcome: str,
    completed_at: datetime | None = None,
    notifier: n8n_notifier.N8nNotifier | None = None,
    dispatch: bool = True,
    now: datetime | None = None,
    security_demo: dict[str, Any] | None = None,
    trigger_every: int | None = None,
    policy: str | None = None,
) -> dict[str, Any]:
    """Count one successful collection and dispatch n8n when the sequence qualifies.

    Default policy: every 2nd success (TRIGGER_EVERY). Cloud DEMO mode may pass
    `trigger_every=1` for one notification per successful collection.

    Never raises into the collection path. Failed collections must not call this.
    Optional `security_demo` is attached only to the webhook body for this attempt.
    """
    every = max(1, int(trigger_every if trigger_every is not None else TRIGGER_EVERY))
    try:
        return _record(
            session,
            source_type=source_type,
            collection_run_id=collection_run_id,
            owner_id=owner_id,
            account_id=account_id,
            outcome=outcome,
            completed_at=completed_at,
            notifier=notifier,
            dispatch=dispatch,
            now=now or _now(),
            security_demo=security_demo,
            trigger_every=every,
            policy=policy or ("every_success" if every == 1 else "alternate_success"),
        ).as_dict()
    except Exception as exc:  # noqa: BLE001 - must never fail the real collection
        try:
            session.rollback()
        except Exception:  # noqa: BLE001
            pass
        logger.error(
            "collection n8n trigger failed for %s run %s: %s",
            source_type, collection_run_id, type(exc).__name__,
        )
        return {
            "counted": False,
            "sequence_number": 0,
            "dispatch_status": STATUS_FAILED,
            "reason": f"internal_error:{type(exc).__name__}",
            "trigger_every": every,
            "delivery_layer": "webhook",
            "email_delivery": "unknown",
        }


def _record(
    session: Session,
    *,
    source_type: str,
    collection_run_id: str,
    owner_id: str | None,
    account_id: str | None,
    outcome: str,
    completed_at: datetime | None,
    notifier: n8n_notifier.N8nNotifier | None,
    dispatch: bool,
    now: datetime,
    security_demo: dict[str, Any] | None = None,
    trigger_every: int = TRIGGER_EVERY,
    policy: str | None = None,
) -> RecordResult:
    source = (source_type or "").strip().upper()
    if source not in SOURCE_TYPES:
        raise ValueError(f"unsupported source_type: {source_type!r}")
    run_id = (collection_run_id or "").strip()
    if not run_id:
        raise ValueError("collection_run_id is required")

    scope = tenant_scope_key(owner_id, account_id)
    existing = _existing_dispatch(session, source_type=source, collection_run_id=run_id)
    state = _locked_sequence(
        session, scope=scope, source_type=source, owner_id=owner_id, account_id=account_id, now=now,
    )

    every = max(1, int(trigger_every or TRIGGER_EVERY))
    policy_label = policy or ("every_success" if every == 1 else "alternate_success")

    if state.last_counted_run_id == run_id:
        sequence_number = int(state.success_count or 0)
        if existing is None:
            return RecordResult(
                False, sequence_number, STATUS_SKIPPED, reason="odd_sequence_already_counted",
                trigger_every=every, policy=policy_label,
            )
        if dispatch and existing.status in (STATUS_PENDING, STATUS_FAILED, STATUS_NOT_CONFIGURED):
            attempt_dispatch(session, existing, notifier=notifier, now=now, security_demo=security_demo)
            session.refresh(existing)
        return RecordResult(
            False, sequence_number, existing.status, event_id=existing.event_id, reason="duplicate_run",
            trigger_every=every, policy=policy_label,
        )

    if existing is not None:
        # Outbox exists (unique) but sequence did not count this run — recover without double-count.
        sequence_number = int(existing.sequence_number)
        if dispatch and existing.status in (STATUS_PENDING, STATUS_FAILED, STATUS_NOT_CONFIGURED):
            attempt_dispatch(session, existing, notifier=notifier, now=now, security_demo=security_demo)
            session.refresh(existing)
        return RecordResult(
            False, sequence_number, existing.status, event_id=existing.event_id, reason="outbox_exists",
            trigger_every=every, policy=policy_label,
        )

    state.success_count = int(state.success_count or 0) + 1
    state.last_counted_run_id = run_id
    state.updated_at = now
    sequence_number = int(state.success_count)

    if not qualifies_for_trigger(sequence_number, every):
        session.commit()
        logger.info(
            "collection n8n skipped (policy=%s every=%s): source=%s collection=%s sequence=%s",
            policy_label, every, source, run_id, sequence_number,
        )
        return RecordResult(
            True, sequence_number, STATUS_SKIPPED, reason="sequence_not_eligible",
            trigger_every=every, policy=policy_label,
        )

    row = _ensure_outbox(
        session,
        source_type=source,
        collection_run_id=run_id,
        scope=scope,
        owner_id=owner_id,
        account_id=account_id,
        sequence_number=sequence_number,
        outcome=outcome,
        completed_at=completed_at,
        now=now,
    )
    session.commit()
    logger.info(
        "collection n8n outbox queued: source=%s collection=%s sequence=%s event_id=%s policy=%s",
        source, run_id, sequence_number, row.event_id, policy_label,
    )
    if dispatch:
        attempt_dispatch(session, row, notifier=notifier, now=now, security_demo=security_demo)
        session.refresh(row)
    return RecordResult(
        True, sequence_number, row.status, event_id=row.event_id,
        trigger_every=every, policy=policy_label,
    )


def record_linux_success(
    session: Session,
    *,
    collection_run_id: str,
    owner_id: str | None,
    account_id: str | None,
    completed_at: datetime | None = None,
    notifier: n8n_notifier.N8nNotifier | None = None,
) -> dict[str, Any]:
    return record_successful_collection(
        session,
        source_type=LINUX,
        collection_run_id=collection_run_id,
        owner_id=owner_id,
        account_id=account_id,
        outcome=OUTCOME_LINUX_SUCCESS,
        completed_at=completed_at,
        notifier=notifier,
    )


def record_cloud_success(
    session: Session,
    *,
    collection_run_id: str,
    owner_id: str | None,
    account_id: str | None,
    completed_at: datetime | None = None,
    notifier: n8n_notifier.N8nNotifier | None = None,
    security_demo: dict[str, Any] | None = None,
    trigger_every: int | None = None,
    policy: str | None = None,
) -> dict[str, Any]:
    return record_successful_collection(
        session,
        source_type=CLOUD,
        collection_run_id=collection_run_id,
        owner_id=owner_id,
        account_id=account_id,
        outcome=OUTCOME_CLOUD_SUCCESS,
        completed_at=completed_at,
        notifier=notifier,
        security_demo=security_demo,
        trigger_every=trigger_every,
        policy=policy,
    )

"""Presentation demo trigger: one marked alert after every 1-3 successful manual collections.

State is one PresentationTriggerState row per tenant scope (account, else owner) and environment,
so a backend restart keeps the selected interval and the progress towards it. A collection run is
counted at most once. Nothing here commits: the caller stores the trigger records and this state
in one transaction, so a failure leaves neither behind.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.models import PresentationTriggerState

MIN_INTERVAL = 1
MAX_INTERVAL = 3

_RANDOM = random.SystemRandom()


def choose_interval() -> int:
    return _RANDOM.randint(MIN_INTERVAL, MAX_INTERVAL)


def scope_key(owner_id: str | None, account_id: str | None) -> str:
    return f"account:{account_id}" if account_id else f"owner:{owner_id}"


@dataclass(frozen=True)
class Advance:
    counted: bool
    triggered: bool
    state: PresentationTriggerState


def _state(session: Session, *, owner_id: str | None, account_id: str | None, environment: str) -> PresentationTriggerState | None:
    return session.scalar(
        select(PresentationTriggerState).where(
            PresentationTriggerState.scope_key == scope_key(owner_id, account_id),
            PresentationTriggerState.environment == environment,
        )
    )


def advance(
    session: Session,
    *,
    owner_id: str | None,
    account_id: str | None,
    environment: str,
    run_id: str,
    now: datetime,
) -> Advance:
    """Count one successful manual collection run; triggered=True when it completes the interval."""
    state = _state(session, owner_id=owner_id, account_id=account_id, environment=environment)
    if state is None:
        state = PresentationTriggerState(
            scope_key=scope_key(owner_id, account_id),
            environment=environment,
            owner_id=owner_id,
            account_id=account_id,
            trigger_interval=choose_interval(),
            progress=0,
            triggers_generated=0,
            created_at=now,
        )
        session.add(state)
    elif run_id in (state.last_counted_run_id, state.last_triggered_run_id):
        return Advance(counted=False, triggered=False, state=state)
    state.last_counted_run_id = run_id
    state.progress = int(state.progress or 0) + 1
    state.updated_at = now
    if state.progress < state.trigger_interval:
        return Advance(counted=True, triggered=False, state=state)
    state.progress = 0
    state.trigger_interval = choose_interval()
    state.last_triggered_run_id = run_id
    state.last_triggered_at = now
    state.triggers_generated = int(state.triggers_generated or 0) + 1
    return Advance(counted=True, triggered=True, state=state)


def state_view(state: PresentationTriggerState | None, environment: str) -> dict[str, Any]:
    """Read-only progress for the demo account; no identifiers or secrets."""
    if state is None:
        return {"environment": environment, "started": False}
    remaining = max(0, int(state.trigger_interval) - int(state.progress or 0))
    return {
        "environment": environment,
        "started": True,
        "trigger_interval": int(state.trigger_interval),
        "progress": int(state.progress or 0),
        "collections_until_next_trigger": remaining,
        "triggers_generated": int(state.triggers_generated or 0),
        "last_triggered_at": state.last_triggered_at.isoformat() if state.last_triggered_at else None,
    }


def status(session: Session, *, owner_id: str | None, account_id: str | None, environment: str) -> dict[str, Any]:
    return state_view(_state(session, owner_id=owner_id, account_id=account_id, environment=environment), environment)

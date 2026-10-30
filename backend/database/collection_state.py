"""Per-server incremental collection state (journal cursor)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.collector.journal import JournalBatch, JournalPosition
from backend.core.logging import get_logger
from backend.database.models import LinuxCollectionState

logger = get_logger(__name__)


def get_state(session: Session, server_id: str) -> LinuxCollectionState | None:
    return session.execute(
        select(LinuxCollectionState).where(LinuxCollectionState.server_id == server_id)
    ).scalar_one_or_none()


def load_journal_position(session: Session, server_id: str) -> JournalPosition | None:
    """Stored position, an empty position on first run, or None when state storage is unavailable."""
    try:
        state = get_state(session, server_id)
    except SQLAlchemyError:
        session.rollback()
        logger.warning("Collection state unavailable server_id=%s; using tail collection", server_id)
        return None
    if state is None:
        return JournalPosition()
    return JournalPosition(state.journal_cursor, state.journal_boot_id, state.journal_realtime_usec)


def save_journal_state(
    session: Session,
    server_id: str,
    batch: JournalBatch,
    *,
    advance_cursor: bool,
) -> dict[str, Any]:
    """Record what this run saw; move the cursor only when its events were stored."""
    now = datetime.now(timezone.utc)
    state = get_state(session, server_id)
    previous_boot = state.journal_current_boot_id if state else None
    reboot_detected = bool(previous_boot and batch.current_boot_id and previous_boot != batch.current_boot_id)
    if state is None:
        state = LinuxCollectionState(server_id=server_id, created_at=now)
        session.add(state)
    advanced = advance_cursor and batch.last_position is not None
    if advanced:
        state.journal_cursor = batch.last_position.cursor
        state.journal_boot_id = batch.last_position.boot_id
        state.journal_realtime_usec = batch.last_position.realtime_usec
    state.journal_current_boot_id = batch.current_boot_id or state.journal_current_boot_id
    state.journal_persistent = batch.persistent
    state.journal_storage = batch.storage
    state.journal_boots_available = batch.boots_available
    state.last_mode = batch.mode
    state.last_entries_read = batch.entries_read
    state.backlog_pending = bool(advanced and batch.truncated)
    if reboot_detected:
        state.last_reboot_detected_at = now
    state.updated_at = now
    session.commit()
    return {
        "mode": batch.mode,
        "entries_read": batch.entries_read,
        "backlog_pending": state.backlog_pending,
        "persistent": batch.persistent,
        "storage": batch.storage,
        "boots_available": batch.boots_available,
        "reboot_detected": reboot_detected,
        # Entries written before the reboot and after the last collection are gone with a volatile journal.
        "gap_possible": reboot_detected and batch.persistent is not True,
        "cursor_advanced": advanced,
    }

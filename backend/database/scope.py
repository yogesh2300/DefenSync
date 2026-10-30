"""Account and data-scope visibility helpers. owner_id remains collector identity, not the sole ACL."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import ColumnElement, and_, func, or_
from sqlalchemy.orm import Session

from backend.core.environments import LINUX, normalize_environment, source_types_for_family
from backend.database.models import (
    DATA_SCOPE_GLOBAL,
    DATA_SCOPE_PRIVATE,
    GLOBAL_DATA_ORIGINS,
    Account,
    CloudSource,
    SecurityEvent,
    Server,
    User,
)

YOGESH_ACCOUNT_NAME = "Yogesh"
YOGESH_ACCOUNT_ID = str(uuid.uuid5(uuid.NAMESPACE_DNS, "defensync.account.yogesh"))


def is_admin(user: User | None) -> bool:
    return bool(user) and str(getattr(user, "role", "")).upper() == "ADMIN"


def resolve_account_id(current_user: User) -> str | None:
    """ANALYST account membership. ADMIN is platform-level (None unless impersonating)."""
    if is_admin(current_user):
        return None
    return getattr(current_user, "account_id", None)


def infer_data_scope(data_origin: str | None, explicit: str | None = None) -> str:
    if explicit in {DATA_SCOPE_PRIVATE, DATA_SCOPE_GLOBAL}:
        return explicit
    origin = (data_origin or "LIVE_LINUX").upper()
    if origin in GLOBAL_DATA_ORIGINS:
        return DATA_SCOPE_GLOBAL
    return DATA_SCOPE_PRIVATE


def user_can_access_server(user: User, server: Server) -> bool:
    if is_admin(user):
        return True
    account_id = getattr(user, "account_id", None)
    server_account = getattr(server, "account_id", None)
    if account_id and server_account and account_id == server_account:
        return True
    return (server.owner_id or server.created_by) == user.id


def user_can_access_cloud_source(user: User, source: CloudSource) -> bool:
    """Same ownership rule as Linux servers: ADMIN, the owning account, or the creating user."""
    if is_admin(user):
        return True
    account_id = getattr(user, "account_id", None)
    if account_id and source.account_id and account_id == source.account_id:
        return True
    return (source.owner_id or source.created_by) == user.id


def cloud_source_visibility_clause(user: User) -> ColumnElement[bool] | None:
    """SQL form of user_can_access_cloud_source; None means unscoped (ADMIN)."""
    if is_admin(user):
        return None
    owned = or_(CloudSource.owner_id == user.id, and_(CloudSource.owner_id.is_(None), CloudSource.created_by == user.id))
    account_id = getattr(user, "account_id", None)
    return or_(CloudSource.account_id == account_id, owned) if account_id else owned


def event_visibility_clause(
    *,
    scope: str,
    user: User,
    selected_account_id: str | None = None,
) -> ColumnElement[bool] | None:
    """SQLAlchemy filter for PRIVATE / GLOBAL / BOTH event reads."""
    requested = (scope or "private").lower()
    admin = is_admin(user)
    account_id = selected_account_id if admin else getattr(user, "account_id", None)

    private = _private_clause(user=user, account_id=account_id, admin=admin)
    global_only = SecurityEvent.data_scope == DATA_SCOPE_GLOBAL

    if requested == "global":
        return global_only
    if requested == "both":
        return or_(private, global_only)
    return private


def _private_clause(*, user: User, account_id: str | None, admin: bool) -> ColumnElement[bool]:
    private = SecurityEvent.data_scope == DATA_SCOPE_PRIVATE
    if admin:
        if account_id:
            return and_(private, SecurityEvent.account_id == account_id)
        return private
    if account_id:
        return and_(private, SecurityEvent.account_id == account_id)
    return and_(
        private,
        SecurityEvent.owner_id == user.id,
        or_(SecurityEvent.account_id.is_(None), SecurityEvent.account_id == ""),
    )


def environment_clause(environment: str) -> ColumnElement[bool]:
    """Rows whose source_type belongs to one environment, mirroring core.environments.source_family."""
    family = normalize_environment(environment)
    clause = func.upper(SecurityEvent.source_type).in_(source_types_for_family(family))
    if family == LINUX:
        clause = or_(clause, SecurityEvent.source_type.is_(None), SecurityEvent.source_type == "")
    return clause


def with_environment(visibility: ColumnElement[bool] | None, environment: str | None) -> ColumnElement[bool] | None:
    """Narrow a visibility clause to one environment; None keeps the clause unchanged."""
    if environment is None:
        return visibility
    clause = environment_clause(environment)
    return clause if visibility is None else and_(visibility, clause)


def apply_event_visibility(stmt: Any, clause: ColumnElement[bool] | None):
    if clause is None:
        return stmt
    return stmt.where(clause)


def get_account(session: Session, account_id: str | None) -> Account | None:
    if not account_id:
        return None
    return session.get(Account, account_id)

"""Secure event_ids filter for GET /api/v1/events (visibility still enforced)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.api import events as events_api
from backend.api.dependencies import get_current_user, get_db
from backend.core.environments import CLOUD, LINUX
from backend.core.exceptions import ValidationException, register_exception_handlers
from backend.database.models import DATA_SCOPE_PRIVATE, Account, Base, Event, User
from backend.services.cloud.azure_normalizer import DATA_ORIGIN as AZURE_ORIGIN
from backend.services.event_service import (
    MAX_EVENT_IDS_FILTER,
    normalize_event_ids,
    resolve_cloud_event_ids_data_origin,
)

T0 = datetime(2026, 10, 4, 8, 0, tzinfo=timezone.utc)
ACCOUNT_A = "acct-a"
ACCOUNT_B = "acct-b"
PRESENTATION = "PRESENTATION"
SYNTHETIC = "SYNTHETIC_CLOUD_DEMO"


def new_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


@pytest.fixture
def session():
    db = new_session()
    db.add_all(
        [
            Account(id=ACCOUNT_A, name="Account A"),
            Account(id=ACCOUNT_B, name="Account B"),
            User(id="user-a", username="analyst_a", email="a@example.test", hashed_password="x", role="ANALYST", account_id=ACCOUNT_A),
            User(id="user-b", username="analyst_b", email="b@example.test", hashed_password="x", role="ANALYST", account_id=ACCOUNT_B),
        ]
    )
    db.commit()
    yield db
    db.close()


def add_event(
    session,
    *,
    event_id=None,
    account_id=ACCOUNT_A,
    owner_id="user-a",
    source_type=CLOUD,
    data_origin=AZURE_ORIGIN,
):
    eid = event_id or str(uuid.uuid4())
    session.add(
        Event(
            event_id=eid,
            timestamp=T0,
            hostname="cloud",
            username="alice@contoso.test",
            actor_id="actor-1",
            event_type="CLOUD_LOGIN_SUCCESS",
            category="cloud",
            severity="info",
            risk_score=10,
            message="test",
            raw_log='{"secret":"not-for-url"}',
            hash=str(uuid.uuid4()),
            owner_id=owner_id,
            account_id=account_id,
            data_scope=DATA_SCOPE_PRIVATE,
            source_type=source_type,
            provider="AZURE" if source_type == CLOUD else None,
            data_origin=data_origin,
        )
    )
    session.commit()
    return eid


def api(session, user_id: str) -> TestClient:
    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(events_api.router, prefix="/api/v1/events")
    user = session.get(User, user_id)
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app)


def unauthenticated_api(session) -> TestClient:
    """Real auth dependency — do not override get_current_user."""
    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(events_api.router, prefix="/api/v1/events")
    app.dependency_overrides[get_db] = lambda: session
    return TestClient(app)


def test_normalize_event_ids_validation():
    assert normalize_event_ids(None) is None
    assert normalize_event_ids([" a ", "a", "b,c"]) == ["a", "b", "c"]
    with pytest.raises(ValidationException):
        normalize_event_ids([" "])
    with pytest.raises(ValidationException):
        normalize_event_ids(["bad id!"])
    with pytest.raises(ValidationException):
        normalize_event_ids([f"id-{i}" for i in range(MAX_EVENT_IDS_FILTER + 1)])


def test_resolve_cloud_event_ids_forces_azure_origin():
    assert (
        resolve_cloud_event_ids_data_origin(
            event_ids=["evt-1"],
            environment=CLOUD,
            requested_data_origin=SYNTHETIC,
        )
        == AZURE_ORIGIN
    )
    assert (
        resolve_cloud_event_ids_data_origin(
            event_ids=None,
            environment=CLOUD,
            requested_data_origin=SYNTHETIC,
        )
        == SYNTHETIC
    )
    assert (
        resolve_cloud_event_ids_data_origin(
            event_ids=["evt-1"],
            environment=LINUX,
            requested_data_origin=None,
        )
        is None
    )


def test_matching_event_ids_return_visible_rows(session):
    keep = add_event(session, event_id="evt-keep")
    other = add_event(session, event_id="evt-other")
    client = api(session, "user-a")
    response = client.get(
        "/api/v1/events",
        params=[("event_ids", keep), ("event_ids", other), ("environment", CLOUD), ("limit", "50")],
    )
    assert response.status_code == 200, response.text
    ids = {row["event_id"] for row in response.json()}
    assert ids == {keep, other}


def test_nonexistent_event_ids_return_empty(session):
    add_event(session, event_id="evt-real")
    client = api(session, "user-a")
    response = client.get(
        "/api/v1/events",
        params={"event_ids": "evt-missing", "environment": CLOUD, "limit": 50},
    )
    assert response.status_code == 200
    assert response.json() == []


def test_unauthorized_cross_account_event_ids_are_hidden(session):
    mine = add_event(session, event_id="evt-a", account_id=ACCOUNT_A, owner_id="user-a")
    theirs = add_event(session, event_id="evt-b", account_id=ACCOUNT_B, owner_id="user-b")
    client = api(session, "user-a")
    response = client.get(
        "/api/v1/events",
        params={"event_ids": f"{mine},{theirs}", "environment": CLOUD, "limit": 50},
    )
    assert response.status_code == 200
    ids = [row["event_id"] for row in response.json()]
    assert ids == [mine]
    assert theirs not in ids


def test_environment_isolation_for_event_ids(session):
    cloud_id = add_event(session, event_id="evt-cloud", source_type=CLOUD, data_origin=AZURE_ORIGIN)
    linux_id = add_event(session, event_id="evt-linux", source_type=LINUX, data_origin="LIVE_LINUX")
    client = api(session, "user-a")
    cloud = client.get(
        "/api/v1/events",
        params={"event_ids": f"{cloud_id},{linux_id}", "environment": CLOUD, "limit": 50},
    ).json()
    linux = client.get(
        "/api/v1/events",
        params={"event_ids": f"{cloud_id},{linux_id}", "environment": LINUX, "limit": 50},
    ).json()
    assert [row["event_id"] for row in cloud] == [cloud_id]
    assert [row["event_id"] for row in linux] == [linux_id]


def test_cloud_event_ids_exclude_non_azure_origin_even_when_visible(session):
    azure_id = add_event(session, event_id="evt-azure", data_origin=AZURE_ORIGIN)
    presentation_id = add_event(session, event_id="evt-presentation", data_origin=PRESENTATION)
    synthetic_id = add_event(session, event_id="evt-synthetic", data_origin=SYNTHETIC)
    client = api(session, "user-a")
    # Client even requests a non-Azure origin; server must still force Azure for CLOUD+event_ids.
    response = client.get(
        "/api/v1/events",
        params={
            "event_ids": f"{azure_id},{presentation_id},{synthetic_id}",
            "environment": CLOUD,
            "data_origin": SYNTHETIC,
            "limit": 50,
        },
    )
    assert response.status_code == 200, response.text
    ids = [row["event_id"] for row in response.json()]
    assert ids == [azure_id]
    assert presentation_id not in ids
    assert synthetic_id not in ids


def test_ordinary_listing_unchanged_without_event_ids(session):
    first = add_event(session, event_id="evt-1")
    second = add_event(session, event_id="evt-2", data_origin=SYNTHETIC)
    client = api(session, "user-a")
    response = client.get("/api/v1/events", params={"environment": CLOUD, "limit": 50})
    assert response.status_code == 200
    ids = {row["event_id"] for row in response.json()}
    assert ids == {first, second}


def test_empty_event_ids_returns_422(session):
    client = api(session, "user-a")
    response = client.get("/api/v1/events", params={"event_ids": "", "environment": CLOUD})
    assert response.status_code == 422
    assert "empty" in response.text.lower() or "event_ids" in response.text.lower()


def test_too_many_event_ids_returns_422(session):
    client = api(session, "user-a")
    ids = ",".join(f"id-{i}" for i in range(MAX_EVENT_IDS_FILTER + 1))
    response = client.get("/api/v1/events", params={"event_ids": ids, "environment": CLOUD})
    assert response.status_code == 422
    assert str(MAX_EVENT_IDS_FILTER) in response.text or "at most" in response.text.lower()


def test_invalid_event_ids_return_422(session):
    client = api(session, "user-a")
    response = client.get("/api/v1/events", params={"event_ids": "bad id!", "environment": CLOUD})
    assert response.status_code == 422
    assert "event_ids" in response.text.lower() or "letters" in response.text.lower()


def test_unauthenticated_requests_cannot_access_events(session):
    secret = add_event(session, event_id="evt-secret")
    client = unauthenticated_api(session)
    listed = client.get("/api/v1/events", params={"environment": CLOUD, "limit": 50})
    filtered = client.get(
        "/api/v1/events",
        params={"event_ids": secret, "environment": CLOUD, "limit": 50},
    )
    assert listed.status_code in {401, 403}, listed.text
    assert filtered.status_code in {401, 403}, filtered.text
    assert secret not in listed.text
    assert secret not in filtered.text
    assert "not-for-url" not in listed.text
    assert "not-for-url" not in filtered.text

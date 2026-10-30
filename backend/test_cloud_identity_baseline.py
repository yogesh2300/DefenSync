"""Cloud identity behavioral baseline v0: aggregation, isolation, origin filtering."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.api import cloud as cloud_api
from backend.api.dependencies import get_current_user, get_db
from backend.core.environments import CLOUD, LINUX
from backend.core.exceptions import register_exception_handlers
from backend.database.models import (
    DATA_SCOPE_PRIVATE,
    PRESENTATION_DATA_ORIGIN,
    Account,
    Base,
    Event,
    User,
)
from backend.services.cloud.azure_normalizer import DATA_ORIGIN as AZURE_ORIGIN
from backend.services.cloud.identity_baseline_service import CloudIdentityBaselineService

T0 = datetime(2026, 10, 4, 8, 0, tzinfo=timezone.utc)
ACCOUNT_A = "acct-a"
ACCOUNT_B = "acct-b"
ALICE = "11111111-1111-1111-1111-111111111111"
BOB = "22222222-2222-2222-2222-222222222222"


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
            User(
                id="user-a",
                username="analyst_a",
                email="a@example.test",
                hashed_password="x",
                role="ANALYST",
                account_id=ACCOUNT_A,
            ),
            User(
                id="user-b",
                username="analyst_b",
                email="b@example.test",
                hashed_password="x",
                role="ANALYST",
                account_id=ACCOUNT_B,
            ),
        ]
    )
    db.commit()
    yield db
    db.close()


def add_event(
    session,
    *,
    actor_id,
    account_id=ACCOUNT_A,
    owner_id="user-a",
    minute=0,
    operation="Sign-in activity",
    resource_id="app-1",
    source_type=CLOUD,
    data_origin=AZURE_ORIGIN,
    identity=None,
    event_type="CLOUD_LOGIN_SUCCESS",
    timestamp=None,
):
    identity = identity if identity is not None else {
        "tenant_id": "tenant-a",
        "object_id": actor_id,
        "user_principal_name": "alice@contoso.test" if actor_id == ALICE else "bob@contoso.test",
        "identity_type": "user",
    }
    session.add(
        Event(
            event_id=str(uuid.uuid4()),
            timestamp=timestamp if timestamp is not None else T0 + timedelta(minutes=minute),
            hostname="entra-id",
            username=(identity or {}).get("user_principal_name") if identity else None,
            actor_id=actor_id,
            event_type=event_type,
            category="cloud",
            severity="info",
            risk_score=10,
            message="test",
            raw_log="{}",
            hash=str(uuid.uuid4()),
            owner_id=owner_id,
            account_id=account_id,
            data_scope=DATA_SCOPE_PRIVATE,
            source_type=source_type,
            provider="AZURE" if source_type == CLOUD else None,
            data_origin=data_origin,
            operation=operation,
            resource_id=resource_id,
            normalized_data=json.dumps({"cloud_identity": identity}) if identity is not None else None,
        )
    )
    session.commit()


def api(session, user_id: str) -> TestClient:
    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(cloud_api.router, prefix="/api/v1/cloud")
    user = session.get(User, user_id)
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app)


def test_normal_aggregation_by_actor_id(session):
    add_event(session, actor_id=ALICE, minute=0, operation="Sign-in activity", resource_id="app-1")
    add_event(session, actor_id=ALICE, minute=30, operation="MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE", resource_id="/subscriptions/x")
    add_event(session, actor_id=BOB, minute=60, operation="Sign-in activity", resource_id="app-2")
    result = CloudIdentityBaselineService(session).build(
        user=session.get(User, "user-a"),
        start_time=T0,
        end_time=T0 + timedelta(hours=3),
    )
    assert result["environment"] == CLOUD
    assert result["data_origins"] == [AZURE_ORIGIN]
    assert result["summary"]["identity_count"] == 2
    assert result["summary"]["event_count"] == 3
    assert "not a determination of compromise" in result["disclaimer"].lower()
    alice = next(item for item in result["identities"] if item["actor_id"] == ALICE)
    bob = next(item for item in result["identities"] if item["actor_id"] == BOB)
    assert alice["event_count"] == 2
    assert alice["distinct_operations"] == 2
    assert alice["distinct_resources"] == 2
    assert alice["activity_rate_per_hour"] == round(2 / 3, 4)
    assert alice["cloud_identity"]["user_principal_name"] == "alice@contoso.test"
    assert alice["hourly_distribution"]["8"] == 2
    assert bob["event_count"] == 1
    assert bob["hourly_distribution"]["9"] == 1


def test_empty_window_returns_zero_identities(session):
    result = CloudIdentityBaselineService(session).build(
        user=session.get(User, "user-a"),
        start_time=T0,
        end_time=T0 + timedelta(hours=1),
    )
    assert result["identities"] == []
    assert result["summary"] == {
        "identity_count": 0,
        "event_count": 0,
        "events_skipped_missing_identity": 0,
    }


def test_missing_actor_id_is_skipped(session):
    add_event(session, actor_id=ALICE, minute=0)
    add_event(session, actor_id=None, minute=5, identity=None)
    result = CloudIdentityBaselineService(session).build(
        user=session.get(User, "user-a"),
        start_time=T0,
        end_time=T0 + timedelta(hours=1),
    )
    assert result["summary"]["identity_count"] == 1
    assert result["summary"]["events_skipped_missing_identity"] == 1
    assert result["identities"][0]["actor_id"] == ALICE


def test_account_isolation(session):
    add_event(session, actor_id=ALICE, account_id=ACCOUNT_A, owner_id="user-a", minute=0)
    add_event(session, actor_id=BOB, account_id=ACCOUNT_B, owner_id="user-b", minute=0)
    for user_id, expected in (("user-a", ALICE), ("user-b", BOB)):
        result = CloudIdentityBaselineService(session).build(
            user=session.get(User, user_id),
            start_time=T0,
            end_time=T0 + timedelta(hours=1),
        )
        assert [item["actor_id"] for item in result["identities"]] == [expected]
        assert result["summary"]["event_count"] == 1


def test_linux_and_non_azure_origins_are_excluded(session):
    add_event(session, actor_id=ALICE, minute=0, data_origin=AZURE_ORIGIN)
    add_event(
        session,
        actor_id=ALICE,
        minute=1,
        source_type=LINUX,
        data_origin="LIVE_LINUX",
        operation="Failed Login",
        resource_id=None,
        identity=None,
    )
    add_event(
        session,
        actor_id=ALICE,
        minute=2,
        data_origin=PRESENTATION_DATA_ORIGIN,
    )
    add_event(
        session,
        actor_id=ALICE,
        minute=3,
        data_origin="SYNTHETIC_CLOUD_DEMO",
    )
    add_event(
        session,
        actor_id=ALICE,
        minute=4,
        data_origin="PUBLIC_DATASET",
    )
    result = CloudIdentityBaselineService(session).build(
        user=session.get(User, "user-a"),
        start_time=T0,
        end_time=T0 + timedelta(hours=1),
    )
    assert result["summary"]["event_count"] == 1
    assert result["identities"][0]["event_count"] == 1


def test_invalid_window_and_disallowed_origin(session):
    service = CloudIdentityBaselineService(session)
    user = session.get(User, "user-a")
    with pytest.raises(Exception) as too_short:
        service.build(user=user, start_time=T0, end_time=T0)
    assert "after start_time" in str(too_short.value).lower() or "too short" in str(too_short.value).lower()
    with pytest.raises(Exception) as bad_origin:
        service.build(
            user=user,
            start_time=T0,
            end_time=T0 + timedelta(hours=1),
            data_origins=["SYNTHETIC_CLOUD_DEMO"],
        )
    assert "Unsupported data_origins" in str(bad_origin.value)


def test_api_requires_auth_and_returns_baselines(session):
    add_event(session, actor_id=ALICE, minute=0)
    add_event(session, actor_id=ALICE, minute=20, operation="Other")
    client = api(session, "user-a")
    response = client.get(
        "/api/v1/cloud/identity-baselines",
        params={"start_time": T0.isoformat(), "end_time": (T0 + timedelta(hours=2)).isoformat()},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["environment"] == "CLOUD"
    assert body["identities"][0]["actor_id"] == ALICE
    assert body["identities"][0]["event_count"] == 2
    assert "owner_id" not in body["identities"][0]
    assert "account_id" not in body["identities"][0]


def test_api_actor_filter_and_account_isolation(session):
    add_event(session, actor_id=ALICE, account_id=ACCOUNT_A, owner_id="user-a", minute=0)
    add_event(session, actor_id=BOB, account_id=ACCOUNT_A, owner_id="user-a", minute=0)
    add_event(session, actor_id=ALICE, account_id=ACCOUNT_B, owner_id="user-b", minute=0)
    client = api(session, "user-a")
    response = client.get(
        "/api/v1/cloud/identity-baselines",
        params={
            "start_time": T0.isoformat(),
            "end_time": (T0 + timedelta(hours=1)).isoformat(),
            "actor_id": ALICE,
        },
    )
    assert response.status_code == 200
    identities = response.json()["identities"]
    assert len(identities) == 1
    assert identities[0]["actor_id"] == ALICE
    assert identities[0]["event_count"] == 1

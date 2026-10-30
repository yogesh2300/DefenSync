"""Cloud suspicious activity sequence detection v0 tests."""

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
from backend.services.cloud.sequence_detection_service import CloudSequenceDetectionService
from backend.services.datasets.azure_import_service import (
    CLOUD_AUTHENTICATION,
    CLOUD_LOGIN_FAILURE,
    CLOUD_LOGIN_SUCCESS,
    CLOUD_PRIVILEGE_CHANGE,
    CLOUD_RESOURCE_OPERATION,
)

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
    actor_id,
    event_type,
    minute=0,
    account_id=ACCOUNT_A,
    owner_id="user-a",
    source_ip=None,
    operation=None,
    resource_id=None,
    source_type=CLOUD,
    data_origin=AZURE_ORIGIN,
):
    identity = None
    if actor_id:
        identity = {
            "object_id": actor_id,
            "user_principal_name": "alice@contoso.test" if actor_id == ALICE else "bob@contoso.test",
            "identity_type": "user",
        }
    session.add(
        Event(
            event_id=str(uuid.uuid4()),
            timestamp=T0 + timedelta(minutes=minute),
            hostname="cloud",
            username=(identity or {}).get("user_principal_name"),
            actor_id=actor_id,
            event_type=event_type,
            category="cloud",
            severity="info",
            risk_score=20,
            message="test",
            raw_log='{"secret":"should-not-appear"}',
            hash=str(uuid.uuid4()),
            owner_id=owner_id,
            account_id=account_id,
            data_scope=DATA_SCOPE_PRIVATE,
            source_type=source_type,
            provider="AZURE" if source_type == CLOUD else None,
            data_origin=data_origin,
            source_ip=source_ip,
            operation=operation,
            resource_id=resource_id,
            normalized_data=json.dumps({"cloud_identity": identity}) if identity else None,
        )
    )
    session.commit()


def detect(session, user_id="user-a", **kwargs):
    defaults = {
        "user": session.get(User, user_id),
        "start_time": T0,
        "end_time": T0 + timedelta(hours=2),
        "sequence_minutes": 60,
    }
    defaults.update(kwargs)
    return CloudSequenceDetectionService(session).detect(**defaults)


def api(session, user_id: str) -> TestClient:
    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(cloud_api.router, prefix="/api/v1/cloud")
    user = session.get(User, user_id)
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app)


def test_valid_auth_failure_then_success_sequence(session):
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_FAILURE, minute=0)
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_FAILURE, minute=2)
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_SUCCESS, minute=5)
    result = detect(session)
    findings = [item for item in result["findings"] if item["pattern_id"] == "auth_failures_then_success"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["actor_id"] == ALICE
    assert finding["severity"] == "high"
    assert finding["interpretation"] == "heuristic"
    assert "does not confirm" in finding["limitations"][0].lower()
    assert len(finding["event_refs"]) == 3
    assert "raw_log" not in json.dumps(finding)
    assert "should-not-appear" not in json.dumps(result)


def test_wrong_ordering_does_not_match(session):
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_SUCCESS, minute=0)
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_FAILURE, minute=2)
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_FAILURE, minute=4)
    add_event(session, actor_id=ALICE, event_type=CLOUD_RESOURCE_OPERATION, minute=1, operation="write")
    add_event(session, actor_id=ALICE, event_type=CLOUD_PRIVILEGE_CHANGE, minute=3, operation="roleAssignments/write")
    result = detect(session)
    assert result["findings"] == []


def test_events_outside_sequence_window_do_not_match(session):
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_FAILURE, minute=0)
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_FAILURE, minute=1)
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_SUCCESS, minute=90)
    result = detect(session, sequence_minutes=60)
    assert [item["pattern_id"] for item in result["findings"]] == []


def test_ambiguous_authentication_type_is_not_treated_as_success_or_failure(session):
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_FAILURE, minute=0)
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_FAILURE, minute=1)
    add_event(session, actor_id=ALICE, event_type=CLOUD_AUTHENTICATION, minute=2)
    result = detect(session)
    assert result["findings"] == []


def test_missing_source_ip_skips_ip_change_rule(session):
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_SUCCESS, minute=0, source_ip=None)
    add_event(
        session,
        actor_id=ALICE,
        event_type=CLOUD_PRIVILEGE_CHANGE,
        minute=5,
        source_ip="198.51.100.9",
        operation="roleAssignments/write",
    )
    result = detect(session)
    assert all(item["pattern_id"] != "login_success_then_privilege_ip_change" for item in result["findings"])


def test_privilege_then_resource_and_ip_change_rules(session):
    add_event(
        session,
        actor_id=ALICE,
        event_type=CLOUD_LOGIN_SUCCESS,
        minute=0,
        source_ip="203.0.113.10",
    )
    add_event(
        session,
        actor_id=ALICE,
        event_type=CLOUD_PRIVILEGE_CHANGE,
        minute=10,
        source_ip="198.51.100.20",
        operation="Microsoft.Authorization/roleAssignments/write",
    )
    add_event(
        session,
        actor_id=ALICE,
        event_type=CLOUD_RESOURCE_OPERATION,
        minute=15,
        operation="Microsoft.Compute/virtualMachines/write",
        resource_id="/subscriptions/x/vm-1",
    )
    result = detect(session)
    patterns = {item["pattern_id"] for item in result["findings"]}
    assert "privilege_then_resource" in patterns
    assert "login_success_then_privilege_ip_change" in patterns


def test_different_identities_do_not_cross_match(session):
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_FAILURE, minute=0)
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_FAILURE, minute=1)
    add_event(session, actor_id=BOB, event_type=CLOUD_LOGIN_SUCCESS, minute=2)
    add_event(session, actor_id=ALICE, event_type=CLOUD_PRIVILEGE_CHANGE, minute=3, operation="roleAssignments/write")
    add_event(session, actor_id=BOB, event_type=CLOUD_RESOURCE_OPERATION, minute=4, operation="write", resource_id="r1")
    result = detect(session)
    assert result["findings"] == []


def test_empty_dataset(session):
    result = detect(session)
    assert result["findings"] == []
    assert result["summary"]["finding_count"] == 0
    assert result["summary"]["event_count"] == 0


def test_account_isolation(session):
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_FAILURE, minute=0, account_id=ACCOUNT_A, owner_id="user-a")
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_FAILURE, minute=1, account_id=ACCOUNT_A, owner_id="user-a")
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_SUCCESS, minute=2, account_id=ACCOUNT_A, owner_id="user-a")
    add_event(session, actor_id=BOB, event_type=CLOUD_LOGIN_FAILURE, minute=0, account_id=ACCOUNT_B, owner_id="user-b")
    add_event(session, actor_id=BOB, event_type=CLOUD_LOGIN_FAILURE, minute=1, account_id=ACCOUNT_B, owner_id="user-b")
    add_event(session, actor_id=BOB, event_type=CLOUD_LOGIN_SUCCESS, minute=2, account_id=ACCOUNT_B, owner_id="user-b")
    for user_id, actor in (("user-a", ALICE), ("user-b", BOB)):
        result = detect(session, user_id=user_id)
        assert len(result["findings"]) == 1
        assert result["findings"][0]["actor_id"] == actor


def test_data_origin_and_linux_isolation(session):
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_FAILURE, minute=0, data_origin=PRESENTATION_DATA_ORIGIN)
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_FAILURE, minute=1, data_origin="SYNTHETIC_CLOUD_DEMO")
    add_event(
        session,
        actor_id=ALICE,
        event_type=CLOUD_LOGIN_SUCCESS,
        minute=2,
        source_type=LINUX,
        data_origin="LIVE_LINUX",
    )
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_FAILURE, minute=3, data_origin=AZURE_ORIGIN)
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_FAILURE, minute=4, data_origin=AZURE_ORIGIN)
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_SUCCESS, minute=5, data_origin=AZURE_ORIGIN)
    result = detect(session)
    assert len(result["findings"]) == 1
    assert result["data_origins"] == [AZURE_ORIGIN]


def test_api_sequence_findings_endpoint(session):
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_FAILURE, minute=0)
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_FAILURE, minute=1)
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_SUCCESS, minute=2)
    client = api(session, "user-a")
    response = client.get(
        "/api/v1/cloud/sequence-findings",
        params={
            "start_time": T0.isoformat(),
            "end_time": (T0 + timedelta(hours=1)).isoformat(),
            "sequence_minutes": 60,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["environment"] == "CLOUD"
    assert body["summary"]["finding_count"] == 1
    assert body["findings"][0]["pattern_id"] == "auth_failures_then_success"
    assert "compromise" in body["disclaimer"].lower()
    assert {rule["pattern_id"] for rule in body["rules"]} >= {
        "auth_failures_then_success",
        "privilege_then_resource",
        "login_success_then_privilege_ip_change",
    }


def test_findings_cap_sets_truncated(session):
    from backend.services.cloud.sequence_detection_service import MAX_FINDINGS

    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_FAILURE, minute=0)
    add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_FAILURE, minute=1)
    for offset in range(MAX_FINDINGS + 3):
        add_event(session, actor_id=ALICE, event_type=CLOUD_LOGIN_SUCCESS, minute=2 + offset)
    result = detect(session, end_time=T0 + timedelta(hours=5), sequence_minutes=300)
    assert result["summary"]["finding_count"] == MAX_FINDINGS
    assert result["summary"]["truncated"] is True
    assert len(result["findings"]) == MAX_FINDINGS

"""One controlled Cloud DEMO → n8n webhook check (no Azure changes).

Creates/uses the presentation DEMO payload and POSTs once through N8nNotifier.
Does not invent mailbox delivery: prints webhook HTTP status only.
Recipient/From stay in the existing n8n Send Email node.
"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timezone

from backend.core.config import get_settings
from backend.core.environments import CLOUD
from backend.database.connection import get_session
from backend.database.models import PRESENTATION_DATA_ORIGIN, CloudSource, User
from backend.services import collection_n8n_trigger, n8n_notifier
from backend.services.cloud.presentation_telemetry import (
    DEMO_ACTOR,
    DEMO_EMAIL_SUBJECT,
    DEMO_OPERATION,
    DEMO_RESOURCE_GROUP,
    DEMO_TITLE,
    NOTE,
    RECOMMENDATION,
    SYSTEM_NAME,
    cloud_demo_n8n_every_success,
)
from backend.risk.levels import risk_level_from_score
from sqlalchemy import select


def main() -> int:
    settings = get_settings()
    emails = (settings.PRESENTATION_TELEMETRY_EMAILS or "").strip()
    print("PRESENTATION_TELEMETRY_EMAILS:", emails or "(empty)")
    print("CLOUD_DEMO_EVERY_SUCCESS:", settings.CLOUD_DEMO_EVERY_SUCCESS)
    print("CLOUD_DEMO_N8N_EVERY_SUCCESS:", settings.CLOUD_DEMO_N8N_EVERY_SUCCESS)
    print("N8N_NOTIFICATION_RECIPIENT_EMAILS:", (settings.N8N_NOTIFICATION_RECIPIENT_EMAILS or "").strip() or "(empty)")
    print("n8n configured:", bool(settings.N8N_WEBHOOK_URL.get_secret_value()))
    if not emails:
        print("ERROR: set PRESENTATION_TELEMETRY_EMAILS in .env to the Cloud source owner login email.")
        return 2

    session = get_session()
    try:
        owner = None
        for raw in emails.split(","):
            email = raw.strip().lower()
            if not email:
                continue
            owner = session.scalar(select(User).where(User.email == email))
            if owner:
                break
        if owner is None:
            print("ERROR: no DefenSync user matches PRESENTATION_TELEMETRY_EMAILS.")
            return 2
        source = session.scalar(select(CloudSource).where(CloudSource.owner_id == owner.id).limit(1))
        if source is None:
            print("ERROR: owner has no cloud source; add one in Cloud Accounts first.")
            return 2
        print("owner:", owner.email)
        print("cloud_source:", source.id)

        now = datetime.now(timezone.utc)
        run_id = str(uuid.uuid4())  # fits CollectionN8nDispatch.collection_run_id String(36)
        collection_id = run_id
        demo = {
            "simulated": True,
            "demo_label": "DEMO",
            "title": DEMO_TITLE,
            "system_name": SYSTEM_NAME,
            "environment": CLOUD,
            "operation": DEMO_OPERATION,
            "operation_result": "Failed",
            "initiating_user": DEMO_ACTOR,
            "target_resource": DEMO_RESOURCE_GROUP,
            "event_timestamp": now.isoformat(),
            "risk_score": 70,
            "risk_level": risk_level_from_score(70),
            "event_type": "CLOUD_PRIVILEGE_CHANGE",
            "collection_id": collection_id,
            "recommended_action": RECOMMENDATION,
            "email_subject": DEMO_EMAIL_SUBJECT,
            "data_origin": PRESENTATION_DATA_ORIGIN,
            "note": NOTE,
        }
        every = 1 if cloud_demo_n8n_every_success(settings) else 2
        notifier = n8n_notifier.N8nNotifier.from_settings(background=False)
        # Use a unique run id so this verify script never collides with a real collection outbox row.
        view = collection_n8n_trigger.record_successful_collection(
            session,
            source_type=CLOUD,
            collection_run_id=run_id,
            owner_id=owner.id,
            account_id=getattr(source, "account_id", None),
            outcome=collection_n8n_trigger.OUTCOME_CLOUD_SUCCESS,
            completed_at=now,
            notifier=notifier,
            security_demo=demo,
            trigger_every=every,
            policy="cloud_demo_every_success" if every == 1 else "alternate_success",
            now=now,
        )
        print("dispatch:", json.dumps(view, default=str))
        last = n8n_notifier.last_delivery()
        print("last_delivery:", json.dumps(last, default=str))
        print("email_delivery: unknown (DefenSync only sees webhook HTTP; check n8n execution + mailbox)")
        print("suggested_subject:", DEMO_EMAIL_SUBJECT)
        print(
            "n8n mapping hint: Subject = {{$json.body.notification.suggested_subject}} "
            "or hardcode; HTML = {{$json.body.notification.suggested_html}}"
        )
        if view.get("dispatch_status") != "SENT":
            return 1
        return 0
    finally:
        session.close()


if __name__ == "__main__":
    sys.exit(main())

# DefenSync → n8n security alert email

## Why Gmail showed blank fields

The Send Email HTML still had **literal editor placeholders** such as `[Execute previous nodes for preview]`, or expressions that pointed at `body.incident.*` on a **collection** webhook.

Collection notifications use schema `defensync-collection-n8n-v1`. Demo values are under `body.security_demo` and normalized into `body.notification.email_fields`. They are **not** under `body.incident`.

n8n’s design-time preview text is not a real value. Execute the webhook (or use DefenSync’s pre-rendered `suggested_html`) before judging the email.

## Actual webhook JSON (collection + DEMO)

Top-level keys (posted body; in n8n usually `$json.body`):

| Path | Example |
|------|---------|
| `event` | `collection.alternate_success` |
| `event_id` | collection notification id |
| `source_type` | `CLOUD` |
| `collection_id` | collection run id |
| `sequence_number` | integer |
| `completed_at` / `outcome` / `sent_at` | metadata |
| `notification.recipient_emails` | To addresses |
| `notification.suggested_subject` | subject line |
| `notification.suggested_html` | full HTML body (preferred) |
| `notification.email_fields.*` | flat display strings (N/A already applied) |
| `security_demo.*` | raw demo fields (`simulated`, `title`, `initiating_user`, …) |

## Actual webhook JSON (real incident)

| Path | Meaning |
|------|---------|
| `event` | `incident.created` / `incident.escalated` |
| `incident.*` | title, severity, environment, risk_score, actor, … |
| `notification.email_fields.*` | same flat keys as demo (N/A for missing) |
| `notification.suggested_html` | full HTML |
| `security_demo` | only when presentation telemetry is attached |

## Exact HTML expression paths

| Email label | Primary expression |
|-------------|-------------------|
| Label | `{{$json.body.notification.email_fields.label}}` |
| Severity | `{{$json.body.notification.email_fields.severity}}` |
| Environment | `{{$json.body.notification.email_fields.environment}}` |
| Risk Score | `{{$json.body.notification.email_fields.risk_score}}` |
| Confidence | `{{$json.body.notification.email_fields.confidence}}` |
| Actor | `{{$json.body.notification.email_fields.actor}}` |
| Event Count | `{{$json.body.notification.email_fields.event_count}}` |
| Status | `{{$json.body.notification.email_fields.status}}` |
| Detected Activity | `{{$json.body.notification.email_fields.detected_activity}}` |
| Operation | `{{$json.body.notification.email_fields.operation}}` |
| Target | `{{$json.body.notification.email_fields.target_resource}}` |
| Security Analysis | `{{$json.body.notification.email_fields.security_analysis}}` |
| Recommended Action | `{{$json.body.notification.email_fields.recommended_action}}` |
| Incident ID | `{{$json.body.notification.email_fields.incident_id}}` |
| Collection ID | `{{$json.body.notification.email_fields.collection_id}}` |
| Timestamp | `{{$json.body.notification.email_fields.event_timestamp}}` |

Fallbacks (if `email_fields` missing on an old execution):

- Demo: `security_demo.initiating_user`, `security_demo.operation`, `security_demo.note`, `event_id`
- Incident: `incident.severity`, `incident.actor`, `incident.explanation`, `incident.incident_id`

## n8n Send Email node

Keep existing From / SMTP credential.

| Field | Expression |
|-------|------------|
| **To** | `{{$json.body.notification.recipient_emails[0]}}` |
| **Subject** | `{{$json.body.notification.suggested_subject}}` |
| **HTML** | Paste [`n8n-security-alert-email-template.html`](./n8n-security-alert-email-template.html) **or** use `{{$json.body.notification.suggested_html}}` |

## Demo values (from payload, not hardcoded in n8n)

| Field | Typical DEMO value |
|-------|-------------------|
| Label | DEMO / SIMULATED |
| Detected Activity | Suspicious Cloud Privilege Change |
| Environment | CLOUD |
| Operation | Microsoft.Authorization/roleAssignments/write |
| Actor | demo-suspicious-user |
| Target | demo-resource-group |
| Status | Failed |
| Risk Score | 70/100 |
| Severity | High |
| Event Count | 1 |
| Confidence | N/A |
| Incident ID | collection `event_id` |

`dispatch_status=SENT` = webhook HTTP accepted. It does **not** prove Gmail delivery.

## How to apply

1. Restart DefenSync backend (so payloads include `email_fields` / `suggested_html`).
2. Replace the Send Email HTML with the template file (or the one-line `suggested_html` expression).
3. Delete any leftover `[Execute previous nodes for preview]` text from the HTML field.
4. Trigger one approved Collect now / live test after template validation.

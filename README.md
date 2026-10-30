# DefenSync — Hybrid Behavioral Log Intelligence

DefenSync is a research prototype for **Linux + cloud + behavioral** security monitoring. It normalizes events, builds user baselines, correlates cross-source activity, and runs **Isolation Forest** (unknown anomalies) plus **Random Forest** (only when genuine `original_label` ground truth exists).

This is **defensive monitoring**. The system does **not** block accounts, terminate SSH sessions, isolate cloud resources, or enforce MFA on monitored systems. (DefenSync's own sign-in does require a one-time code — see [Sign-in and MFA](#sign-in-and-mfa).)

## Architecture

```
Linux logs (SSH) + OpenStack files + optional Azure Activity Log files + behavioral CSV
  + optional live Azure telemetry (Log Analytics: Entra sign-ins, Activity Log)
        → parse / normalize
        → RiskEngine (0–100 rules)
        → PostgreSQL events
        → behavioral baseline (CSV / sufficient Linux observations)
        → hybrid ML (persisted under models/)
        → backend correlation / incidents
        → Dashboard + Intelligence + Detection
```

**Event time vs collection time:** `events.timestamp` is the **source occurrence time**. `events.collection_timestamp` is when DefenSync retrieved the line. The dashboard timeline uses event time.

## Technology stack

- Frontend: React 18, Vite, Tailwind, Recharts
- Backend: FastAPI, SQLAlchemy 2, PostgreSQL
- Auth: JWT + bcrypt, analyst vs admin RBAC
- Collect: Paramiko SSH
- ML: scikit-learn IsolationForest / RandomForestClassifier, joblib persistence

## Linux monitoring

Default collection now includes `/var/log/secure`, `/var/log/auth.log`, `/var/log/audit/audit.log`, `journalctl --output=short-iso`, `last -F`, and diagnostic commands. Missing files are **skipped**; collection continues.

journald (auth/authpriv facilities) is read **incrementally** from a per-server cursor stored in `linux_collection_state`; the cursor advances only after the batch is stored, and a cursor lost to a reboot falls back to the last stored time (overlap is removed by event-hash deduplication). Collection reports whether the host journal is persistent. A volatile journal (`/run/log/journal`, the RHEL default without `/var/log/journal`) loses entries written between the last collection and a reboot. To check a host, or enable persistent storage on it as root:

```bash
bash scripts/linux/enable_persistent_journal.sh            # read-only check
sudo bash scripts/linux/enable_persistent_journal.sh --apply --max-use 500M
```

Live Linux features (when present): login hour from **event** time, failed-login batch counts, sudo/auth parsers, CPU/memory/disk/process/network snapshots. **Typing speed is not invented** for live Linux; those fields belong to the behavioral CSV dataset.

## Cloud monitoring

| Source | Status |
|---|---|
| OpenStack file import | Working (`provider=OPENSTACK`, `source_type=CLOUD`) |
| OpenStack synthetic demo | Working (`data_origin=SYNTHETIC_CLOUD_DEMO`) |
| Live OpenStack API | **No** |
| Azure Activity Log **file** import | Working (`POST /api/v1/datasets/azure/import`) — **not** live Azure |
| Live Azure telemetry (Entra sign-ins + Activity Log via Log Analytics) | Implemented, read-only, manual trigger (`POST /api/v1/cloud/azure/collect`). Tested with a real-shaped fake transport; **not yet tested against a live workspace** |
| BGL / HDFS | README placeholders only |

### Live Azure telemetry collector

**REAL AZURE TELEMETRY** (this collector, `data_origin=AZURE_LOG_ANALYTICS`, `data_scope=PRIVATE`) is kept separate from **PUBLIC / SYNTHETIC / CURATED DATASETS** (OpenStack, HDFS, BGL, synthetic demo, Azure file import). Nothing synthetic is ever labelled `AZURE_LOG_ANALYTICS`.

```
Azure (Entra ID sign-ins, Activity Log)
  → Log Analytics workspace (diagnostic settings export)
  → backend/services/cloud/azure_client.py      (OAuth2 client credentials + Log Analytics Query API, stdlib HTTPS)
  → backend/services/cloud/azure_normalizer.py  (cloud normalizer)
  → backend/services/cloud/azure_collector.py   (bounded window, dedup, insert)
  → events table: source_type=CLOUD, provider=AZURE, data_scope=PRIVATE
  → Cloud dashboard / account aggregates (?environment=CLOUD)
```

**Dependencies:** none added. The Log Analytics Query API and the Entra token endpoint are plain HTTPS/JSON, so the collector uses the Python standard library (`urllib`) instead of `azure-identity` / `azure-monitor-query`.

**Configuration** (project-root `.env`; all four are required, otherwise the status is `NOT_CONFIGURED` and the rest of the app is unaffected):

| Setting | Meaning |
|---|---|
| `AZURE_TENANT_ID` | Entra tenant (GUID or verified domain) |
| `AZURE_CLIENT_ID` | App registration (service principal) client id |
| `AZURE_CLIENT_SECRET` | Client secret (never returned, logged, or stored in events) |
| `AZURE_LOG_ANALYTICS_WORKSPACE_ID` | Workspace (customer) id GUID |

No subscription id is needed: both sources are read from the workspace.

**Minimum permissions (read-only):**
- Service principal: **Log Analytics Reader** on the workspace (or a custom role with `Microsoft.OperationalInsights/workspaces/query/read`). Owner, Contributor and Global Administrator are **not** required.
- One-time Azure-side setup by an administrator (not automated by DefenSync): an Entra ID diagnostic setting that sends `SignInLogs` to the workspace (requires Entra ID P1/P2), and a subscription diagnostic setting that sends the Activity Log (`AzureActivity`).
- The collector only issues token requests and KQL read queries; it never modifies Azure resources, users, roles, sessions, policies, or logs.

**Sources:** `ENTRA_SIGNIN` → `SigninLogs`, `AZURE_ACTIVITY` → `AzureActivity`. If a table does not exist in the workspace, that source reports `SOURCE_NOT_AVAILABLE` and the other source is still collected.

**Endpoints:**
- `GET /api/v1/cloud/azure/status` → `NOT_CONFIGURED` / `CONFIGURED` / `COLLECTION_OK` / `COLLECTION_FAILED`, plus missing/invalid setting **names** (never values) and a summary of the last run in this process.
- `POST /api/v1/cloud/azure/collect` (admin only) with `{ "account_id": "<DefenSync account>", "lookback_minutes": 15 }`, or an explicit `start_time` + `end_time`, plus optional `sources` and `max_records` (default 500, max 5000 per source). `lookback_minutes` defaults to 15 and can't exceed 1440. An explicit window can't exceed `CLOUD_COLLECTION_MAX_WINDOW_HOURS` (default 168) or start more than `CLOUD_COLLECTION_MAX_HISTORY_DAYS` (default 90) ago. The response reports `configured`, `outcome` (`SUCCESS` / `PARTIAL` / `FAILED`), `issues`, `records_retrieved`, `records_normalized`, `records_failed`, `records_inserted`, `records_deduplicated`, `collection_started_at`, `collection_completed_at`, and per-source status (including `truncated` and `resume_from`).
- Cloud sources: `POST /api/v1/cloud/sources/{id}/collect` accepts the same window options (`lookback_minutes`, or `start_time` + `end_time` for historical backfill, plus `sources` and `max_records`). Every accepted request is stored in `cloud_collection_runs` (window, rows retrieved / stored / duplicate / failed, truncation, safe error code and message, per-source results; never credentials). `GET /api/v1/cloud/sources/{id}/collections` lists runs newest first, `GET /api/v1/cloud/sources/{id}/collections/{run_id}` returns one, and each source view includes `last_collection_run`. A run is `PARTIAL` when a source was missing or failed, a source hit the row cap (collect again from `resume_from`), or rows could not be normalized; `FAILED` when nothing was retrieved.
- Dashboard → **Cloud** shows the collector status and, for admins with an account selected, a **Collect now** button (last 15 minutes).

**Normalized fields:**
- Common: `source_type=CLOUD`, `provider=AZURE`, `data_origin=AZURE_LOG_ANALYTICS`, `data_scope=PRIVATE`, `dataset_name=NULL`, `server_id=NULL`, `raw_log` = full Azure record (secret-redacted JSON).
- Sign-ins: `actor_id` = Entra object id (UPN if absent), `username` = UPN, `source_ip`, `resource_id` = app id, `resource_type=ENTRA_APPLICATION`.
- Activity: `actor_id` = caller object id / UPN / caller, `operation` = original operation name, `resource_id`, `resource_type` (e.g. `Microsoft.Compute/virtualMachines`), `hostname` = resource group.
- `normalized_data` keeps tenant, subscription, resource group, UPN, object id, app id, client app, IP, device, location, authentication result and methods, conditional access, correlation id, status, and the original operation.
- Taxonomy: `CLOUD_LOGIN_SUCCESS`, `CLOUD_LOGIN_FAILURE`, `CLOUD_AUTHENTICATION` (sign-in without a clear outcome), `CLOUD_PRIVILEGE_CHANGE`, `CLOUD_RESOURCE_OPERATION`, `CLOUD_ACTIVITY` (anything not confidently classifiable). Risk uses the existing importer convention (failed = medium/70, otherwise info/20); no new risk model.

**Timestamps:** `timestamp` = Azure event time (`CreatedDateTime` for sign-ins, else `TimeGenerated`), `collection_timestamp` = retrieval time, `timestamp_source=SOURCE_EVENT`. If the Azure time is missing or unparsable, `timestamp` falls back to collection time with `timestamp_source=COLLECTION_TIME_FALLBACK`, and the raw value stays in `raw_log` and `normalized_data.source_timestamp_raw`.

**Identity:** `owner_id` is the DefenSync admin who triggered collection, and `account_id` is the DefenSync account (access-control boundary) chosen in the request. The Azure identity is **not** stored in either column. It lives in `actor_id`, `username`, and `normalized_data.cloud_identity`, because `account_id` is the DefenSync ACL key and reusing it would break isolation. No schema change was made.

**Deduplication:** Azure rows use an isolated, account-scoped hash (`AZURE_ACCOUNT_SCOPED_V1`: account + tenant + source + Azure record id, or the canonical record when there is no id). Re-collecting an overlapping window inserts nothing new. The same Azure record collected into two DefenSync accounts stays separate per account. The global `calculate_event_hash` and all existing Linux/dataset hashes are unchanged.

**Errors:** missing configuration → `NOT_CONFIGURED`. Other failures return `COLLECTION_FAILED` with a safe code and message, never including response bodies, tokens, or secrets. Codes: `INVALID_CREDENTIALS`, `EXPIRED_CREDENTIALS`, `INVALID_TENANT`, `AUTHENTICATION_FAILED`, `INVALID_WORKSPACE`, `PERMISSION_DENIED`, `SOURCE_NOT_AVAILABLE`, `QUERY_FAILED`, `RATE_LIMITED` (with `retry_after`), `TIMEOUT`, `AZURE_UNAVAILABLE`, `MALFORMED_RESPONSE`. Malformed individual rows are counted in `records_failed` and skipped without aborting the batch.

**Live vs test:** `backend/test_azure_collector.py` drives the real collector, normalizer and storage code through a fake HTTPS transport that returns real-shaped Entra token and Log Analytics responses. That proves the logic, **not** live Azure connectivity. A live run needs the four settings above plus a workspace that receives the diagnostic exports.

## Behavioral monitoring

CSV import → `behavior_profiles` → `OverEfficiencyDetector` with human-readable reasons. Baselines exclude high-risk rows (`BEHAVIORAL_BASELINE_UPDATE_MAX_RISK`).

## Hybrid ML

- Isolation Forest: unsupervised, **does not** use rule `risk_score` as a feature.
- Random Forest: trains **only** on `original_label` (NORMAL vs ANOMALOUS/…). If no labels: RF status `no_valid_labels`.
- Models saved under `MODEL_DIR` (default `models/`). Opening Detection does **not** retrain; use **Run Detection**.
- Accuracy/F1 are reported only on labeled hold-out data.

## Correlation

Frontend `computeCorrelation` is preserved. Backend `POST /api/v1/intelligence/correlate` persists `incidents` using **event timestamps** and a 15-minute conceptual window. Intelligence prefers stored incidents when present.

### n8n incident notifications (optional)

DefenSync detects, correlates and stores incidents; n8n only formats and delivers a notification. Nothing is blocked, shut down or modified automatically.

When correlation stores a **new** incident with severity `high` or `critical`, or **escalates** an existing incident to one of them, DefenSync POSTs one JSON document (`schema_version: "defensync-incident-v1"`) to n8n. Re-running correlation or reading incidents does not resend. Delivery is one attempt on a background thread with a short timeout (`N8N_WEBHOOK_TIMEOUT_SECONDS`, default 3 s, max 10 s), at most 10 incidents per correlation run; failures (timeout, unreachable, 4xx/5xx) are logged without the URL or token and never affect incident storage.

1. **Set `N8N_WEBHOOK_URL`** in `.env` to your n8n production webhook URL (optionally `N8N_WEBHOOK_AUTH_HEADER` / `N8N_WEBHOOK_AUTH_TOKEN` for n8n Header Auth) and restart the backend. Blank means not configured; `GET /api/v1/intelligence/n8n/status` shows the state.
2. **Create an n8n workflow** with a **Webhook** trigger: method `POST`, path of your choice, Respond `Immediately`.
3. **Receive the incident JSON**: `event` (`incident.created`, `incident.escalated` or `incident.test`), `test`, `sent_at`, `notice`, and `incident` with `id`, `incident_id`, `title`, `environment`, `severity`, `risk_score`, `confidence`, `actor`, `sources`, `event_count`, `start_time`, `end_time`, `status`, `evidence_summary`, `explanation`, `recommendation`. No credentials, tokens, raw log lines or event IDs are included.
4. **Format the notification**, e.g. a Set/Code node building a subject such as `[DefenSync] {{$json.body.incident.severity}} {{$json.body.incident.title}}` and a body from `evidence_summary` and `recommendation`.
5. **Send an email** with n8n's **Send Email** (SMTP credential stored in n8n) or Gmail node.

To test without new incidents, an admin can send an existing incident: `POST /api/v1/intelligence/incidents/{incident_id}/n8n-test` (demo operation; payload has `"test": true`, nothing is created or changed).

## Risk and explainability

Rule engine: type base scores + context + `backend/risk/rules.py` recommendations.  
Behavioral: `risk_reasons` JSON.  
ML: Isolation Forest / RF messages plus optional RF feature importance.  
**SHAP/LIME are not used.** Intelligence recommendation cards remain advisory templates.

## Alerts

Created from high-risk rules and ML flags. Acknowledge still works. Extra fields: explanation, event occurrence time, confidence. Recommendations are advisory.

## Installation

PostgreSQL must be running locally. This project uses the database named in your **project-root `.env`** (`DB_NAME`). Do not copy `.env.example` over an existing working `.env` — that overwrites real credentials and causes `password authentication failed for user "postgres"`.

1. Create `.env` from the example **only if you do not already have one**, then set `DB_USER` / `DB_PASSWORD` / `DB_NAME` to your local PostgreSQL values.
2. `DB_HOST=127.0.0.1` avoids IPv4/IPv6 localhost confusion.

```powershell
cd C:\Users\Lenovo\OneDrive\Desktop\CloudSync
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
python scripts\migrate_schema.py
python -m backend.database.init_db
```

Check the connection (does not print the password):

```powershell
$env:PYTHONPATH = (Get-Location)
python scripts\check_db.py
```

### Backend

```powershell
cd C:\Users\Lenovo\OneDrive\Desktop\CloudSync
.\.venv\Scripts\Activate.ps1
python -m backend.main
```

API: http://localhost:8000  Docs: http://localhost:8000/docs  Health: http://localhost:8000/health

### Frontend

```powershell
cd C:\Users\Lenovo\OneDrive\Desktop\CloudSync\frontend
npm install
npm run dev
```

UI: http://localhost:5173 (Vite proxies `/api` and `/health` to the backend).

Accounts register with **username + email + password** and sign in with **email + password**; the username is only the display name (shown top-right). Registration is completed only by email verification: `POST /api/v1/auth/register` (202) holds a pending registration in memory (normalized email/username and a bcrypt hash, expiring with its OTP challenge) and emails a code; `POST /api/v1/auth/register/verify` (201) creates the account and signs it in. If the code cannot be sent, nothing is written and the same email can retry. `python scripts/cleanup_unverified_users.py --created-after <ISO time>` (dry run) / `--yes` removes accounts left by the old one-step registration that own no data; it never touches admins or `ADMIN_EMAIL` and refuses to run in production. The admin account is bootstrapped from `ADMIN_USERNAME`, `ADMIN_EMAIL` and `ADMIN_PASSWORD` in the local `.env` (git-ignored): at startup it is created once if no admin exists, and never duplicated or silently changed. `ADMIN_EMAIL` must be a real mailbox because the OTP goes there. To apply a changed `ADMIN_PASSWORD`, run `python -m backend.bootstrap.default_admin --reset-password`. `python scripts/reset_skeleton.py` (dry run) / `--yes` deletes all application rows (users, servers, accounts, events, alerts, detections, incidents, risk history, behavior profiles, collection runs, dataset imports) in one transaction and keeps exactly that admin; schema, `datasets/` source files and `models/` are untouched.

## Sign-in and MFA

1. `POST /api/v1/auth/token` checks the password. On success it returns an **OTP challenge** (`challenge_id`, masked destination, expiry) — **no access token**.
2. A 6-digit code (Python `secrets`) is emailed. Only an HMAC of the code is kept, in process memory.
3. `POST /api/v1/auth/otp/verify` with `challenge_id` + `otp` issues the normal JWT. API routes reject tokens that were not issued after OTP verification.

| Rule | Default (`.env`) |
|---|---|
| Code lifetime | 5 min (`OTP_EXPIRE_MINUTES`) |
| Wrong codes before the challenge is destroyed | 5 (`OTP_MAX_ATTEMPTS`) |
| Resend cooldown | 120 s (`OTP_RESEND_COOLDOWN_SECONDS`), enforced by the server on every send |
| Codes per sign-in | 3 (`OTP_MAX_SENDS`) |

`POST /api/v1/auth/otp/send` resends a code for both sign-in and registration challenges. A resend issues a new code and invalidates the previous one; requests inside the cooldown get HTTP 429 `OTP_RESEND_COOLDOWN` with `retry_after` seconds, and the challenge view reports `resend_available_in`. Starting sign-in or registration again does not reset the cooldown. If a resend cannot be delivered, the challenge (and a pending registration) is kept as it was, so the user can retry; the attempt still counts toward `OTP_MAX_SENDS`.

**Forgot password** (`/forgot-password` in the UI): `POST /api/v1/auth/password-reset/request` (email) always answers 202 with the same body ("If the account exists, a verification code has been sent to the registered email."); unknown emails get a decoy challenge that behaves identically but sends nothing, and real delivery runs after the response. `…/password-reset/resend` follows the same 120 s cooldown and send limit, `…/password-reset/verify` (challenge + code) returns a 10-minute single-use `reset_token` — not an access token — and `…/password-reset/complete` (token, new password, confirmation) applies the normal password policy, stores a bcrypt hash and cancels pending sign-in codes. Nobody is signed in by a reset: the user signs in again with email + new password and the login OTP. Reset codes are a separate purpose and cannot be used for login or registration (or the reverse).

Email delivery needs `SMTP_HOST`, `SMTP_FROM` and (for authenticated relays) `SMTP_USERNAME` / `SMTP_PASSWORD`. For Gmail use an **App Password**, not the account password. If no channel is configured, a correct password still fails with HTTP 503 `MFA_NOT_CONFIGURED` ("Two-factor verification is not configured") — MFA is never bypassed. The backend logs a startup warning naming the missing settings, and each refused sign-in logs the per-channel reason (never values). SMS goes through a provider interface, but no SMS provider is implemented, so it always reports "SMS provider not configured". Pending challenges live in memory: restarting the backend means signing in again. `scripts/qa_verify.py` and `backend/test_suite.py` sign in through the full OTP flow, reading the code from a local QA mailbox (`backend/testing/otp_mailbox.py`, 127.0.0.1 only). For those runs start the backend with `SMTP_HOST=127.0.0.1 SMTP_PORT=2525 SMTP_SECURITY=none SMTP_FROM=defensync-qa@localhost` as process environment (not in `.env`); `QA_SMTP_PORT` changes the mailbox port. `QA_OTP_SOURCE=prompt python scripts/qa_verify.py` instead asks for the code from a real inbox.

## Linux and Cloud workspaces

After the code is verified, analysts choose **Linux** or **Cloud**. The sidebar has a permanent **LINUX / CLOUD** switch; switching does not sign you out.

- **Linux**: Dashboard, Servers, Events, Alerts, Detection, Intelligence (and Collection for admins).
- **Cloud**: Dashboard, Cloud Accounts, Events, Alerts, Intelligence.

Choosing an environment always opens its dashboard. The dashboard shows `Linux · Servers: N` or `Cloud · Cloud Accounts: N` with a permanent **+ Add Server** (`/servers/new`) or **+ Add Cloud Account** (`/cloud-accounts/new`) button. With zero resources it shows a prominent empty state instead ("No Linux servers configured" / "No Cloud Accounts configured"). On an Add screen, Cancel (or browser Back) returns to Environment Selection, and a successful creation opens the dashboard. The sidebar's LINUX/CLOUD switch changes environment at any time. In the Cloud workspace, the header shows `Azure · Connected` when at least one accessible cloud source is connected, otherwise `Azure · Not connected`.

**Cloud sources** (`cloud_sources` table, created automatically at startup; no existing table changes) are account-owned, using the same ownership rule as Linux servers. ADMIN sees all of them and may assign a source to an account. The first supported source is Microsoft Azure → Azure Log Analytics (Tenant ID, Client ID, Client Secret, Workspace ID):
- `GET /api/v1/cloud/sources` lists the sources you can access. `GET /api/v1/cloud/sources/{id}` returns one source's status. Sources owned by another account return 404.
- `POST /api/v1/cloud/sources/test-connection` tests unsaved credentials. It is read-only: it requests a token and runs the constant query `print connection_test = 1` against the workspace, and it stores nothing.
- `POST /api/v1/cloud/sources` runs the same connection test first. The source is saved, with status `CONNECTED`, only if the test succeeds; otherwise the response is 422 `CLOUD_CONNECTION_FAILED` with a safe Azure error code.
- `POST /api/v1/cloud/sources/{id}/test-connection` re-tests a saved source. `POST /api/v1/cloud/sources/{id}/collect` runs **Collect Now** with the existing collector, writing into the source's account and recording last-collection status, error and time. `DELETE /api/v1/cloud/sources/{id}` is admin only, matching server deletion.
- The client secret is Fernet-encrypted with the same helper used for SSH credentials. It is never returned (responses show only `client_secret_configured`), never logged, never put in a URL, and never kept in browser storage.

The server `.env` Azure settings above still drive the admin-only `/cloud/azure/*` endpoints. Admin → Cloud Accounts shows that collector only when it is configured.

Pages pass `?environment=LINUX|CLOUD` to the API. The selection only changes what is shown; the backend still enforces account ownership on every request.

### Demo data

- Intelligence: **Load Behavioral Demo Data**, **Load OpenStack Demo Data**
- Detection: **Run Detection** after events exist
- Azure file: place exported Activity Log / sign-in JSON or CSV files under `datasets/Azure/` and `POST /api/v1/datasets/azure/import` with `{ "path": "<file relative to datasets/Azure>" }`. Paths outside that directory (`../`, absolute paths, symlink/junction escapes) are rejected.

## Limitations

- Live Linux requires reachable SSH hosts.
- Scheduler is **off** by default (`SCHEDULER_ENABLED=false`).
- Cloud: OpenStack/HDFS/BGL are dataset/file imports. Live Azure collection is manual (no scheduler), uses a single Log Analytics workspace in the Azure public cloud, and keeps no persisted collection cursor (the last run summary is process-local). There's no subscription filter (the workspace decides what's exported). Sign-ins with any non-zero `ResultType` count as failures (this includes MFA interrupts). Duplicates do not refresh `collection_timestamp`. Only admins can trigger collection.
- RF metrics are N/A without `original_label`.
- No automatic blocking or isolation.

## Research contribution

The prototype demonstrates hybrid Linux–cloud normalization, behavioral baselines, cross-source temporal correlation, sequential incident timelines, unsupervised + labeled classification, 0–100 risk, explainable (rule/behavioral/ML) decisions, and **correct source-event timestamps**.

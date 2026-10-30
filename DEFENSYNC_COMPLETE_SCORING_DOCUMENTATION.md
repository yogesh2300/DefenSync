# DefenSync Complete Security Scoring Documentation

**Document type:** Source-code audit (read-only)  
**Scope:** Linux live collection, Azure Log Analytics live + file import, presentation/demo telemetry, dashboard aggregation, ML/behavioral/incident scores  
**Accuracy rule:** Only values and formulas found in source are documented. Gaps are labeled explicitly.

---

## 1. Architecture overview

DefenSync stores a per-event integer `risk_score` (0–100) on `events`. Different pipelines assign that score differently:

| Pipeline | Who assigns `event.risk_score` | Uses `RiskEngine`? |
|----------|--------------------------------|--------------------|
| Live Linux (SSH collect → parse → store) | `RiskScoreCalculator` + `DEFAULT_RULES` via `TransformService.enrich_events` | **Yes** |
| Standalone `EventNormalizer(score_risk=True)` | `RiskScoreCalculator` only (no rules) | No |
| Azure live LA (`azure_normalizer`) | Binary: failed → 70, else 20 | **No** |
| Azure file import (`azure_import_service`) | Same binary: failed → 70, else 20 | **No** |
| Azure presentation telemetry | Fixed per demo step | **No** |
| Linux presentation trigger | Fixed 80 | **No** |
| OpenStack / BGL / HDFS dataset import | Severity / failure-token maps | **No** |
| Behavioral analysis (BEHAVIORAL source) | `OverEfficiencyDetector` overwrites `risk_score` | **No** |

The **primary dashboard / Intelligence account score** is backend `average_risk_score` = rounded average of in-scope security-event `risk_score` values. It is **not** ML anomaly score, investigation confidence, or the composite `account_risk` field.

---

## 2. Linux scoring — complete breakdown

### 2.1 Execution order (live pipeline)

1. Parse logs (`pipeline_service` / parsers).
2. Normalize with `EventNormalizer(score_risk=False)` → placeholder `risk_score=0`, severity `info` (`event_normalizer.py`).
3. Optional login-history / snapshot builders may temporarily set placeholders (0 / 10 / 55 / 15) in `pipeline_service.py`.
4. `TransformService.enrich_events` → for each event:
   - `RiskEngine.build_context(...)`
   - `RiskEngine.enrich(...)`:
     1. Base = `RiskScoreCalculator.calculate(event_type, is_root, is_privileged_user, is_remote)`
     2. Default severity from `DEFAULT_SEVERITY`
     3. **Every matching rule** in `DEFAULT_RULES` is applied; deltas **add**; severity may escalate if rule severity ranks higher
     4. Clamp score to **[0, 100]**
     5. Set `metadata.risk_level` via `risk_level_from_score`
5. Persist enriched `risk_score` / `severity` on `events`.

**Multiple rules can apply** to the same event (additive). Example: remote root successful login gets calculator bonuses **and** `RootLoginRule` (+20) **and** `SshSuccessRule` (+0 factor only).

### 2.2 Base scores and default severities

Source: `backend/normalizer/severity.py` — `BASE_RISK_SCORE`, `DEFAULT_SEVERITY`.

| Event type | Base score | Default severity |
|------------|------------|------------------|
| Failed Login | 65 | high |
| Successful Login | 20 | low |
| Invalid User | 70 | high |
| User Creation | 70 | high |
| User Deletion | 85 | critical |
| Sudo Command | 55 | medium |
| File Modification | 45 | medium |
| Directory Creation | 30 | low |
| Permission Change | 60 | high |
| Command Execution | 40 | low |
| Privilege Escalation | 50 | medium |
| Failed Privilege Escalation | 60 | high |
| Session Opened | 10 | low |
| Session Closed | 5 | low |
| System Snapshot | 0 | low |
| System Event | 10 | low |
| **Unmapped `EventType`** | **50** | **medium** |

### 2.3 Context modifiers (`RiskScoreCalculator.calculate`)

| Modifier | Delta | Applies when |
|----------|-------|--------------|
| `is_root` | +10 | Root / uid 0 (metadata or username) |
| `is_privileged_user` | +5 | In live engine, set equal to `is_root` (`RiskEngine.build_context`) |
| `is_remote` | +5 | Only for: Failed Login, Successful Login, Invalid User, Sudo Command, Command Execution |

Clamp after modifiers: 0–100.

**Note:** For root events, live path effectively adds **+15** (+10 root + +5 privileged) before rules.

### 2.4 Risk rules (`backend/risk/rules.py` → `DEFAULT_RULES`)

| Rule | Event type | Score delta | Severity override | Condition |
|------|------------|-------------|-------------------|-----------|
| `FailedLoginRule` | Failed Login | **0** | — | Always (factor/recommendation only) |
| `MultipleFailedLoginRule` | Failed Login | **+15** | HIGH | `failed_login_count >= 3` (batch context from pipeline) |
| `RootLoginRule` | Successful Login | **+20** | HIGH | username in `{root,0}` or `context.is_root` |
| `SshSuccessRule` | Successful Login | **0** | — | `source_ip` or `is_remote` (factor only) |
| `SuspiciousSudoRule` | Sudo Command | **+10** | HIGH | cmd/proctitle contains sensitive token |
| `SuspiciousSudoRule` | Sudo Command | **+5** | MEDIUM | Not sensitive, but root user |
| `NewUserCreationRule` | User Creation | **+5** | HIGH | Always |

Sensitive sudo tokens: `chmod`, `chown`, `useradd`, `userdel`, `passwd`, `visudo`, `iptables`, `firewall-cmd`, `rm`, `mkfs`, `dd`, `curl`, `wget`.

**No dedicated rules** for: User Deletion, File Modification, Directory Creation, Permission Change, Command Execution, Privilege Escalation, Failed Privilege Escalation, Session Opened/Closed, System Snapshot/Event (beyond base + context).

### 2.5 Linux score → `risk_level` string

`backend/risk/levels.py` `risk_level_from_score`:

| Score | risk_level |
|-------|------------|
| ≥ 85 | critical |
| ≥ 70 | high |
| ≥ 40 | medium |
| else | low |

### 2.6 Pipeline placeholders (not final)

`pipeline_service.py` may seed:

| Source | Placeholder before enrich |
|--------|---------------------------|
| Snapshot commands | System Snapshot / 0 |
| reboot/shutdown pseudo | System Event / 10 |
| `lastb` | Failed Login / 55 |
| `last`/`who`/`w` | Successful Login / 15 |

These are **replaced** by RiskEngine before durable storage on the live enrich path.

---

## 3. Azure / Cloud scoring

### 3.1 Event taxonomy (classification ≠ score)

`backend/services/datasets/azure_import_service.py` → `classify_azure_event`:

| Condition | Event type |
|-----------|------------|
| Sign-in + failed | `CLOUD_LOGIN_FAILURE` |
| Sign-in + success | `CLOUD_LOGIN_SUCCESS` |
| Sign-in + unknown outcome | `CLOUD_AUTHENTICATION` |
| Privilege ops / prefixes | `CLOUD_PRIVILEGE_CHANGE` |
| ARM `…/(write\|delete\|action)` | `CLOUD_RESOURCE_OPERATION` |
| Else | `CLOUD_ACTIVITY` |

Privilege detection (type only):

- Exact ops: `microsoft.authorization/elevateaccess/action`, `add member to role`, `remove member from role`
- Prefixes: `microsoft.authorization/roleassignments/`, `microsoft.authorization/roledefinitions/`

### 3.2 Live Azure score (`azure_normalizer.normalize_record`)

```text
risk_score = 70 if failed else 20
severity   = "medium" if failed else "info"
```

**Failed detection:**

| Source | Failed when |
|--------|-------------|
| Entra sign-in | Outcome present and ≠ `"0"`; unknown outcome → `failed=False` → **20** |
| Activity | `ActivityStatus` lowercased in `{failed, failure}` |

**Operation type does not change the numeric score.** A successful Owner role assignment scores **20**; a failed benign activity scores **70**.

### 3.3 Azure file import (`AzureActivityLogImportService._normalize`)

Identical numeric rule: `risk = 70 if failed else 20` with `failed = status in {failed,failure} OR sign_in_failed is True`.

Live and file import are **consistent** on the binary rule. They share `classify_azure_event` for types.

### 3.4 Inconsistency / gap (documented, not invented)

Azure taxonomy distinguishes privilege vs resource vs activity, but **live scoring ignores that distinction**. Presentation telemetry (below) uses richer fixed scores; live LA does not.

---

## 4. Presentation / demo scoring

Simulated rows use `data_origin=PRESENTATION_SIMULATED`. They are private/account-scoped and **can** enter `average_risk_score` if they are security event types in scope (they are not System Snapshot/Event).

### 4.1 Linux presentation trigger

| Operation | Event type | Score | Severity | Source |
|-----------|------------|-------|----------|--------|
| Simulated privileged sudo | Sudo Command | **80** | high | `linux_presentation_trigger.py` `RISK_SCORE=80` |

Triggered after N successful manual collections for allow-listed presentation emails (separate presentation counter; not the n8n alternate-success counter).

### 4.2 Azure presentation steps (`presentation_telemetry.py`)

| Operation | Typical classify type | Score | Severity |
|-----------|----------------------|-------|----------|
| Sign-in activity | CLOUD_LOGIN_SUCCESS | 20 | info |
| Add application | CLOUD_ACTIVITY / resource-like | 30 | low |
| Add service principal | | 30 | low |
| Update application – certificates/secrets | | 45 | medium |
| `roleAssignments/write` (Reader) | CLOUD_PRIVILEGE_CHANGE | 55 | medium |
| `workspaces/write` | CLOUD_RESOURCE_OPERATION | 25 | low |
| `diagnosticSettings/write` | CLOUD_RESOURCE_OPERATION | 35 | low |
| `elevateAccess/action` | CLOUD_PRIVILEGE_CHANGE | 60 | medium |
| Failed Owner `roleAssignments/write` (trigger) | CLOUD_PRIVILEGE_CHANGE | **70** | medium (live failed) |

These are **fixed** step scores, not the live Azure 20/70 rule.

---

## 5. Primary dashboard score

### 5.1 Storage

- Column: `events.risk_score` (`backend/database/models.py` `Event` / `SecurityEvent`)
- Also: `risk_level`, `severity`, optional `behavioral_risk_score`

### 5.2 Aggregation formula

`backend/database/crud.py` → `dashboard_summary`:

```text
average_risk_score = int(round(AVG(risk_score)))
  WHERE event_type NOT IN ("System Snapshot", "System Event")
  AND visibility/environment/account filters apply

high_risk = COUNT where security event AND risk_score >= 70
max_risk_score = MAX(security event risk_score)
```

Consumed by:

- `DashboardService` → `GET /api/v1/dashboard`
- `AccountService.summary` → `GET /api/v1/account/summary` field `average_risk_score`

### 5.3 Frontend primary score

- `frontend/src/intelligence/primaryScore.js` → `resolvePrimarySecurityScore`
- Display: `Dashboard.jsx` `RiskWidget`, Intelligence page
- Source of truth: backend `average_risk_score`
- Fallback: **unavailable** (does not invent 0 as “safe”) when no usable source / empty scope
- UI severity bands for the **displayed average**: ≥80 Critical, ≥60 High, ≥40 Medium, else Low (`primaryScoreSeverity`) — **differs from** backend `risk_level_from_score` bands

### 5.4 Related but different aggregates

| Metric | Formula | Includes System Snapshot? | Primary UI? |
|--------|---------|---------------------------|-------------|
| `average_risk_score` | AVG security events, exclude Snapshot/Event | No | **Yes** |
| `account_risk` | `round(avg*0.4 + min(40, high_risk/50) + min(30, anomalies/40))` | Uses avg of security events | **No** |
| Server avg (`average_risk_for_server`) | `round(AVG(all server events))` | **Yes (no exclusion)** | Server cards only |
| Admin user detail avg | `AVG(owner events)` | **Yes (no exclusion)** | Admin only |

---

## 6. Score kinds — does each affect primary dashboard score?

| Kind | Definition | Affects `average_risk_score`? |
|------|------------|-------------------------------|
| Event `risk_score` | Per-event score | **Yes** (input to AVG) |
| Dashboard `average_risk_score` | AVG of security events | **This is the primary score** |
| Composite `account_risk` | Weighted avg + high-risk count + anomaly counts | **No** |
| ML `anomaly_score` | `-IsolationForest.score_samples` (higher = more anomalous) | **No** (features exclude risk_score; does not rewrite event risk) |
| ML alert `risk_score` | Copies `event.risk_score` (no floor); IF strength in `confidence` / `anomaly_score` | **No** (event unchanged) |
| Behavioral `risk_score` | Detector weights; **overwrites** BEHAVIORAL event `risk_score` | Only if those rows are in private Linux/Cloud AVG scope (typically GLOBAL BEHAVIORAL → out of private env averages) |
| Incident `risk_score` | `min(100, round(confidence*0.45 + max_risk*0.55))` | **No** |
| Investigation `confidence` | Evidence/high-risk based 0–100 | **No** |

---

## 7. ML and behavioral scoring

### 7.1 Linux Isolation Forest

- `backend/ml/linux_isolation_forest.py`: `anomaly_score = -score_samples(x)`
- Explicitly does **not** use `risk_score` / severity for baseline or threshold (`test_linux_detection.py` asserts this)
- Writes `Detection` rows; may create ML alerts

### 7.2 ML alerts

`AlertService.create_ml_alert`: preserves `event.risk_score` and `event.severity` on the Alert row; stores Isolation Forest strength in `confidence`. API `serialize_alert` exposes `event_risk_score`, `anomaly_score`, and `alert_priority` separately. Legacy rows that stored `risk_score=75` / `severity=high` are corrected at presentation via linked event risk (historical rows are not rewritten).

### 7.3 Behavioral / over-efficiency

`OverEfficiencyDetector.evaluate` accumulates weighted signals (typing +20, command_rate +25, etc.), clamps 0–100, then `BehaviorAnalysisService.analyze_event` sets:

- `event.behavioral_risk_score = result.risk_score`
- `event.risk_score = result.risk_score` (**overwrite**)
- Behavioral `_risk_level`: ≥85 critical, ≥70 high, ≥50 medium, ≥30 low, else **info** (differs from `levels.py`)

Classification bands (`classification_for`): ≥85 AUTOMATED_ACTIVITY, ≥70 OVER_EFFICIENCY, ≥50 SUSPICIOUS_BEHAVIOR, ≥30 UNUSUAL_SESSION, else NORMAL.

### 7.4 Dataset imports (not live Azure LA)

| Helper | Failure override | Severity map |
|--------|------------------|--------------|
| `streaming_import.risk_score_for` | type contains FAILURE/EXCEPTION/AUTHORIZATION/LOGIN_FAILURE → 70 | critical 85, high 70, medium 45, low 20, info 5, default 5 |
| `openstack_import_service._risk_score_for` | CLOUD_*_FAILURE types → 70 | same map |

Used by BGL/HDFS/OpenStack importers — separate from Azure LA live scoring.

---

## 8. Risk level / threshold inconsistencies

| Consumer | Low | Medium | High | Critical | Notes |
|----------|-----|--------|------|----------|-------|
| Backend `risk_level_from_score` | <40 | ≥40 | ≥70 | ≥85 | Event metadata |
| Frontend primary badge | <40 | ≥40 | ≥60 | ≥80 | **Different high/critical** |
| Alerts high-risk sync | — | — | ≥70 | — | `HIGH_RISK_THRESHOLD=70` |
| Correlation incident severity | — | else | max_risk≥70 | max_risk≥85 | |
| Behavioral `_risk_level` | ≥30 | ≥50 | ≥70 | ≥85 | Has **info** below 30 |
| Azure live severity labels | — | failed→medium | — | — | success→**info** (not low) |

---

## 9. Operation-wise master tables

### 9.1 Linux (live RiskEngine path)

| Environment | Operation | Event Type | Base Score | Modifiers | Final Score/Formula | Severity | Source File |
|-------------|-----------|------------|------------|-----------|---------------------|----------|-------------|
| Linux | Failed auth | Failed Login | 65 | +10 root; +5 priv; +5 remote; +15 if failures≥3 | `clamp(base+mods+rules)` | default high; rules may set HIGH | `severity.py`, `rules.py`, `engine.py` |
| Linux | SSH success | Successful Login | 20 | +10/+5 root; +5 remote; +20 root login rule | same | default low; root→HIGH | same |
| Linux | Invalid user | Invalid User | 70 | +10/+5 root; +5 remote | same | high | `severity.py` |
| Linux | useradd-like | User Creation | 70 | context; **+5** rule always | same | high | `NewUserCreationRule` |
| Linux | userdel-like | User Deletion | 85 | context only | same | critical | `severity.py` |
| Linux | sudo | Sudo Command | 55 | context; +10 sensitive / +5 root-non-sensitive | same | medium→HIGH if sensitive | `SuspiciousSudoRule` |
| Linux | priv esc | Privilege Escalation | 50 | context (+10/+5 if root) | same | medium | no dedicated rule |
| Linux | failed priv esc | Failed Privilege Escalation | 60 | context | same | high | no dedicated rule |
| Linux | file change | File Modification | 45 | context (no remote bonus) | same | medium | no dedicated rule |
| Linux | mkdir | Directory Creation | 30 | context | same | low | no dedicated rule |
| Linux | chmod/chown audit | Permission Change | 60 | context | same | high | no dedicated rule |
| Linux | process | Command Execution | 40 | +5 remote; root bonuses | same | low | no dedicated rule |
| Linux | session open | Session Opened | 10 | root bonuses | same | low | no dedicated rule |
| Linux | session close | Session Closed | 5 | root bonuses | same | low | no dedicated rule |
| Linux | snapshot | System Snapshot | 0 | — | 0; **excluded from AVG** | low | `NON_SECURITY_EVENT_TYPES` |
| Linux | system | System Event | 10 | — | 10; **excluded from AVG** | low | same |
| Linux | unmapped | *(other)* | 50 | modifiers if flags set | clamp | medium | `calculate` fallback |

### 9.2 Azure Live (Log Analytics)

| Environment | Operation | Event Type | Base Score | Modifiers | Final Score/Formula | Severity | Source File |
|-------------|-----------|------------|------------|-----------|---------------------|----------|-------------|
| Azure Live | Entra sign-in success | CLOUD_LOGIN_SUCCESS | — | — | **20** | info | `azure_normalizer.py` |
| Azure Live | Entra sign-in failure | CLOUD_LOGIN_FAILURE | — | — | **70** | medium | same |
| Azure Live | Entra sign-in unknown | CLOUD_AUTHENTICATION | — | — | **20** | info | same |
| Azure Live | Privilege op success | CLOUD_PRIVILEGE_CHANGE | — | type only | **20** | info | classify + binary score |
| Azure Live | Privilege op failed | CLOUD_PRIVILEGE_CHANGE | — | — | **70** | medium | same |
| Azure Live | ARM write/delete/action success | CLOUD_RESOURCE_OPERATION | — | — | **20** | info | same |
| Azure Live | ARM write/delete/action failed | CLOUD_RESOURCE_OPERATION | — | — | **70** | medium | same |
| Azure Live | Other activity success | CLOUD_ACTIVITY | — | — | **20** | info | same |
| Azure Live | Other activity failed | CLOUD_ACTIVITY | — | — | **70** | medium | same |

### 9.3 Azure File Import

Same formulas as §9.2 (`azure_import_service._normalize`). Operation taxonomy shared via `classify_azure_event`.

### 9.4 Presentation / Demo

| Environment | Operation | Event Type | Base Score | Modifiers | Final | Severity | Source File |
|-------------|-----------|------------|------------|-----------|-------|----------|-------------|
| Linux presentation | Simulated sudo | Sudo Command | 80 | none | 80 | high | `linux_presentation_trigger.py` |
| Azure presentation | Sign-in | CLOUD_LOGIN_SUCCESS | 20 | none | 20 | info | `presentation_telemetry.SETUP_STEPS` |
| Azure presentation | Add application | (classified) | 30 | none | 30 | low | same |
| Azure presentation | Add service principal | | 30 | none | 30 | low | same |
| Azure presentation | Client secret update | | 45 | none | 45 | medium | same |
| Azure presentation | Reader roleAssignments/write | CLOUD_PRIVILEGE_CHANGE | 55 | none | 55 | medium | same |
| Azure presentation | workspaces/write | CLOUD_RESOURCE_OPERATION | 25 | none | 25 | low | same |
| Azure presentation | diagnosticSettings/write | CLOUD_RESOURCE_OPERATION | 35 | none | 35 | low | same |
| Azure presentation | elevateAccess/action | CLOUD_PRIVILEGE_CHANGE | 60 | none | 60 | medium | same |
| Azure presentation | Failed Owner roleAssignments/write | CLOUD_PRIVILEGE_CHANGE | 70 | none | 70 | medium | `_trigger_payload` via `azure_normalizer` |

---

## 10. Worked examples (from implementation)

Assumptions stated; scores clamped to [0,100].

### Example 1 — Normal successful Linux login (non-root, no IP)

- Base 20; no modifiers; no matching score rules (SshSuccess needs remote)
- **Final = 20**, severity low

### Example 2 — Successful login, remote IP, non-root

- Base 20 + remote 5 = **25**; SshSuccessRule +0
- **Final = 25**

### Example 3 — Root login, remote

- Base 20 + root 10 + privileged 5 + remote 5 = 40; RootLoginRule +20; SshSuccess +0
- **Final = 60**, severity HIGH

### Example 4 — Single failed login, remote, failed_login_count=1

- Base 65 + remote 5 = 70; MultipleFailedLoginRule does not fire
- **Final = 70**

### Example 5 — Failed login, remote, failed_login_count=3

- Base 65 + 5 + MultipleFailedLoginRule 15 = **85**

### Example 6 — Invalid user, remote

- Base 70 + remote 5 = **75**

### Example 7 — Sudo `chmod 777 /tmp/x` as alice (non-root, no remote bonus for sudo? remote **does** apply to Sudo)

- Base 55 + remote 5 (if IP) + SuspiciousSudo +10 = **70** with IP; **65** without IP

### Example 8 — User Deletion as non-root

- Base **85**; no deletion rule
- **Final = 85**, severity critical

### Example 9 — Successful Azure Entra sign-in

- failed=False → **20**, severity info

### Example 10 — Failed Azure Entra sign-in

- failed=True → **70**, severity medium

### Example 11 — Failed Azure `roleAssignments/write`

- Type CLOUD_PRIVILEGE_CHANGE; failed → **70** (not presentation 55/80)

### Example 12 — System Snapshot on Linux

- Score **0**; **excluded** from `average_risk_score`

---

## 11. Source evidence index

| Topic | File | Symbol | Notes |
|-------|------|--------|-------|
| Base map | `backend/normalizer/severity.py` | `BASE_RISK_SCORE` L53–70 | Direct |
| Calculator | same | `RiskScoreCalculator.calculate` L91–119 | Direct |
| Rules | `backend/risk/rules.py` | `DEFAULT_RULES` | Direct |
| Engine order | `backend/risk/engine.py` | `enrich` L42–89 | Direct; multi-rule additive |
| Pipeline enrich | `backend/services/transform_service.py` | `enrich_events` L134–148 | Direct |
| Unscored placeholder | `backend/normalizer/event_normalizer.py` | `_UNSCORED_RISK_SCORE=0` | Direct |
| Azure binary score | `backend/services/cloud/azure_normalizer.py` | L92–93 | Direct; tested |
| Azure classify | `backend/services/datasets/azure_import_service.py` | `classify_azure_event` L345–356 | Direct |
| Azure import score | same `_normalize` L300–327 | Direct |
| Dashboard AVG | `backend/database/crud.py` | `dashboard_summary` L238–282 | Direct; env tests |
| Primary UI | `frontend/src/intelligence/primaryScore.js` | entire module | Direct; frontend tests |
| account_risk | `backend/services/account_service.py` | `_compute_account_risk` L187–192 | Direct |
| Incident score | `backend/services/correlation_service.py` | `_incident_from_cluster` L369–399 | Direct |
| ML anomaly | `backend/ml/linux_isolation_forest.py` | `anomaly_scores` | Direct |
| ML alert floor | `backend/services/alert_service.py` | `create_ml_alert` L92 | Direct |
| Behavioral overwrite | `backend/services/behavioral/behavior_analysis_service.py` L61–63 | Direct |
| Presentation Azure | `backend/services/cloud/presentation_telemetry.py` L72–92 | Direct; tests |
| Presentation Linux | `backend/services/linux_presentation_trigger.py` | `RISK_SCORE=80` | Direct; tests |

### Test evidence (non-exhaustive)

| Test file | What it verifies |
|-----------|------------------|
| `backend/test_azure_collector.py` | Failed Azure → medium/70 |
| `backend/test_environment_aggregates.py` | Env-scoped `average_risk_score` |
| `backend/test_presentation_telemetry.py` | Presentation trigger score 80 |
| `backend/test_presentation_demo_trigger.py` | Linux presentation Sudo 80 |
| `backend/test_linux_detection.py` | risk_score does not drive IF baseline |
| `frontend/tests/primaryScore.test.js` | Primary = average_risk_score; UI bands |

### Coverage gaps

1. No unit test asserts every `BASE_RISK_SCORE` row through full RiskEngine.
2. Azure privilege success scoring at 20 is implemented but may surprise vs presentation fixed scores — **by design in code**, not a silent bug claim.
3. Server/admin averages omit Snapshot exclusion used by dashboard — inconsistency.
4. Frontend critical/high thresholds (80/60) ≠ backend (85/70).
5. Cloud sequence detection assigns finding severity only; **no finding risk_score**.

---

## 12. Related dataset scoring (inspected, not Azure LA)

Documented for completeness so they are not mistaken for live Azure:

- `streaming_import.risk_score_for` / OpenStack `_risk_score_for`: failure types → 70; else severity map 85/70/45/20/5.

---

*End of technical scoring audit.*

# DefenSync Scoring — Explained for Viva

Simple English guide based on the **actual code**. Use this to explain the project to an examiner. For full tables and file paths, see `DEFENSYNC_COMPLETE_SCORING_DOCUMENTATION.md`.

---

## 1. One-sentence summary

**Every security log becomes an event with a risk number from 0 to 100. The big number on the Dashboard is the average of those event scores (excluding system noise). Machine learning and investigation confidence are separate and do not replace that average.**

---

## 2. How a Linux log gets a score

1. DefenSync collects logs over SSH and parses them.
2. It classifies the line into a type (for example Failed Login or Sudo Command).
3. It starts from a **fixed base score** for that type (example: Failed Login = 65, Successful Login = 20).
4. It may add small bonuses (root user, remote IP).
5. It may add rule bonuses (many failed logins, root login, suspicious sudo, new user).
6. The final number is kept between 0 and 100 and stored on the event.

**Important:** Several rules can fire on the same event; their points **add up**.

### Easy base-score memory aids

| What happened | Base score (approx meaning) |
|---------------|-----------------------------|
| Session closed | 5 — almost noise |
| Successful login | 20 — normal |
| Sudo | 55 — worth watching |
| Failed login | 65 — concerning |
| Invalid user | 70 — attack probing |
| User deletion | 85 — very serious |
| System snapshot | 0 — not used in the dashboard average |

---

## 3. How Azure cloud logs get a score

Live Azure scoring is **simpler** than Linux:

- If the operation/sign-in **failed** → score **70**
- If it **succeeded** (or outcome unknown for sign-in) → score **20**

DefenSync still **labels** the event (login failure, privilege change, resource operation, etc.), but that **label does not change the number** for live Azure. A successful role assignment is still 20. A failed activity is still 70.

**Do not confuse this with demo/presentation Azure events**, which use fixed scores like 55 or 80 for story steps.

---

## 4. What the Dashboard number really is

Displayed as **Account / system risk**:

```text
average of risk_score for security events in your account/environment
(excluding "System Snapshot" and "System Event")
rounded to a whole number
```

### What it is **not**

| People sometimes think… | Actually… |
|-------------------------|-----------|
| It is the Isolation Forest anomaly score | No — ML is separate |
| It is investigation confidence | No — that is for incidents |
| It is `account_risk` | No — that is a different composite field |
| Zero means “safe” when empty | Frontend treats missing data as **unavailable**, not zero-risk |

---

## 5. Ten viva-friendly examples

1. **Normal user SSH success, no IP flags** → about **20**
2. **Same login from a remote IP** → **25** (20 + 5 remote)
3. **Root SSH success from remote** → **60** (20 + 10 + 5 + 5 + 20 root rule)
4. **One failed password, remote** → **70** (65 + 5)
5. **Three-or-more failed logins in the batch** → **85** (65 + 5 + 15)
6. **Invalid user, remote** → **75**
7. **Sudo running `chmod` (sensitive)** → mid-60s to 70 depending on remote/root
8. **User deletion** → **85**
9. **Azure sign-in success** → **20**
10. **Azure sign-in failure** → **70**

---

## 6. How to draw it on a whiteboard

```text
Linux log ──► type ──► base score ──► + context ──► + rules ──► store risk_score
Azure log ──► failed? ──► 70 : 20 ───────────────────────────► store risk_score
                                    │
                                    ▼
              AVG(security events) = Dashboard primary score
                                    │
              ML / incidents / confidence ──► other screens (not this average)
```

---

## 7. Common viva Q&A

**Q: Why is successful Azure privilege change only 20?**  
A: Live Azure code only checks failure vs success. Operation name sets the *type*, not the *score*. Demo telemetry uses higher fixed scores for storytelling.

**Q: Can ML change the event risk score?**  
A: Isolation Forest does not rewrite Linux/Azure event risk. It stores detections and may create alerts. Behavioral analysis can overwrite scores for **behavioral** dataset events.

**Q: Do System Snapshot events pull the average down?**  
A: No. Dashboard average excludes System Snapshot and System Event.

**Q: What is high risk?**  
A: Events with `risk_score >= 70` count as high-risk for alerts and dashboard counters. The frontend badge for the *average* uses slightly different cutoffs (60 high, 80 critical).

**Q: Why might server risk differ from dashboard risk?**  
A: Server average currently averages **all** events for that server and does **not** exclude snapshots the same way the dashboard does.

**Q: Is presentation data real attacks?**  
A: No. It is marked `PRESENTATION_SIMULATED` for demos. It can still appear in averages if it is in scope.

**Q: Where is the source of truth for the big number?**  
A: Backend `average_risk_score` from `dashboard_summary` / account summary. Frontend `primaryScore.js` only displays it.

**Q: Can multiple Linux rules stack?**  
A: Yes. The risk engine walks all default rules and adds every matching delta.

---

## 8. What to say if asked “is scoring complete?”

Honest answer from the audit:

- Linux has a full base map + context + additive rules.
- Live Azure is intentionally binary (20/70).
- Presentation uses separate fixed scores.
- ML and investigation are parallel tracks.
- Some UI thresholds differ from backend event levels.
- Not every base score has its own unit test; the map lives in `severity.py`.

Accuracy beats marketing: explain what the code does, not what a perfect SIEM might do.

---

## 9. Files to open during viva

1. `backend/normalizer/severity.py` — Linux base scores  
2. `backend/risk/rules.py` — Linux rule bonuses  
3. `backend/risk/engine.py` — order of calculation  
4. `backend/services/cloud/azure_normalizer.py` — Azure 20/70  
5. `backend/database/crud.py` — `dashboard_summary` average  
6. `frontend/src/intelligence/primaryScore.js` — what the UI shows  

---

*Aligned with source audit in `DEFENSYNC_COMPLETE_SCORING_DOCUMENTATION.md`.*

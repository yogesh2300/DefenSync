"""Patch DefenSync_ML_Analysis.ipynb for MCA review improvements."""
from __future__ import annotations

import json
import uuid
from pathlib import Path

NOTEBOOK = Path(__file__).resolve().parent.parent / "DefenSync_ML_Analysis.ipynb"


def cell_id() -> str:
    return uuid.uuid4().hex[:8]


def md(source: str) -> dict:
    return {"cell_type": "markdown", "id": cell_id(), "metadata": {}, "source": source.splitlines(keepends=True)}


def code(source: str) -> dict:
    return {
        "cell_type": "code",
        "id": cell_id(),
        "metadata": {},
        "outputs": [],
        "execution_count": None,
        "source": source.splitlines(keepends=True),
    }


def set_source(nb: dict, idx: int, text: str) -> None:
    nb["cells"][idx]["source"] = text.splitlines(keepends=True)
    if nb["cells"][idx]["cell_type"] == "code":
        nb["cells"][idx]["outputs"] = []
        nb["cells"][idx]["execution_count"] = None


def main() -> None:
    nb = json.loads(NOTEBOOK.read_text(encoding="utf-8"))

    if any("Section 14 — Key Findings" in "".join(c.get("source", [])) for c in nb["cells"]):
        print("Notebook already patched — skipping duplicate Section 14.")
        return

    # --- Section 0: title ---
    set_source(
        nb,
        0,
        """# DefenSync — Machine Learning Analysis

**Project:** DefenSync (CloudSync) — Behavioral Log Intelligence Platform  
**Notebook:** `DefenSync_ML_Analysis.ipynb`  
**Purpose:** Reproduce and document the **exact** hybrid ML pipeline implemented in `backend/services/detection_service.py` using live PostgreSQL data.

> **Note:** This notebook mirrors production logic only. It does **not** introduce new models, features, or synthetic data.

---

### Notebook Structure

| # | Section |
|---|---------|
| 1 | Project Introduction |
| 2 | Load Libraries |
| 3 | Load Live Dataset |
| 4 | Exploratory Data Analysis |
| 5 | Feature Engineering |
| 6 | Isolation Forest |
| 7 | Isolation Forest Visualizations |
| 8 | Random Forest |
| 9 | Operational ML Outputs & Prediction Distribution |
| 10 | Feature Importance |
| 11 | Hybrid Detection Strategy & Pipeline |
| 12 | Integration with DefenSync |
| 13 | Conclusion |
| 14 | Key Findings |
""",
    )

    # --- Section 2: imports ---
    set_source(
        nb,
        3,
        """import sys
from pathlib import Path

ROOT = Path.cwd()
if not (ROOT / "backend").exists() and (ROOT.parent / "backend").exists():
    ROOT = ROOT.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import warnings
warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from dotenv import load_dotenv
from IPython.display import display, Markdown
from sqlalchemy import select
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from backend.database.connection import get_engine, get_session
from backend.database.models import SecurityEvent
from backend.services.detection_service import DetectionService

load_dotenv(ROOT / ".env")

# Consistent presentation settings
FIG_W, FIG_H = 12, 6
sns.set_theme(style="whitegrid", palette="muted")
plt.rcParams.update({
    "figure.figsize": (FIG_W, FIG_H),
    "axes.titlesize": 13,
    "axes.labelsize": 11,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
})
print(f"Project root: {ROOT}")
""",
    )

    # --- Section 6: Isolation Forest markdown ---
    set_source(
        nb,
        13,
        """---
## Section 6 — Isolation Forest

### Why Isolation Forest?

DefenSync uses **Isolation Forest** for **unsupervised** multivariate anomaly detection. Unlike signature-based rules, Isolation Forest identifies events that are **statistically isolated** in the 15-dimensional behavioral feature space — meaning they require fewer random splits to separate from the bulk of normal activity.

### How Isolation Forest Isolates Abnormal Behaviour

1. Random trees partition the feature space using random features and split values.
2. **Normal** events (dense regions) require many splits to isolate.
3. **Abnormal** events (sparse/outlier regions) are isolated in fewer splits.
4. Events with shorter average path length receive higher anomaly scores.
5. DefenSync flags events where `predict == -1` and stores `isolation_score = -score_samples()`.

### Production Parameters (`detection_service.py`)

| Parameter | Value |
|-----------|-------|
| `contamination` | `0.1` |
| `random_state` | `42` |
| `n_estimators` | `100` |

### Production Workflow

`fit(features)` → `predict == -1` → anomaly flag → `isolation_score = -score_samples(features)`
""",
    )

    # --- Section 6: IF code ---
    set_source(
        nb,
        14,
        """iso = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
iso.fit(X)
anomaly_flags = iso.predict(X) == -1
anomaly_scores = -iso.score_samples(X)

n_normal = int((~anomaly_flags).sum())
n_anomaly = int(anomaly_flags.sum())
anomaly_pct = (n_anomaly / len(X) * 100) if len(X) else 0.0

risk_ml = pd.Series([e.risk_score for e in events_orm])

if_summary = pd.DataFrame({
    "Metric": [
        "Total Events Analysed (ML window)",
        "Normal Count (IF predict != -1)",
        "Anomaly Count (IF predict == -1)",
        "Anomaly Percentage",
        "Isolation Score — Minimum",
        "Isolation Score — Maximum",
        "Isolation Score — Mean",
        "Isolation Score — Median",
        "Average Risk Score (ML window)",
        "Maximum Risk Score (ML window)",
        "Minimum Risk Score (ML window)",
    ],
    "Value": [
        len(X),
        n_normal,
        n_anomaly,
        f"{anomaly_pct:.2f}%",
        f"{anomaly_scores.min():.4f}",
        f"{anomaly_scores.max():.4f}",
        f"{anomaly_scores.mean():.4f}",
        f"{np.median(anomaly_scores):.4f}",
        f"{risk_ml.mean():.2f}",
        int(risk_ml.max()),
        int(risk_ml.min()),
    ],
})
display(if_summary.style.set_caption("Isolation Forest — Operational Summary (Live Data)").hide(axis="index"))

df_if = pd.DataFrame({
    "event_id": [e.event_id for e in events_orm],
    "is_anomaly": anomaly_flags,
    "isolation_score": anomaly_scores,
    "risk_score": risk_ml.values,
    "timestamp": [e.timestamp for e in events_orm],
})
print("\\nTop 10 anomalies by isolation score:")
display(df_if[df_if["is_anomaly"]].sort_values("isolation_score", ascending=False).head(10))
""",
    )

    # --- Section 7: IF viz markdown ---
    set_source(
        nb,
        15,
        """---
## Section 7 — Isolation Forest Visualizations

The charts below visualize anomaly separation, score distribution, and temporal clustering using the **same 2,000-event ML window** loaded from PostgreSQL.
""",
    )

    # --- Section 7: IF viz code ---
    set_source(
        nb,
        16,
        """fig, axes = plt.subplots(2, 3, figsize=(18, 10))

# 1. Scatter plot
sc = axes[0, 0].scatter(
    X[:, 8], X[:, 0], c=anomaly_flags.astype(int), cmap="coolwarm", alpha=0.55, s=14, edgecolors="none"
)
axes[0, 0].set_xlabel("Risk Score (feature index 8)")
axes[0, 0].set_ylabel("Login Hour (feature index 0)")
axes[0, 0].set_title("Feature Space Scatter — Anomalies Highlighted")

# 2. Pie chart
axes[0, 1].pie(
    [n_normal, n_anomaly],
    labels=["Normal", "Anomaly"],
    autopct="%1.1f%%",
    colors=["#2ecc71", "#e74c3c"],
    startangle=90,
)
axes[0, 1].set_title("Isolation Forest — Normal vs Anomaly Split")

# 3. Histogram — all scores
axes[0, 2].hist(anomaly_scores, bins=40, color="#8e44ad", alpha=0.8, edgecolor="white")
axes[0, 2].axvline(anomaly_scores.mean(), color="black", linestyle="--", label=f"Mean = {anomaly_scores.mean():.3f}")
axes[0, 2].set_xlabel("Isolation Score (-score_samples)")
axes[0, 2].set_ylabel("Frequency")
axes[0, 2].set_title("Isolation Score Distribution (All Events)")
axes[0, 2].legend()

# 4. Box plot — normal vs anomaly scores
box_data = [anomaly_scores[~anomaly_flags], anomaly_scores[anomaly_flags]]
axes[1, 0].boxplot(box_data, tick_labels=["Normal", "Anomaly"], patch_artist=True)
axes[1, 0].set_ylabel("Isolation Score")
axes[1, 0].set_title("Isolation Score Box Plot by Class")

# 5. Histogram — anomalies only
if n_anomaly:
    axes[1, 1].hist(anomaly_scores[anomaly_flags], bins=min(20, n_anomaly), color="#c0392b", alpha=0.85, edgecolor="white")
else:
    axes[1, 1].text(0.5, 0.5, "No anomalies detected", ha="center", va="center")
axes[1, 1].set_xlabel("Isolation Score")
axes[1, 1].set_ylabel("Frequency")
axes[1, 1].set_title("Isolation Score Distribution (Anomalies Only)")

# 6. Timeline
df_if["ts"] = pd.to_datetime(df_if["timestamp"])
timeline = df_if[df_if["is_anomaly"]].groupby(df_if["ts"].dt.floor("h")).size()
axes[1, 2].plot(timeline.index, timeline.values, marker="o", color="#d35400")
axes[1, 2].set_xlabel("Timestamp (hourly bins)")
axes[1, 2].set_ylabel("Anomaly Count")
axes[1, 2].set_title("Timeline of Detected Anomalies")
axes[1, 2].tick_params(axis="x", rotation=45)

plt.suptitle("DefenSync — Isolation Forest Analysis (Live PostgreSQL Data)", fontsize=14, y=1.01)
plt.tight_layout()
plt.show()
""",
    )

    # --- Section 9: replace evaluation markdown ---
    set_source(
        nb,
        19,
        """---
## Section 9 — Operational ML Outputs & Prediction Distribution

### Random Forest Label Context

> ⚠️ **Important — Operational Labels vs Ground Truth**
>
> Random Forest in DefenSync is trained using project-generated labels derived from risk score and event type. These labels are **operational labels** used by the detection pipeline rather than externally annotated ground-truth data. Therefore the analysis shown in this notebook represents **consistency with the project rules** rather than real-world predictive accuracy.
>
> **Accuracy, Precision, Recall, F1 Score, and ROC Curve are not reported** because no externally verified attack labels exist in the database.

### Operational ML Outputs

The table below summarizes detection behaviour on the live PostgreSQL dataset using the production 2,000-event ML window and hybrid merge logic from `DetectionService.run_detection()`.

### Prediction Distribution Dashboard

Hybrid classification output (Normal / Suspicious / Malicious) for the current ML run.
""",
    )

    # --- Section 9: operational outputs code ---
    set_source(
        nb,
        20,
        """n_normal_cls = int((df_pred["classification"] == "Normal").sum())
n_susp_cls = int((df_pred["classification"] == "Suspicious").sum())
n_mal_cls = int((df_pred["classification"] == "Malicious").sum())

operational = pd.DataFrame({
    "Operational Metric": [
        "Total Events Analysed (ML window)",
        "Total Normal Events (classification)",
        "Total Suspicious Events (classification)",
        "Total Malicious Events (classification)",
        "Total Isolation Forest Anomalies",
        "Percentage of Anomalies",
        "Average Risk Score (ML window)",
        "Maximum Risk Score (ML window)",
        "Minimum Risk Score (ML window)",
        "Total Events in Database (full table)",
        "Total Alerts in Database",
        "Total Detections Stored in Database",
    ],
    "Value": [
        len(events_orm),
        n_normal_cls,
        n_susp_cls,
        n_mal_cls,
        n_anomaly,
        f"{anomaly_pct:.2f}%",
        f"{risk_ml.mean():.2f}",
        int(risk_ml.max()),
        int(risk_ml.min()),
        len(df_events),
        len(df_alerts),
        len(df_detections),
    ],
})
display(operational.style.set_caption("DefenSync — Operational ML Outputs (Live PostgreSQL)").hide(axis="index"))

if rf_model is not None:
    rf_dist = pd.Series(rf_model.predict(X)).map({0: "normal", 1: "suspicious"}).value_counts()
    print("\\nRandom Forest operational label distribution (0=normal, 1=suspicious):")
    display(rf_dist.to_frame("count"))
else:
    print("Random Forest was not trained (production requires >= 2 pseudo-label classes).")
""",
    )

    # --- Section 9: prediction distribution code ---
    set_source(
        nb,
        21,
        """class_counts = df_pred["classification"].value_counts().reindex(["Normal", "Suspicious", "Malicious"], fill_value=0)
class_pct = (class_counts / class_counts.sum() * 100).round(2)

dist_table = pd.DataFrame({
    "Classification": class_counts.index,
    "Count": class_counts.values,
    "Percentage": class_pct.values.astype(str) + "%",
})
display(dist_table.style.set_caption("Hybrid Classification Distribution").hide(axis="index"))

fig, axes = plt.subplots(1, 2, figsize=(14, 5))
colors = {"Normal": "#27ae60", "Suspicious": "#f39c12", "Malicious": "#c0392b"}

axes[0].pie(class_counts.values, labels=class_counts.index, autopct="%1.1f%%",
            colors=[colors[c] for c in class_counts.index], startangle=90)
axes[0].set_title("Classification Distribution — Pie Chart")

bars = axes[1].bar(class_counts.index, class_counts.values, color=[colors[c] for c in class_counts.index])
axes[1].set_title("Classification Distribution — Bar Chart")
axes[1].set_xlabel("Classification")
axes[1].set_ylabel("Event Count")
for bar, val in zip(bars, class_counts.values):
    axes[1].text(bar.get_x() + bar.get_width() / 2, bar.get_height(), str(val), ha="center", va="bottom")

plt.suptitle("DefenSync Hybrid Detection — Prediction Distribution (Live Data)", fontsize=13)
plt.tight_layout()
plt.show()

if len(df_detections):
    print("Stored detections table (production history) — classification counts:")
    display(df_detections["classification"].value_counts().to_frame("stored_count"))
""",
    )

    # --- Section 10: feature importance markdown ---
    set_source(
        nb,
        22,
        """---
## Section 10 — Feature Importance

Random Forest computes `feature_importances_` after training on operational pseudo-labels. DefenSync does **not** persist feature importance in the database; values are computed here for analysis using the same model configuration as production.

Feature importance indicates which behavioural dimensions contributed most to the Random Forest split decisions when learning operational suspicious vs normal patterns.
""",
    )

    # --- Section 10: feature importance code ---
    set_source(
        nb,
        23,
        """FEATURE_EXPLANATIONS = {
    "risk_score": "Rule-engine composite score; strongest signal for suspicious operational labels.",
    "severity_encoded": "Encoded severity (info→critical); correlates with event criticality.",
    "failed_login_count": "Behavioural brute-force indicator from auth telemetry.",
    "is_failed_login": "Binary flag for Failed Login event type.",
    "is_suspicious_type": "Flag for SUSPICIOUS_TYPES (Failed Login, Invalid User, User Creation, Sudo Command).",
    "login_hour": "Temporal behaviour — off-hours activity patterns.",
    "session_duration": "Session length from SSH-collected auth metadata.",
    "cpu_usage": "Server CPU at collection time (SSH `top`).",
    "memory_usage": "Memory utilisation at collection time.",
    "disk_usage": "Disk utilisation at collection time.",
    "commands_executed": "Command activity volume per session.",
    "network_connections": "Active network connections (`ss` count).",
    "is_root_user": "Privilege escalation / root activity indicator.",
    "is_remote_ip": "Remote source IP (non-localhost) indicator.",
    "server_hash_feature": "Server identity hash for per-server behavioural context.",
}

if rf_model is not None:
    imp = pd.Series(rf_model.feature_importances_, index=FEATURE_NAMES).sort_values(ascending=False)
    imp_table = imp.to_frame("importance")
    imp_table["rank"] = range(1, len(imp_table) + 1)
    imp_table = imp_table[["rank", "importance"]]

    display(imp_table.style.set_caption("Ranked Feature Importance Table").format({"importance": "{:.4f}"}))

    top5 = imp.head(5)
    print("\\nTop 5 Most Influential Features:")
    for rank, (feat, val) in enumerate(top5.items(), start=1):
        print(f"  {rank}. {feat} ({val:.4f}) — {FEATURE_EXPLANATIONS.get(feat, '')}")

    fig, ax = plt.subplots(figsize=(10, 7))
    imp.sort_values(ascending=True).plot(kind="barh", ax=ax, color="#1a5276")
    ax.set_xlabel("Gini Importance")
    ax.set_ylabel("Feature")
    ax.set_title("Random Forest Feature Importance — Ranked Horizontal Bar Chart")
    plt.tight_layout()
    plt.show()

    display(Markdown(
        "**Interpretation:** The top features reflect which behavioural dimensions the Random Forest "
        "relied on most when separating operational normal vs suspicious labels. "
        "In DefenSync, `risk_score` and severity-related features typically dominate because "
        "pseudo-labels are derived from the rule engine; telemetry features (CPU, session, network) "
        "capture multivariate behavioural context that complements rule-based scoring."
    ))
else:
    print("Feature importance unavailable — Random Forest was not trained.")
""",
    )

    # --- Section 11: pipeline + hybrid strategy ---
    set_source(
        nb,
        24,
        """---
## Section 11 — Hybrid Detection Strategy & Pipeline

### Hybrid Detection Strategy

DefenSync uses a **four-stage hybrid pipeline** that combines unsupervised anomaly detection, rule-based risk scoring, supervised operational classification, and alert generation.

```
Stage 1: Isolation Forest (Unsupervised)
    ↓  Multivariate anomaly flags + isolation_score
Stage 2: Risk Score (Rule Engine)
    ↓  risk_score, severity, risk_level from DEFAULT_RULES
Stage 3: Random Forest Classification (Operational Labels)
    ↓  random_forest_label + merged Normal/Suspicious/Malicious
Stage 4: Alert Generation
    ↓  AlertService.sync_from_events + create_ml_alert → alerts table
```

#### Why Hybrid Detection?

| Technique Alone | Limitation | Hybrid Benefit |
|-----------------|------------|----------------|
| Rules only | Cannot detect novel multivariate outliers | Isolation Forest finds behavioural anomalies rules miss |
| Isolation Forest only | High false positives on benign outliers | Rules + RF provide operational context |
| Random Forest only | Requires labels; project uses operational pseudo-labels | IF adds unsupervised signal without ground truth |
| **Combined** | — | **Normal / Suspicious / Malicious tiers** with detection_type attribution (rule_based, isolation_forest, random_forest, hybrid) |

Combining **unsupervised anomaly detection** with **supervised operational classification** and **rule-based risk scoring** improves behavioural threat detection because each stage compensates for the weaknesses of the others.

---

### End-to-End Pipeline

```
Linux Server
    ↓ SSH (Paramiko)
SSH Collector (CollectorService + log_sources catalog)
    ↓ raw log lines + system metrics (top/free/df/ss)
Parser (backend/parser/engine.py)
    ↓ structured dicts
Normalizer (EventNormalizer)
    ↓ NormalizedSecurityEvent
RiskEngine + DEFAULT_RULES (backend/risk/)
    ↓ risk_score, severity, risk_level
Events Table (PostgreSQL)
    ↓ DetectionService._load_events(limit=2000)
Feature Engineering (_features → 15-dim matrix)
    ↓
Isolation Forest (contamination=0.1, n_estimators=100)
    ↓ anomaly flags + isolation_score
Random Forest (n_estimators=50, max_depth=6, pseudo-labels)
    ↓ random_forest_label + merged classification
Detections Table (detections / MLPrediction)
    ↓ AlertService.sync_from_events + create_ml_alert
Alerts Table
    ↓ Dashboard / Detection page / Admin Console
```
""",
    )

    # --- Section 13: conclusion ---
    set_source(
        nb,
        27,
        """---
## Section 13 — Conclusion

The Machine Learning module successfully demonstrates **behavioural anomaly detection** using Isolation Forest followed by event classification using Random Forest. This notebook validates the production implementation of DefenSync using **live PostgreSQL data**.

Since Random Forest uses **project-defined operational labels** instead of externally annotated datasets, this notebook focuses on **detection behaviour, prediction distribution, feature importance, and anomaly analysis** rather than conventional supervised accuracy metrics.

### Summary

| Aspect | Implementation |
|--------|----------------|
| Features | 15 behavioural features from `DetectionService._features()` — no sklearn scaling |
| Isolation Forest | `IsolationForest(contamination=0.1, random_state=42, n_estimators=100)` |
| Random Forest | `RandomForestClassifier(n_estimators=50, random_state=42, max_depth=6)` |
| Labels | Operational pseudo-labels from risk score ≥ 70 and SUSPICIOUS_TYPES |
| Storage | Predictions → `detections` table; alerts → `alerts` table |

### Advantages of Hybrid Detection

1. Rules provide interpretable baseline risk and alert synchronisation  
2. Isolation Forest discovers multivariate behavioural outliers  
3. Random Forest aligns with suspicious operational patterns  
4. Merge logic produces actionable Normal / Suspicious / Malicious tiers  
5. Results are persisted and surfaced on the analyst dashboard

### Current Limitations (As Implemented)

1. ML window capped at **2,000** most recent events per run  
2. Models **retrained on each** `run_detection()` call — no persisted `.pkl`  
3. RF labels are operational pseudo-labels, not analyst-verified ground truth  
4. No production accuracy / F1 / ROC tracking  
5. NULL telemetry fields are coerced to 0 during feature engineering  
6. Feature importance is not stored in the database

### Future Improvements (Academic Discussion Only)

Externally annotated datasets, model persistence, held-out evaluation, class imbalance handling, and SHAP explainability — none of these are implemented in the current codebase.
""",
    )

    # --- Section 13: conclusion code + insert Key Findings ---
    set_source(
        nb,
        28,
        """run_summary = pd.DataFrame({
    "Metric": [
        "Total Events (full PostgreSQL table)",
        "Events Analysed (ML window)",
        "Normal Events",
        "Suspicious Events",
        "Malicious Events",
        "Isolation Forest Anomalies",
        "Anomaly Percentage",
        "Features Used",
    ],
    "Value": [
        len(df_events),
        len(events_orm),
        n_normal_cls,
        n_susp_cls,
        n_mal_cls,
        n_anomaly,
        f"{anomaly_pct:.2f}%",
        X.shape[1],
    ],
})
display(run_summary.style.set_caption("ML Run Summary — Live Data").hide(axis="index"))
""",
    )

    # Insert Section 14 — Key Findings
    key_findings_md = md("""---
## Section 14 — Key Findings

This section consolidates the principal outcomes of the DefenSync ML analysis notebook for MCA project review and viva.
""")

    key_findings_code = code("""key_findings = pd.DataFrame({
    "Category": [
        "Total Events Processed",
        "Total Alerts Generated",
        "Total Detections Stored",
        "Number of Servers",
        "Number of Features Used",
        "Isolation Forest — contamination",
        "Isolation Forest — n_estimators",
        "Isolation Forest — random_state",
        "Random Forest — n_estimators",
        "Random Forest — max_depth",
        "Random Forest — random_state",
    ],
    "Value": [
        len(df_events),
        len(df_alerts),
        len(df_detections),
        len(df_servers),
        len(FEATURE_NAMES),
        0.1,
        100,
        42,
        50,
        6,
        42,
    ],
})
display(key_findings.style.set_caption("Key Findings — Live Database Statistics").hide(axis="index"))
""")

    key_findings_tables = md("""### Files Responsible for ML

| File | Role |
|------|------|
| `backend/services/detection_service.py` | Isolation Forest, Random Forest, features, classification merge |
| `backend/services/alert_service.py` | Rule alerts + ML anomaly alerts |
| `backend/risk/engine.py` | Rule-based risk scoring |
| `backend/risk/rules.py` | Detection rules |
| `backend/services/pipeline_service.py` | Collect, parse, normalize, ingest |
| `backend/services/collector_service.py` | SSH telemetry collection |
| `backend/services/scheduler_service.py` | Scheduled detection per owner |
| `backend/api/detection.py` | Detection REST API |

### Database Tables Used

| Table | Purpose |
|-------|---------|
| `events` | ML input features and risk scores |
| `detections` | Stored ML predictions |
| `alerts` | Actionable security alerts |
| `servers` | Server metadata and health |

### APIs Used

| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/detection/status` | Detection engine status |
| `POST /api/v1/detection/run` | Trigger hybrid detection |
| `GET /api/v1/detection/anomalies` | Retrieve flagged events |
| `GET /api/v1/alerts` | List alerts |
| `GET /api/v1/alerts/summary` | Alert summary statistics |

### Advantages of the Hybrid ML Pipeline

1. **Unsupervised + supervised + rules** — complementary detection layers
2. **Behavioural features** — session, telemetry, auth, and temporal signals
3. **Live PostgreSQL integration** — no CSV or synthetic datasets
4. **Production parity** — notebook reuses `DetectionService._features()` and merge logic
5. **Actionable output** — classifications persisted to `detections` and `alerts`
""")

    nb["cells"].extend([key_findings_md, key_findings_code, key_findings_tables])

    NOTEBOOK.write_text(json.dumps(nb, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"Patched {NOTEBOOK} ({len(nb['cells'])} cells)")


if __name__ == "__main__":
    main()

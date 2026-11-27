# DefenSync
### Hybrid Behavioral Log Intelligence System

**Intelligent Security Monitoring for Linux and Cloud Environments Using Behavioral Analysis and Machine Learning.**

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue?logo=python" />
  <img src="https://img.shields.io/badge/Backend-FastAPI-009688?logo=fastapi" />
  <img src="https://img.shields.io/badge/Frontend-React-61DAFB?logo=react" />
  <img src="https://img.shields.io/badge/Database-PostgreSQL-4169E1?logo=postgresql" />
  <img src="https://img.shields.io/badge/ML-Scikit--learn-F7931E?logo=scikitlearn" />
</p>

---

## 1. Project Overview

DefenSync is a cybersecurity research prototype developed to monitor Linux and cloud environments, analyse user behaviour, detect suspicious activities, and support security incident investigation.

The platform combines security event collection, event normalization, behavioral analysis, machine learning, risk assessment, incident correlation, and evidence-based investigation in a unified monitoring system.

It uses **Isolation Forest** to identify unknown anomalies and **Random Forest** for supervised classification when genuine labelled data is available.

DefenSync focuses on identifying suspicious activities and supporting security analysts through investigation and recommendations.

## 2. Project Screenshots

DefenSync provides separate monitoring workspaces for Linux and Cloud environments.

### Linux Security Dashboard

<p align="center">
  <img src="imgs/Linux Dashboard.png" width="100%" alt="DefenSync Linux Security Dashboard" />
</p>

### Cloud Security Dashboard

<p align="center">
  <img src="imgs/Cloud Dashboard.png" width="100%" alt="DefenSync Cloud Security Dashboard" />
</p>

### Linux Alert Monitoring

<p align="center">
  <img src="imgs/Linux Alert Detection.png" width="100%" alt="DefenSync Linux Alert Monitoring" />
</p>

### Cloud Threat Intelligence

<p align="center">
  <img src="imgs/Cloud Detection.png" width="100%" alt="DefenSync Cloud Threat Intelligence" />
</p>

## 3. Problem Statement

Traditional security monitoring often focuses on individual security events, making it difficult to identify unusual behaviour that develops over time or involves multiple related activities.

DefenSync addresses this challenge by analysing security events, establishing behavioral patterns, identifying anomalies, and correlating related activities to provide better investigation context.

## 4. Key Features

- **Linux Security Monitoring:** Collects SSH, authentication, audit, and system activity logs.
- **Cloud Security Monitoring:** Supports Azure Log Analytics integration and cloud event imports.
- **Event Normalization:** Converts different security log formats into a common event structure.
- **Behavioral Analysis:** Builds user activity baselines and identifies unusual behaviour.
- **Hybrid Machine Learning:** Combines Isolation Forest and Random Forest.
- **Risk Assessment:** Uses a rule-based Risk Engine with scores from 0–100.
- **Incident Correlation:** Groups related security events using event timestamps.
- **Evidence Management:** Provides event details and evidence summaries for investigation.
- **Security Alerts:** Displays suspicious activities with severity, explanations, and recommendations.
- **Intelligence Module:** Presents correlated incidents and advisory investigation information.
- **Notifications:** Supports optional n8n webhook integration.
- **Secure Authentication:** Supports JWT authentication, password hashing, role-based access, and email OTP verification.

## 5. System Architecture

```text
       LINUX ENVIRONMENT          CLOUD ENVIRONMENT
       SSH / System Logs          Azure / OpenStack
               |                        |
               +-----------+------------+
                           |
                    Event Collection
                           |
                    Event Normalization
                           |
                    Rule-Based Risk Engine
                           |
                       PostgreSQL
                           |
                    Behavioral Analysis
                           |
                   Hybrid ML Detection
                     /           \
              Isolation Forest  Random Forest
                     \           /
                    Incident Correlation
                           |
                 Evidence & Intelligence
                           |
                 Dashboard and Alerts
                           |
                 Optional n8n Notifications
```

**Architecture Note:** Linux and Cloud operate as separate monitoring workspaces. Their events are not combined into one global risk timeline.

## 6. System Workflow

1. **Data Collection:** Collects Linux logs, cloud events, and behavioral datasets.
2. **Event Processing:** Parses and normalizes incoming security events.
3. **Risk Assessment:** Calculates rule-based risk scores.
4. **Data Storage:** Stores normalized events in PostgreSQL.
5. **Behavioral Analysis:** Compares activities with established user baselines.
6. **ML Detection:** Applies Isolation Forest and Random Forest where applicable.
7. **Incident Correlation:** Groups related events into security incidents.
8. **Investigation:** Presents evidence, explanations, and recommendations.
9. **Notifications:** Sends optional incident notifications through n8n.

## 7. Machine Learning Methodology

### Isolation Forest

- Unsupervised anomaly detection.
- Identifies unusual patterns without requiring labelled training data.
- Detects deviations from normal activity patterns.
- Does not use rule-based risk scores as an input feature.

### Random Forest

- Supervised classification algorithm.
- Uses genuine `original_label` ground-truth labels.
- Trains only when valid labels are available.
- Evaluates performance using labelled hold-out data.

### Behavioral Analysis

- Builds behavioral profiles using behavioral datasets and sufficient Linux observations.
- Identifies unusual activity patterns.
- Generates human-readable risk reasons.
- Uses configured thresholds to prevent high-risk events from updating normal behavioral baselines.

## 8. Monitoring Environments

### Linux Security Monitoring

DefenSync supports remote Linux monitoring through SSH.

Monitored information includes:

- Authentication and login events.
- Failed login attempts.
- SSH activity.
- Sudo and privilege-related activity.
- Linux audit logs.
- journald events.
- CPU, memory, disk, process, and network snapshots.

The collector supports incremental journald reading, event deduplication, and collection-state tracking.

### Cloud Security Monitoring

DefenSync provides a separate Cloud workspace.

**Microsoft Azure**

- Entra ID sign-in logs.
- Azure Activity Logs.
- Azure Log Analytics integration.
- Cloud identity and activity event normalization.
- Manual read-only telemetry collection.
- Azure JSON/CSV file imports.

**OpenStack**

- OpenStack event file imports.
- Synthetic OpenStack demonstration data.

Real Azure telemetry is distinguished from imported, public, synthetic, and curated datasets. Synthetic events are never labelled as real Azure telemetry.

## 9. Risk Assessment and Incident Correlation

DefenSync uses a rule-based Risk Engine to calculate risk scores from 0–100.

The risk assessment considers event types and contextual information.

The incident correlation module groups related security events using their occurrence timestamps and a configured correlation window.

The Intelligence module presents stored incidents, severity, associated events, evidence summaries, and advisory recommendations.

## 10. Alerts and Notifications

- Generates alerts from high-risk rules and ML flags.
- Displays severity, explanations, confidence, and recommendations.
- Supports alert acknowledgement.
- Stores correlated security incidents.
- Supports optional n8n webhook notifications for newly created or escalated high/critical incidents.

n8n handles notification delivery. Detection and incident storage remain responsibilities of DefenSync.

## 11. Security and Authentication

- JWT-based authentication.
- bcrypt password hashing.
- Admin and Analyst role-based access control.
- Email-based OTP verification.
- Password reset using verification codes.
- Account-level data ownership.
- Secure handling of cloud credentials and environment variables.

## 12. Technology Stack

| Component | Technology |
|---|---|
| Frontend | React 18, Vite |
| UI Styling | Tailwind CSS |
| Charts | Recharts |
| Backend | Python, FastAPI |
| Database | PostgreSQL |
| ORM | SQLAlchemy |
| Machine Learning | Scikit-learn |
| Algorithms | Isolation Forest, Random Forest |
| Model Persistence | Joblib |
| Linux Collection | Paramiko, SSH, journald |
| Cloud Integration | Azure Log Analytics |
| Authentication | JWT, bcrypt, Email OTP |
| Automation | n8n Webhooks |

## 13. Project Structure

```text
DefenSync/
│
├── backend/
│   ├── api/
│   ├── database/
│   ├── models/
│   ├── risk/
│   ├── services/
│   └── tests/
│
├── frontend/
│   ├── src/
│   ├── public/
│   └── package.json
│
├── datasets/
├── models/
├── scripts/
├── docs/
├── imgs/
│   ├── linux-dashboard.webp
│   ├── cloud-dashboard.webp
│   ├── linux-alerts.webp
│   └── cloud-intelligence.webp
│
├── .env.example
├── .gitignore
└── README.md
```

## 14. Installation and Setup

### Prerequisites

- Python 3.11+
- Node.js 18+
- PostgreSQL
- Git
- Windows or Linux development environment.

### Step 1: Clone the Repository

```bash
git clone https://github.com/yogesh2300/DefenSync.git
cd DefenSync
```

To use the behavioral intelligence development branch:

```bash
git checkout prototype/cloud-behavioral-intelligence
```

### Step 2: Backend Setup

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r backend/requirements.txt
```

### Step 3: Configure Environment

Create a project-root `.env` file using `.env.example` only if you do not already have a working configuration.

Configure your local PostgreSQL database credentials and required application settings.

**Never upload `.env`, passwords, API keys, client secrets, or tokens to GitHub.**

### Step 4: Initialize Database

Make sure PostgreSQL is running.

```bash
python scripts/migrate_schema.py
python -m backend.database.init_db
```

### Step 5: Start Backend

From the project root:

```bash
python -m backend.main
```

Backend: `http://localhost:8000`

API Documentation: `http://localhost:8000/docs`

Health Check: `http://localhost:8000/health`

### Step 6: Start Frontend

Open another terminal:

```bash
cd frontend
npm install
npm run dev
```

Frontend: `http://localhost:5173`

The frontend development server proxies API requests to the backend.

## 15. Testing and Demonstration

DefenSync supports demonstration workflows using behavioral and OpenStack demo data.

- Load Behavioral Demo Data.
- Load OpenStack Demo Data.
- Import supported Azure event files.
- Run Detection after events are available.
- Review correlated incidents and alerts.

Live Linux monitoring requires a reachable SSH host. Live Azure collection requires valid Azure credentials and a properly configured Log Analytics workspace.

## 16. Current Limitations

- Live Azure collection is implemented but has not yet been verified against a real Azure workspace in the documented tests.
- Azure file import is separate from live Azure telemetry collection.
- Live OpenStack API integration is not implemented.
- Automatic cloud collection scheduling is not implemented.
- Linux collection requires accessible SSH hosts.
- Random Forest requires valid ground-truth labels.
- SHAP and LIME are not currently used.
- Automatic account blocking, session termination, and cloud resource isolation are not implemented.
- n8n integration requires separate configuration.

## 17. Future Scope

- Validate and improve live cloud telemetry collection.
- Improve behavioral anomaly detection accuracy.
- Enhance sequential threat detection.
- Expand cloud platform integrations.
- Improve incident investigation and evidence reporting.
- Explore human-approved automated response workflows.
- Improve model evaluation using representative datasets.

## 18. Project Information

| Detail | Information |
|---|---|
| Project Name | DefenSync |
| Project Type | MCA Final-Year Research Project |
| Domain | Cybersecurity |
| Focus Areas | Cloud Security, Linux Security, Machine Learning, Behavioral Analytics |
| Repository | [GitHub - DefenSync](https://github.com/yogesh2300/DefenSync) |

---

<p align="center">
  <b>DefenSync — Intelligent Monitoring. Behavioral Analysis. Better Security Investigation.</b>
</p>

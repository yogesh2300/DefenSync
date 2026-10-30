# DefenSync UI/UX redesign — technical overview

Single-page React app (Vite) talking to one FastAPI process and one PostgreSQL database. There are **no microservices** and **no WebSocket/SSE live streams**. Topology in the UI is a **hub-and-spoke diagram**, not a graph engine.

---

## 1. Core entities and topology

### Runtime topology (what actually runs)

| Node | Role | How the UI sees it |
|---|---|---|
| **DefenSync Security Core** | FastAPI on `:8000` | Dashboard “Security Core” circle; `/health` database status |
| **PostgreSQL** (`cloudsync_db`) | System of record | Compact “Database” metric (`connected` / `unknown`) |
| **Vite SPA** (`:5173`) | Analyst + Admin consoles | Proxies `/api` and `/health` to the core |
| **Linux hosts** | SSH collection targets | `servers` table; hub-and-spoke around Security Core |
| **Cloud / behavioral sources** | File import / demo, not live APIs | Events with `source_type` `CLOUD`, `CLOUD_DATASET`, `BEHAVIORAL` |

The Monitored Infrastructure panel is **CSS/HTML nodes + connector lines**, not Canvas/Three.js.

### Entity: Linux server (`servers`)

Attributes used in UI (subset of the ORM):

- Identity: `id`, `server_name`, `host`, `port`, `username`, `operating_system`, `environment`, `description`
- Auth (never shown as secrets): `authentication_type` (`password` / `ssh_key`)
- Health: `status`, `health_status`, `connection_state` (derived), `connection_latency_ms`, `last_seen`, `last_connected`, `last_health_check`, `last_successful_collection`, `health_error_message`, `consecutive_failures`
- Ownership: `owner_id`, `created_by`
- **UI-only / derived:** `risk_score` on cards; ServerCard **CPU% and Disk% are not live host metrics** — they are derived from `risk_score` for display

Backend health engine probes SSH every **30s** and writes `health_status`. Frontend re-fetches servers on the same interval.

### Entity: Security event (`events`)

Shown on Dashboard activity, Events, Intelligence, Detection.

- Time: `timestamp` (source occurrence), `collection_timestamp`, `timestamp_source`, `created_at`
- Actor/host: `hostname`, `username`, `actor_id`, `source_ip`, `server_id`
- Classification: `event_type`, `category`, `severity`, `risk_score`, `risk_level`, `parser_status`
- Content: `message`, `raw_log`, `command`, `process`, `normalized_data`
- Provenance: `source_type` (`LINUX` / `CLOUD` / `CLOUD_DATASET` / `BEHAVIORAL`), `provider` (`OPENSTACK` / `AZURE` / …), `data_origin` (`LIVE_LINUX`, `SYNTHETIC_CLOUD_DEMO`, dataset names)
- Live Linux extras (when collected): `cpu_usage`, `memory_usage`, `disk_usage`, `failed_login_count`, `session_duration`, `commands_executed`, `network_connections`, `login_hour`
- Behavioral extras (CSV/demo): `typing_speed_cpm`, `command_rate_per_minute`, `command_error_rate`, `idle_time_seconds`, `repeated_command_ratio`, `session_duration_minutes`, `behavioral_risk_score`, `behavioral_classification`, `risk_reasons`

### Entity: Alert (`alerts`)

- `title`, `message`, `severity`, `risk_score`, `risk_level`, `detection_type` (`rule_based` / `ml_anomaly` / `hybrid`)
- `acknowledged`, `created_at` (alert time), `event_timestamp` (occurrence), `event_id`, `incident_id`
- `explanation`, `recommendation`, `risk_factors`, `confidence`

### Other persisted entities (console-relevant)

| Entity | Key attributes | UI surface |
|---|---|---|
| **User** | `username`, `email`, `role` (`ADMIN` / `ANALYST`) | Login, layout, Admin Users |
| **Collection run** | `status`, processed/inserted/duplicates/failed/skipped, `duration_ms` | Collection, Admin Collections |
| **Behavior profile** | identity, sample count, usual login hours, typing/command baselines | Intelligence |
| **Detection** | IF score, RF label, classification, confidence | Detection, Admin ML/Detections |
| **Incident** | actor, evidence, timeline, risk, recommendation | Intelligence |
| **Risk history** | entity, score, reason, event time | Intelligence / export |
| **Dataset import** | OpenStack / behavioral / Azure file stats | Intelligence actions, datasets API |

**Not first-class UI nodes:** Azure subscriptions, OpenStack projects, network graphs, K8s clusters.

---

## 2. Visual component inventory

### Analyst shell (`Layout.jsx`) — light mint/neutral theme

Nav: Dashboard, Servers, Events, Alerts, Detection, DefenSync Intelligence, Collection (admin-only). Global **server scope** dropdown. Header clock ticks every **1s** (local time only).

### Dashboard (`Dashboard.jsx`) — primary redesign target

| Panel | Data | Static vs “live” |
|---|---|---|
| **Security Pulse** | Avg risk, critical / failed-login / ML alert counts, `RiskWidget` | Polled snapshot; “Monitoring” dot is **decorative**, not a stream |
| **Security Activity** | Last 8 events (`timestamp`, type, severity, host, message) | Polled list, not a live tail |
| **Monitored Infrastructure** | Server nodes + Security Core hub | Polled health; connectors CSS-animated |
| **Current Attention** | Threshold copy from the same counts | Derived, not a queue |
| **Operational Snapshot** | Events, alerts, ML, failed logins, servers, availability | Count-up animation on poll |
| **Infrastructure State** | Healthy / offline / errors, avg SSH ms, recent connect/disconnect | Polled |
| **Activity — Last 24 Hours** | Recharts Area (`hourly_trends`) | Aggregated REST |
| **Event Types** | Horizontal Bar (top 6 types) | Aggregated REST |
| **Event Severity** | Pie | Aggregated REST |
| **System Health** | DB status, unique users | `/health` + summary |

Actions: **Refresh** (re-GET), **Probe Server Status** (POST refresh-status then reload).

### Other analyst pages (panels to keep in the information architecture)

- **Servers / Server details:** `ServerCard` grid; health, risk, last check; Test / Collect. CPU/Disk on the card are **synthetic from risk**.
- **Events:** filterable table + detail (event time vs collected time).
- **Alerts:** Priority / Watch lists, investigation panel, 20s poll, acknowledge.
- **Detection:** Run Detection, IF/RF status, anomaly table, Recharts area/bar. No fake accuracy.
- **Intelligence:** Security Posture, Intelligence Flow, Active Investigation, Operational Snapshot, Source Cards, Unified Event Stream, Behavioral Analytics + history chart, Cloud Activity, Threat Correlation, Threat Investigation, Risk Analysis, Security Recommendation.
- **Collection:** source checkboxes, run summary JSON (skipped sources included).
- **Login:** JWT form.

### Admin console (`AdminLayout` + `/admin/*`) — separate **dark** zinc theme

Metric tiles, Recharts (Area/Line/Bar/Pie): users, servers, events, alerts, detections, collection success, registration trend, event timeline, ML page, system-health, analytics, settings.

Treat admin vs analyst as **two visual systems** in any redesign.

### Shared primitives

`Card`, `PageHeader`, `Button`, `Badge` / `HealthBadge` / `SeverityBadge`, `DataTable`, `RiskWidget` (score ring), `AlertBanner`, `StatCard`, `LoadingSpinner`, `Input`/`Select`, Framer Motion hover/layout.

**Nothing is WebSocket-streaming.** “Real-time” in this product means **polling + optimistic refresh after collect**.

---

## 3. Tech stack and visualization libraries

| Layer | Choice |
|---|---|
| UI framework | **React 18** + **React Router 6** (not Next.js / Vue) |
| Bundler | **Vite 5** (`@vitejs/plugin-react`) |
| Styling | **Tailwind CSS 4** (`@tailwindcss/vite`), CSS variables in `index.css`, page CSS (`Dashboard.css`, `Intelligence.css`, `admin.css`) |
| Icons | **Lucide React** |
| Charts | **Recharts** (`AreaChart`, `BarChart`, `PieChart`, `LineChart`, `ResponsiveContainer`) — SVG |
| Motion | **Framer Motion** (`layoutId`, `whileHover`) |
| HTTP | **Axios** (`frontend/src/api/client.js`, `adminClient.js`) |
| Count animation | Custom `requestAnimationFrame` on Dashboard (`react-countup` is in `package.json` but unused there) |

**Not present:** Three.js, Canvas charting, D3, Cytoscape, Mapbox, Socket.IO.

Hub diagram = DOM + CSS (`dash-connector`, `dash-core`). Charts = Recharts SVG.

---

## 4. Data flow and state management

### Transport

```
UI  --HTTP GET/POST-->  Vite proxy /api,/health  -->  FastAPI  -->  PostgreSQL
                              (dev only)
```

- **No WebSockets, no SSE.**
- Polling: servers/dashboard/admin **30s**; alerts **20s**; layout clock **1s**.
- After collection: `window` event `defensync:data-refresh`.
- After SSH probe: `defensync:status-refreshed`.
- Server scope change: `defensync:server-changed`.
- Logout: `defensync:logout` + clear token.

Dashboard `load()` uses `withTimeout(..., 1200ms)` so a slow API falls back to empty metrics rather than hanging.

### Global state (React only — no Redux/Zustand)

| Store | Location | Persistence |
|---|---|---|
| Auth user | `AuthContext` | JWT in `localStorage` (`defensync_token`, legacy `cloudsync_token`) |
| Server list + selected host | `SelectedServerContext` | `localStorage` `defensync_selected_server` + `?server_id=` |
| Page data | Local `useState` per page | None |

Host health in the UI is the last `getServers()` payload, which reflects the **backend health engine** (30s SSH checks), not a live agent.

### Typical dashboard fetch set

`getDashboardSummary`, `getEventStats`, `getRecentEvents(10)`, `getAlertSummary`, `getHealth`, then `refreshServers()`. Scoped by `selectedServerId` when set.

### Implications for redesign

1. A live “SOC wall” needs new transport (WS/SSE) or honest labeling of poll intervals.
2. Topology can stay hub-and-spoke; a force-graph would need new data (edges are not stored).
3. Do not treat ServerCard CPU/Disk as telemetry unless wired to `events.cpu_usage` / collection metrics.
4. Preserve **event time vs collection time** in any timeline redesign.
5. Analyst light theme and admin dark theme are currently separate; unify or keep two products.
6. Cloud nodes should remain **import/demo**, not live Azure/OpenStack, unless the backend changes.

import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { Cloud, Plus, RefreshCw, Server } from 'lucide-react'
import {
  getAccountList,
  getAccountSummary,
  getAlertSummary, getCloudSources, getDashboardSummary, getEventStats, getHealth, getMe, getRecentEvents,
  refreshServerStatus,
} from '../api/client'
import { lastCollectionLabel } from '../cloud/cloudSource'
import { useEnvironment } from '../context/EnvironmentContext'
import { useSelectedServer } from '../context/SelectedServerContext'
import { CLOUD, ENVIRONMENT_LABELS, LINUX, workspaceResources } from '../environment'
import Button from '../components/ui/Button'
import Card from '../components/ui/Card'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import PageHeader from '../components/ui/PageHeader'
import RiskWidget from '../components/ui/RiskWidget'
import { SeverityBadge, HealthBadge } from '../components/ui/Badge'
import { PRIMARY_SCORE_LABEL, accountIdForSummaryRequest, resolvePrimarySecurityScore } from '../intelligence/primaryScore'
import { eventRiskFractionClass, formatEventRiskFraction } from '../intelligence/investigation'
import { useAuth } from '../context/AuthContext'
import './Dashboard.css'

const EMPTY_SUMMARY = {
  total_events: 0,
  failed_logins: 0,
  unique_users: 0,
  average_risk_score: 0,
  total_servers: 0,
  online_servers: 0,
  offline_servers: 0,
  healthy_servers: 0,
  servers_with_errors: 0,
  average_ssh_latency_ms: 0,
  recently_connected: 0,
  recently_disconnected: 0,
}

const EMPTY_STATS = {
  by_severity: {},
  by_event_type: {},
  hourly_trends: [],
  top_source_ips: [],
  top_usernames: [],
}

const EMPTY_ALERTS = {
  total: 0,
  unacknowledged: 0,
  ml_anomaly: 0,
  critical: 0,
}

const SEVERITY_COLORS = {
  critical: '#B76E79',
  high: '#9F5F68',
  medium: '#B89B5E',
  low: '#A5A5A5',
  info: '#737373',
}

const CHART_TOOLTIP = {
  contentStyle: {
    background: 'var(--panel-strong)',
    border: '1px solid var(--panel-border)',
    borderRadius: 16,
    color: 'var(--text-main)',
    fontSize: 12,
  },
}

function withTimeout(promise, fallback, ms = 8000) {
  return Promise.race([
    promise.catch(() => fallback),
    new Promise((resolve) => {
      setTimeout(() => resolve(fallback), ms)
    }),
  ])
}

function CountUp({ value, className }) {
  const target = Number(value) || 0
  const [shown, setShown] = useState(target)
  useEffect(() => {
    const reduce = typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches
    if (reduce) {
      setShown(target)
      return undefined
    }
    let frame
    const origin = shown
    const startAt = performance.now()
    const tick = (now) => {
      const progress = Math.min(1, (now - startAt) / 800)
      setShown(Math.round(origin + (target - origin) * progress))
      if (progress < 1) frame = requestAnimationFrame(tick)
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [target])
  return <span className={className}>{shown.toLocaleString()}</span>
}

function CompactMetric({ label, value }) {
  return (
    <div className="rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-4">
      <p className="text-[10px] font-semibold uppercase tracking-wide muted-text">{label}</p>
      <p className="mt-1 text-2xl font-bold tabular-nums tracking-tight cyber-text">{value}</p>
    </div>
  )
}

function connectionKind(server) {
  const health = (server?.health_status || server?.status || '').toLowerCase()
  if (health === 'online') return 'online'
  if (['offline', 'timeout', 'unreachable'].includes(health)) return 'down'
  return 'warn'
}

function padPosition(index, total) {
  const count = Math.max(total, 1)
  const angle = ((Math.PI * 2 * index) / count) - (Math.PI / 2)
  const radius = count <= 1 ? 28 : 31
  return {
    left: `${50 + Math.cos(angle) * radius}%`,
    top: `${50 + Math.sin(angle) * radius}%`,
  }
}

function formatWhen(value) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

function strongestObservedSignal(critical, failedLogins, mlAlerts) {
  const signals = [
    { value: Number(failedLogins) || 0, text: 'Authentication activity is currently the strongest observed signal.' },
    { value: Number(critical) || 0, text: 'Critical alerts are currently the strongest observed signal.' },
    { value: Number(mlAlerts) || 0, text: 'ML-generated alerts are currently the strongest observed signal.' },
  ]
  const peak = Math.max(...signals.map((item) => item.value))
  if (peak <= 0) return null
  return signals.find((item) => item.value === peak)?.text || null
}

function SignalRow({ label, value, max }) {
  const numeric = Number(value) || 0
  const ceiling = Number(max) || 0
  const width = ceiling > 0 ? Math.max(4, Math.round((numeric / ceiling) * 100)) : 0
  return (
    <div className="dash-signal-row">
      <span className="dash-signal-label">{label}</span>
      <span className="dash-signal-track" aria-hidden="true">
        <span className="dash-signal-fill" style={{ width: `${width}%` }} />
      </span>
      <CountUp value={numeric} className="dash-signal-value" />
    </div>
  )
}

function SecurityPulse({
  summary,
  accountSummary,
  loaded = true,
  selectedAccountId = null,
  isAdmin = false,
  environment = null,
  critical,
  failedLogins,
  mlAlerts,
}) {
  const primary = resolvePrimarySecurityScore({
    summary,
    accountSummary,
    loaded,
    selectedAccountId,
    isAdmin,
    expectedEnvironment: environment,
  })
  const criticalCount = Number(critical) || 0
  const failedCount = Number(failedLogins) || 0
  const mlCount = Number(mlAlerts) || 0
  const reviewNeeded = criticalCount + failedCount + mlCount > 0
  const signalMax = Math.max(criticalCount, failedCount, mlCount)
  const strongest = strongestObservedSignal(criticalCount, failedCount, mlCount)
  return (
    <Card className="dash-enter dash-card-hover dash-pulse">
      <div className="dash-pulse-head">
        <p className="text-[11px] font-semibold uppercase tracking-wide muted-text">Security Pulse</p>
        <span className="inline-flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide cyber-text">
          <span className="dash-pulse-dot inline-block h-2 w-2 rounded-full bg-[#6EA779]" />
          Monitoring
        </span>
      </div>
      <div className="dash-pulse-body" data-primary-security-score>
        <div className="flex flex-col items-center gap-2">
          {primary.available ? (
            <RiskWidget score={primary.score} label={PRIMARY_SCORE_LABEL} size="sm" />
          ) : (
            <div className="cyber-card flex flex-col items-center gap-2 rounded-xl border border-[var(--panel-border)] p-4" data-primary-score-unavailable>
              <span className="text-lg font-bold cyber-text">Unavailable</span>
              <span className="text-center text-xs muted-text">{primary.reason}</span>
            </div>
          )}
          <p className="max-w-[14rem] text-center text-[11px] leading-4 muted-text" data-risk-score-caption>
            Overall Risk Score represents the average risk of included security events. Individual event scores represent the risk of each separate activity.
          </p>
        </div>
        <div className="dash-pulse-copy">
          <p className="text-sm cyber-text">
            {reviewNeeded ? 'Security activity requires review.' : 'No elevated alert pressure in the current scope.'}
          </p>
          {strongest && <p className="mt-1 text-[11px] muted-text">{strongest}</p>}
          <div className="dash-signal-stack">
            <SignalRow label="Critical Alerts" value={criticalCount} max={signalMax} />
            <SignalRow label="Failed Logins" value={failedCount} max={signalMax} />
            <SignalRow label="ML Alerts" value={mlCount} max={signalMax} />
          </div>
        </div>
      </div>
    </Card>
  )
}

function OperationalSnapshot({ summary, alerts, onlineRate, isLinux }) {
  const cells = [
    { label: 'Events', value: <CountUp value={summary.total_events} />, note: 'Activity' },
    { label: 'Alerts', value: <CountUp value={alerts?.unacknowledged ?? 0} />, note: `${alerts?.critical ?? 0} Critical` },
    { label: 'ML Alerts', value: <CountUp value={alerts?.ml_anomaly ?? 0} />, note: 'ML generated' },
    { label: isLinux ? 'Failed Login' : 'Failed Sign-in', value: <CountUp value={summary.failed_logins} />, note: 'Auth events' },
    ...(isLinux ? [
      { label: 'Servers', value: <CountUp value={summary.total_servers} />, note: `${summary.online_servers} online` },
      { label: 'Availability', value: `${onlineRate}%`, note: `${summary.offline_servers} offline` },
    ] : []),
  ]
  return (
    <section className="space-y-2">
      <p className="text-[11px] font-semibold uppercase tracking-wide muted-text">Operational Snapshot</p>
      <div className="dash-op-rail">
        {cells.map((cell) => (
          <div key={cell.label} className="dash-op-cell">
            <p className="dash-op-label">{cell.label}</p>
            <p className="dash-op-value">{cell.value}</p>
            <p className="dash-op-note">{cell.note}</p>
          </div>
        ))}
      </div>
      {isLinux && (
        <div className="dash-infra-line">
          <p className="dash-infra-kicker">Infrastructure State</p>
          <div className="dash-infra-items">
            <span>● Healthy {summary.healthy_servers ?? summary.online_servers}</span>
            <span>○ Offline {summary.offline_servers}</span>
            <span>⚠ Errors {summary.servers_with_errors ?? 0}</span>
            <span>↔ Avg SSH {summary.average_ssh_latency_ms ?? 0}ms</span>
            <span>◷ Recent {summary.recently_connected ?? 0} / {summary.recently_disconnected ?? 0}</span>
          </div>
        </div>
      )}
    </section>
  )
}

function SecurityActivity({ events }) {
  const rows = (events || []).slice(0, 8)
  return (
    <Card className="dash-enter dash-enter-delay-1 h-full">
      <div className="mb-3 flex items-center justify-between gap-2">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wide muted-text">Security Activity</p>
          <p className="text-sm muted-text">Newest stored events (occurrence time)</p>
        </div>
        <span className="inline-flex items-center gap-2 text-xs font-semibold cyber-text">
          <span className="dash-pulse-dot inline-block h-2 w-2 rounded-full bg-[#6EA779]" />
          Monitoring
        </span>
      </div>
      <div className="max-h-[220px] overflow-y-auto pr-1">
        {rows.map((event, index) => {
          const time = event.timestamp ? new Date(event.timestamp) : null
          const timeLabel = time && !Number.isNaN(time.getTime())
            ? time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
            : '--:--'
          return (
            <div key={event.event_id || event.id || index} className="dash-timeline-item flex gap-3" style={{ animationDelay: `${index * 55}ms` }}>
              <div className="flex w-4 flex-col items-center">
                <span className="mt-1 h-2.5 w-2.5 rounded-full bg-[#111111]" />
                {index < rows.length - 1 && <span className="mt-1 w-px flex-1 bg-[var(--panel-border)]" />}
              </div>
              <div className="min-w-0 pb-4">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[11px] muted-text">{timeLabel}</span>
                  <SeverityBadge severity={event.severity} />
                  <span className={eventRiskFractionClass(event)} data-event-risk-score title="Individual event risk score">
                    {formatEventRiskFraction(event)}
                  </span>
                  <span className="text-sm font-semibold cyber-text">{event.event_type || 'event'}</span>
                </div>
                <p className="mt-1 line-clamp-1 text-xs muted-text">{event.message || event.raw_log || 'No message available'}</p>
                <p className="mt-0.5 text-[11px] muted-text">{event.hostname || event.server_id || 'Unknown host'}</p>
              </div>
            </div>
          )
        })}
        {!rows.length && <p className="py-8 text-center text-sm muted-text">No recent activity yet.</p>}
      </div>
    </Card>
  )
}

function CurrentAttention({ critical, failedLogins, mlAlerts, offlineServers }) {
  const items = [
    Number(critical) > 0 && `${Number(critical).toLocaleString()} critical alerts require review`,
    Number(failedLogins) > 0 && `${Number(failedLogins).toLocaleString()} failed-login events recorded`,
    Number(mlAlerts) > 0 && `${Number(mlAlerts).toLocaleString()} ML-generated alerts identified`,
    Number(offlineServers) > 0 && `${Number(offlineServers).toLocaleString()} monitored servers currently unavailable`,
  ].filter(Boolean)
  return (
    <div className="dash-attention">
      <p className="text-[11px] font-semibold uppercase tracking-wide muted-text">Current Attention</p>
      <div className="mt-2 space-y-1.5">
        {items.map((item) => (
          <div key={item} className="dash-attention-item">{item}</div>
        ))}
        {!items.length && (
          <div className="dash-attention-item is-clear">No elevated attention items in the current scope.</div>
        )}
      </div>
    </div>
  )
}

function RankList({ title, rows, empty }) {
  const items = (rows || []).slice(0, 4)
  return (
    <div className="dash-rank-block">
      <p className="text-[11px] font-semibold uppercase tracking-wide muted-text">{title}</p>
      <div className="mt-1">
        {items.map((row) => (
          <div key={`${row.name}-${row.count}`} className="dash-rank-row">
            <span className="truncate font-mono text-[11px] cyber-text">{row.name || '—'}</span>
            <span className="tabular-nums text-xs muted-text">{Number(row.count || 0).toLocaleString()}</span>
          </div>
        ))}
        {!items.length && <p className="py-2 text-sm muted-text">{empty}</p>}
      </div>
    </div>
  )
}

function riskWidth(score) {
  return `${Math.min(100, Math.max(4, Number(score) || 0))}%`
}

function IsoCube({ className = '' }) {
  return (
    <span className={`iso-cube ${className}`} aria-hidden="true">
      <span className="iso-face iso-top" />
      <span className="iso-face iso-front" />
      <span className="iso-face iso-right" />
    </span>
  )
}

function InfrastructureFloor({ servers, focusedId, onFocus }) {
  const focused = servers.find((server) => server.id === focusedId) || servers[0] || null
  const peakHighRisk = Math.max(...servers.map((server) => Number(server.high_risk_count) || 0), 1)
  return (
    <Card className="dash-enter dash-enter-delay-2 dash-floor-card h-full" padding={false}>
      <div className="dash-floor-title">
        <p className="text-[11px] font-semibold uppercase tracking-wide muted-text">Monitored Infrastructure</p>
        <p className="text-[11px] muted-text">Select a host container for last-known health.</p>
      </div>
      <div className={`dash-floor ${servers.length ? '' : 'dash-floor-empty'}`}>
        <div className="dash-floor-inner">
          <svg className="dash-spokes" viewBox="0 0 100 100" aria-hidden="true">
            {servers.map((server, index) => {
              const pos = padPosition(index, servers.length)
              const x = Number.parseFloat(pos.left)
              const y = Number.parseFloat(pos.top)
              const kind = connectionKind(server)
              return (
                <line
                  key={server.id}
                  x1="50"
                  y1="50"
                  x2={x}
                  y2={y}
                  stroke={kind === 'down' ? '#C9CCC7' : '#111111'}
                  strokeWidth={kind === 'online' ? 1.1 : 0.6}
                  strokeDasharray={kind === 'down' ? '1.8 1.4' : undefined}
                  opacity={kind === 'warn' ? 0.5 : 0.85}
                />
              )
            })}
          </svg>
          <div className="iso-node iso-core">
            <IsoCube className="iso-base" />
            <span className="iso-core-badge">Core</span>
          </div>
          {servers.map((server, index) => {
            const pos = padPosition(index, servers.length)
            const kind = connectionKind(server)
            const isFocused = focused?.id === server.id
            return (
              <button
                key={server.id}
                type="button"
                className={`iso-node is-${kind} ${isFocused ? 'is-focused' : ''}`}
                style={pos}
                onClick={() => onFocus(server.id)}
                aria-label={server.server_name}
              >
                <IsoCube className="iso-base" />
                <IsoCube className="iso-tower" />
                <span className="iso-frame" aria-hidden="true">
                  <span className="iso-face iso-top" />
                  <span className="iso-face iso-front" />
                  <span className="iso-face iso-right" />
                </span>
              </button>
            )
          })}
        </div>
        <div className="dash-overlay">
          {servers.map((server, index) => {
            const pos = padPosition(index, servers.length)
            const kind = connectionKind(server)
            const isFocused = focused?.id === server.id
            const highShare = Math.max(8, Math.round(((Number(server.high_risk_count) || 0) / peakHighRisk) * 100))
            return (
              <button
                key={`${server.id}-card`}
                type="button"
                className={`dash-float is-${kind} ${isFocused ? 'is-focused' : ''}`}
                style={pos}
                onClick={() => onFocus(server.id)}
              >
                <span className="dash-float-kicker">{kind === 'online' ? 'ONLINE' : kind === 'down' ? 'OFFLINE' : 'CHECK'}</span>
                <span className="dash-float-title">{server.server_name}</span>
                <span className="dash-float-row">
                  <span>Risk</span>
                  <span className="dash-float-track"><i style={{ width: riskWidth(server.risk_score) }} /></span>
                  <span>{Number(server.risk_score ?? 0).toFixed(0)}</span>
                </span>
                <span className="dash-float-row">
                  <span>High-risk</span>
                  <span className="dash-float-track"><i style={{ width: `${highShare}%` }} /></span>
                  <span>{Number(server.high_risk_count ?? 0)}</span>
                </span>
              </button>
            )
          })}
        </div>
        <div className="dash-minimap" aria-hidden="true">
          <span className="dash-minimap-core" />
          {servers.map((server, index) => {
            const pos = padPosition(index, servers.length)
            return <span key={server.id} className="dash-minimap-dot" style={pos} />
          })}
        </div>
        {focused && (
          <div className="dash-hud">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-sm font-semibold cyber-text">{focused.server_name}</p>
              <div className="flex items-center gap-2">
                <HealthBadge healthStatus={focused.health_status || focused.status}>
                  {focused.connection_state || focused.status || focused.health_status}
                </HealthBadge>
                <Link to={`/servers/${focused.id}`} className="text-[11px] font-semibold cyber-text underline">
                  Open host
                </Link>
              </div>
            </div>
            <div className="dash-hud-grid">
              <div className="dash-hud-cell">
                <p className="dash-hud-label">Address</p>
                <p className="dash-hud-value">{focused.host}{focused.port ? `:${focused.port}` : ''}</p>
              </div>
              <div className="dash-hud-cell">
                <p className="dash-hud-label">Risk</p>
                <p className="dash-hud-value">{Number(focused.risk_score ?? 0).toFixed(1)}</p>
              </div>
              <div className="dash-hud-cell">
                <p className="dash-hud-label">High-risk</p>
                <p className="dash-hud-value">{Number(focused.high_risk_count ?? 0).toLocaleString()}</p>
              </div>
              <div className="dash-hud-cell">
                <p className="dash-hud-label">SSH</p>
                <p className="dash-hud-value">{focused.connection_latency_ms != null ? `${focused.connection_latency_ms} ms` : '—'}</p>
              </div>
              <div className="dash-hud-cell">
                <p className="dash-hud-label">Last seen</p>
                <p className="dash-hud-value">{formatWhen(focused.last_seen || focused.last_collection)}</p>
              </div>
              <div className="dash-hud-cell">
                <p className="dash-hud-label">OS</p>
                <p className="dash-hud-value">{focused.operating_system || 'Linux'}</p>
              </div>
            </div>
          </div>
        )}
        {!servers.length && <p className="dash-empty-copy">No registered servers yet.</p>}
      </div>
    </Card>
  )
}

function WorkspaceResources({ environment, listing }) {
  const navigate = useNavigate()
  const info = workspaceResources(environment, listing)
  if (!info) return null
  const Icon = environment === LINUX ? Server : Cloud
  // replace: browser Back from the Add screen then returns to Environment Selection, like Cancel.
  const openAdd = () => navigate(info.addPath, { replace: true })
  const addButton = (
    <Button onClick={openAdd} data-add-resource={environment}>
      <Plus className="h-4 w-4" /> {info.addLabel}
    </Button>
  )
  if (info.empty) {
    return (
      <Card className="py-10 text-center" data-workspace-empty={environment}>
        <Icon className="mx-auto mb-3 h-10 w-10 muted-text" />
        <p className="text-xs font-bold uppercase tracking-wide muted-text">{info.label} · {info.resourceLabel}: 0</p>
        <h2 className="mt-2 text-2xl font-bold tracking-tight cyber-text">{info.emptyTitle}</h2>
        <div className="mt-5 flex justify-center">{addButton}</div>
      </Card>
    )
  }
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-3xl border border-[var(--panel-border)] bg-[var(--panel-strong)] px-4 py-3" data-workspace-resources={environment}>
      <div className="flex items-center gap-3">
        <Icon className="h-5 w-5 cyber-text" />
        <p className="text-sm font-semibold cyber-text">{info.label} · {info.resourceLabel}: {info.count}</p>
      </div>
      {addButton}
    </div>
  )
}

function CloudAccountPanel({ cloudSources, summary }) {
  const sources = cloudSources || []
  const connected = sources.filter((source) => source.connection_status === 'CONNECTED').length
  const latest = sources.map((source) => source.last_successful_collection).filter(Boolean).sort().at(-1)
  return (
    <Card className="dash-enter dash-enter-delay-2 h-full" title="Cloud Accounts" subtitle="Read-only security telemetry">
      <div className="space-y-3" data-cloud-account="AZURE">
        <div className="rounded-3xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-4">
          <p className="text-sm font-semibold cyber-text">Microsoft Azure · Azure Log Analytics</p>
          <p className="mt-1 text-xs muted-text">Entra ID sign-in logs and Azure Activity Log via Log Analytics.</p>
          <p className="mt-3 text-xs font-semibold uppercase tracking-wide cyber-text">
            {sources.length ? `${connected} of ${sources.length} source${sources.length === 1 ? '' : 's'} connected` : 'No cloud source'}
          </p>
        </div>
        <div className="grid grid-cols-2 gap-2">
          <CompactMetric label="Cloud events" value={summary.total_events.toLocaleString()} />
          <CompactMetric label="Failed sign-ins" value={summary.failed_logins.toLocaleString()} />
          <CompactMetric label="Sources" value={sources.length} />
          <CompactMetric label="Last collection" value={lastCollectionLabel({ last_successful_collection: latest })} />
        </div>
        <Link to={sources.length ? '/cloud-accounts' : '/cloud-accounts/new'} className="inline-flex text-xs font-semibold cyber-text underline underline-offset-4">
          {sources.length ? 'View cloud accounts' : 'Add a cloud account'}
        </Link>
      </div>
    </Card>
  )
}

export default function Dashboard() {
  const { selectedServerId, selectedServer, servers, isAllServers, refreshServers, setSelectedServerId } = useSelectedServer()
  const { isAdmin } = useAuth()
  const [summary, setSummary] = useState(null)
  const [stats, setStats] = useState(null)
  const [recent, setRecent] = useState([])
  const [alerts, setAlerts] = useState(null)
  const [health, setHealth] = useState(null)
  const [accountSummary, setAccountSummary] = useState(null)
  const [me, setMe] = useState(null)
  const [accountOptions, setAccountOptions] = useState([])
  const [adminAccountId, setAdminAccountId] = useState('')
  const { environment } = useEnvironment()
  const isLinux = environment === LINUX
  const [loading, setLoading] = useState(true)
  const [refreshingStatus, setRefreshingStatus] = useState(false)
  const [focusedId, setFocusedId] = useState(null)
  const [cloudSources, setCloudSources] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    // Registered servers are Linux hosts; cloud telemetry has no server_id.
    const serverId = environment === LINUX ? selectedServerId || null : null
    const summaryAccountId = accountIdForSummaryRequest({ isAdmin, selectedAccountId: adminAccountId })
    const [s, st, r, a, h, acct, profile] = await Promise.all([
      withTimeout(getDashboardSummary(serverId, environment), EMPTY_SUMMARY),
      withTimeout(getEventStats(serverId, environment), EMPTY_STATS),
      withTimeout(getRecentEvents(10, serverId, environment), []),
      withTimeout(getAlertSummary(serverId, environment), EMPTY_ALERTS),
      withTimeout(getHealth(), { database: 'unknown' }),
      withTimeout(getAccountSummary(serverId, summaryAccountId, environment), null),
      withTimeout(getMe(), null),
    ])
    setSummary({ ...EMPTY_SUMMARY, ...(s || {}) })
    setStats({ ...EMPTY_STATS, ...(st || {}) })
    setRecent(Array.isArray(r) ? r : [])
    setAlerts({ ...EMPTY_ALERTS, ...(a || {}) })
    setHealth(h || { database: 'unknown' })
    setAccountSummary(acct)
    setMe(profile)
    setCloudSources(environment === CLOUD ? (await withTimeout(getCloudSources(), null))?.sources || [] : null)
    if (isAdmin || (profile?.role || '').toUpperCase() === 'ADMIN') {
      try {
        const listed = await getAccountList()
        setAccountOptions(listed?.accounts || [])
      } catch {
        setAccountOptions([])
      }
    } else {
      setAccountOptions([])
      setAdminAccountId('')
    }
    if (environment === LINUX) await refreshServers()
    setLoading(false)
  }, [selectedServerId, refreshServers, adminAccountId, environment, isAdmin])

  const handleRefreshStatus = useCallback(async () => {
    setRefreshingStatus(true)
    try {
      await refreshServerStatus(selectedServerId || null)
      setTimeout(load, 1500)
    } finally {
      setRefreshingStatus(false)
    }
  }, [load, selectedServerId])

  useEffect(() => {
    load()
    const id = setInterval(load, 30000)
    const onRefresh = () => load()
    window.addEventListener('defensync:data-refresh', onRefresh)
    window.addEventListener('defensync:server-changed', onRefresh)
    return () => {
      clearInterval(id)
      window.removeEventListener('defensync:data-refresh', onRefresh)
      window.removeEventListener('defensync:server-changed', onRefresh)
    }
  }, [load])

  const hourly = stats?.hourly_trends || []
  const severityData = useMemo(
    () => Object.entries(stats?.by_severity || {}).map(([name, value]) => ({ name, value })),
    [stats],
  )
  const typeData = useMemo(
    () => Object.entries(stats?.by_event_type || {})
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .map(([name, value]) => ({ name: name.length > 18 ? `${name.slice(0, 16)}..` : name, value })),
    [stats],
  )

  const visibleServers = useMemo(
    () => (selectedServerId ? servers.filter((server) => server.id === selectedServerId) : servers),
    [servers, selectedServerId],
  )

  useEffect(() => {
    if (!visibleServers.length) {
      setFocusedId(null)
      return
    }
    if (!focusedId || !visibleServers.some((server) => server.id === focusedId)) {
      setFocusedId(visibleServers[0].id)
    }
  }, [visibleServers, focusedId])

  const topIps = useMemo(() => {
    const raw = stats?.top_source_ips
    if (Array.isArray(raw)) {
      return raw.map((row) => (Array.isArray(row) ? { name: row[0], count: row[1] } : { name: row.ip || row.name, count: row.count }))
    }
    return Object.entries(raw || {}).map(([name, count]) => ({ name, count }))
  }, [stats])
  const topUsers = useMemo(() => {
    const raw = stats?.top_usernames
    if (Array.isArray(raw)) {
      return raw.map((row) => (Array.isArray(row) ? { name: row[0], count: row[1] } : { name: row.username || row.name, count: row.count }))
    }
    return Object.entries(raw || {}).map(([name, count]) => ({ name, count }))
  }, [stats])

  if (loading || !summary || !stats) return <LoadingSpinner label="Loading Security Monitoring..." />

  const onlineRate = summary.total_servers ? Math.round((summary.online_servers / summary.total_servers) * 100) : 0
  const environmentLabel = ENVIRONMENT_LABELS[environment] || environment
  const scopeLabel = !isLinux
    ? 'Cloud Accounts'
    : isAllServers ? 'All Servers' : selectedServer?.server_name || 'Selected Server'
  const dbLabel = health?.database || 'connected'
  return (
    <div className="page-shell dash-page" data-dashboard-environment={environment}>
      <PageHeader
        title={`${environmentLabel} Security Command Center`}
        subtitle={`Security posture across ${scopeLabel} • Database ${dbLabel}`}
        actions={(
          <>
            {isLinux && (
              <Button variant="ghost" onClick={handleRefreshStatus} disabled={refreshingStatus}>
                {refreshingStatus ? 'Checking...' : 'Probe Server Status'}
              </Button>
            )}
            <Button variant="secondary" onClick={() => load()}>
              <RefreshCw className="h-4 w-4" /> Refresh
            </Button>
          </>
        )}
      />

      <WorkspaceResources environment={environment} listing={isLinux ? servers : cloudSources} />

      <div className="dash-scene-bar">
        {(isAdmin || (me?.role || '').toUpperCase() === 'ADMIN') && accountOptions.length > 0 && (
          <select
            className="dash-scene-chip is-active"
            value={adminAccountId}
            onChange={(event) => setAdminAccountId(event.target.value)}
            data-admin-account-scope
          >
            <option value="">Platform overview</option>
            {accountOptions.map((account) => (
              <option key={account.id} value={account.id}>{account.name} — {account.linux_events} Linux</option>
            ))}
          </select>
        )}
        {!isLinux && (
          <span className="dash-scene-chip" title="Read-only Azure Log Analytics sources (Entra sign-ins + Activity Log)">
            Cloud sources: {(cloudSources || []).filter((source) => source.connection_status === 'CONNECTED').length} connected
          </span>
        )}
        {isLinux && (
          <>
            <button
              type="button"
              className={`dash-scene-chip ${isAllServers ? 'is-active' : ''}`}
              onClick={() => setSelectedServerId('')}
            >
              All hosts
            </button>
            {servers.map((server) => (
              <button
                key={server.id}
                type="button"
                className={`dash-scene-chip ${selectedServerId === server.id ? 'is-active' : ''}`}
                onClick={() => setSelectedServerId(server.id)}
              >
                {server.server_name}
              </button>
            ))}
          </>
        )}
      </div>

      <section className="dash-command">
        <div className="dash-rail">
          <SecurityPulse
            summary={summary}
            accountSummary={accountSummary}
            loaded={!loading}
            selectedAccountId={adminAccountId}
            isAdmin={isAdmin || (me?.role || '').toUpperCase() === 'ADMIN'}
            environment={environment}
            critical={alerts?.critical ?? 0}
            failedLogins={summary?.failed_logins}
            mlAlerts={alerts?.ml_anomaly ?? 0}
          />
          <Card className="dash-enter dash-enter-delay-3">
            <CurrentAttention
              critical={alerts?.critical ?? 0}
              failedLogins={summary.failed_logins}
              mlAlerts={alerts?.ml_anomaly ?? 0}
              offlineServers={isLinux ? summary.offline_servers : 0}
            />
            <div className="dash-stage-row mt-3">
              <div className="dash-stage">
                <p className="dash-stage-label">Collect</p>
                <p className="dash-stage-value"><CountUp value={summary.total_events} /></p>
              </div>
              <div className="dash-stage">
                <p className="dash-stage-label">Auth</p>
                <p className="dash-stage-value"><CountUp value={summary.failed_logins} /></p>
              </div>
              <div className="dash-stage">
                <p className="dash-stage-label">Detect</p>
                <p className="dash-stage-value"><CountUp value={alerts?.ml_anomaly ?? 0} /></p>
              </div>
              <div className="dash-stage">
                <p className="dash-stage-label">Alert</p>
                <p className="dash-stage-value"><CountUp value={alerts?.unacknowledged ?? 0} /></p>
              </div>
            </div>
          </Card>
        </div>

        {isLinux ? (
          <InfrastructureFloor
            servers={visibleServers}
            focusedId={focusedId}
            onFocus={setFocusedId}
          />
        ) : (
          <CloudAccountPanel cloudSources={cloudSources} summary={summary} />
        )}

        <div className="dash-rail">
          <SecurityActivity events={recent} />
          <Card title="Activity — 24h" subtitle="Hourly event volume">
            <ResponsiveContainer width="100%" height={108}>
              <AreaChart data={hourly}>
                <defs>
                  <linearGradient id="monoEvents" x1="0" x2="0" y1="0" y2="1">
                    <stop offset="0%" stopColor="#111111" stopOpacity={0.18} />
                    <stop offset="100%" stopColor="#111111" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="rgba(148,163,184,0.12)" strokeDasharray="3 3" />
                <XAxis dataKey="hour" tick={{ fill: '#A5A5A5', fontSize: 9 }} interval="preserveStartEnd" hide />
                <YAxis tick={{ fill: '#A5A5A5', fontSize: 9 }} width={28} />
                <Tooltip {...CHART_TOOLTIP} />
                <Area type="monotone" dataKey="count" stroke="#111111" strokeWidth={2} fill="url(#monoEvents)" />
              </AreaChart>
            </ResponsiveContainer>
          </Card>
          <Card className="dash-enter">
            <div className="dash-rank-grid">
              <RankList title="Top source IPs" rows={topIps} empty="No source IP ranks in this scope." />
              <RankList title="Top usernames" rows={topUsers} empty="No username ranks in this scope." />
            </div>
          </Card>
        </div>
      </section>

      <OperationalSnapshot summary={summary} alerts={alerts} onlineRate={onlineRate} isLinux={isLinux} />

      <section className="grid gap-2">
        <Card title="MY ACCOUNT" subtitle={`${accountSummary?.account_name ? `${accountSummary.account_name} · ` : ''}Private ${environmentLabel} telemetry`}>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
            <CompactMetric label={`${environmentLabel} events`} value={(accountSummary?.events ?? summary.total_events).toLocaleString()} />
            <CompactMetric label="Incidents" value={(accountSummary?.incidents ?? 0).toLocaleString()} />
            <CompactMetric label="High risk" value={(accountSummary?.high_risk_events ?? summary.high_risk ?? 0).toLocaleString()} />
            <CompactMetric label="Anomalies" value={(accountSummary?.anomalies ?? 0).toLocaleString()} />
            {isLinux ? (
              <>
                <CompactMetric label="Servers" value={accountSummary?.servers ?? summary.total_servers} />
                <CompactMetric label="Users" value={accountSummary?.users ?? 0} />
                <CompactMetric label="Profiles" value={accountSummary?.profiles ?? 0} />
              </>
            ) : (
              <>
                <CompactMetric label="Identities" value={accountSummary?.users ?? 0} />
                <CompactMetric label="Failed sign-ins" value={(accountSummary?.failed_logins ?? summary.failed_logins).toLocaleString()} />
              </>
            )}
          </div>
          <p className="mt-2 text-[11px] muted-text">
            {PRIMARY_SCORE_LABEL} is shown once in Security Pulse for this same account, environment, and server scope. Counts above are operational totals, not competing risk scores.
          </p>
        </Card>
      </section>

      <section className="grid gap-2 xl:grid-cols-12">
        <div className="grid gap-2 xl:col-span-8">
          <Card title="Event Types" subtitle="Most frequent signals">
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={typeData} layout="vertical">
                <CartesianGrid stroke="rgba(148,163,184,0.1)" strokeDasharray="3 3" />
                <XAxis type="number" hide />
                <YAxis dataKey="name" type="category" width={110} tick={{ fill: '#6F746F', fontSize: 11 }} />
                <Tooltip {...CHART_TOOLTIP} />
                <Bar dataKey="value" fill="#737373" radius={[0, 8, 8, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </Card>
        </div>

        <div className="grid gap-2 xl:col-span-4">
          <Card title="Event Severity" subtitle="Stored event severity mix">
            <ResponsiveContainer width="100%" height={160}>
              <PieChart>
                <Pie data={severityData} dataKey="value" nameKey="name" innerRadius={48} outerRadius={74} paddingAngle={3}>
                  {severityData.map((item) => <Cell key={item.name} fill={SEVERITY_COLORS[item.name] || '#737373'} />)}
                </Pie>
                <Tooltip {...CHART_TOOLTIP} />
              </PieChart>
            </ResponsiveContainer>
          </Card>

          <Card title="System Health" subtitle="Platform status">
            <div className="grid gap-2">
              <CompactMetric label="Database" value={health?.database || 'unknown'} />
              <CompactMetric label="Unique Users" value={summary.unique_users} />
            </div>
          </Card>
        </div>
      </section>
    </div>
  )
}

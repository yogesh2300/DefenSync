import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Line, LineChart, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import {
  Activity, AlertTriangle, BrainCircuit, CheckCircle2, Clock3, DatabaseZap,
  Server, ShieldAlert, TerminalSquare,
} from 'lucide-react'
import {
  getAlertSummary, getDashboardSummary, getEventStats, getHealth, getRecentEvents,
  refreshServerStatus,
} from '../api/client'
import { useSelectedServer } from '../context/SelectedServerContext'
import Button from '../components/ui/Button'
import Card from '../components/ui/Card'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import PageHeader from '../components/ui/PageHeader'
import RiskWidget from '../components/ui/RiskWidget'
import { SeverityBadge, HealthBadge } from '../components/ui/Badge'

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

function withTimeout(promise, fallback, ms = 1200) {
  return Promise.race([
    promise.catch(() => fallback),
    new Promise((resolve) => {
      setTimeout(() => resolve(fallback), ms)
    }),
  ])
}

function CompactMetric({ label, value, icon: Icon, caption }) {
  return (
    <div className="rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-4">
      <div className="flex items-center justify-between gap-2">
        <p className="text-[11px] font-semibold uppercase tracking-wide muted-text">{label}</p>
        {Icon && <Icon className="h-4 w-4 text-[#A5A5A5]" />}
      </div>
      <p className="mt-2 text-2xl font-bold tracking-tight cyber-text">{value}</p>
      {caption && <p className="mt-1 text-[11px] muted-text">{caption}</p>}
    </div>
  )
}

function ActivityHeatmap({ data }) {
  const values = data.length ? data : Array.from({ length: 24 }, (_, hour) => ({ hour: `${hour}:00`, count: 0 }))
  const max = Math.max(...values.map((item) => item.count || 0), 1)
  return (
    <div className="grid grid-cols-12 gap-1">
      {values.slice(-24).map((item, index) => {
        const opacity = 0.15 + ((item.count || 0) / max) * 0.75
        return (
          <div
            key={`${item.hour}-${index}`}
            title={`${item.hour}: ${item.count || 0} events`}
            className="aspect-square rounded-lg border border-[var(--panel-border)] bg-neutral-300"
            style={{ opacity }}
          />
        )
      })}
    </div>
  )
}

export default function Dashboard() {
  const { selectedServerId, selectedServer, servers, isAllServers, refreshServers } = useSelectedServer()
  const [summary, setSummary] = useState(null)
  const [stats, setStats] = useState(null)
  const [recent, setRecent] = useState([])
  const [alerts, setAlerts] = useState(null)
  const [health, setHealth] = useState(null)
  const [loading, setLoading] = useState(true)
  const [refreshingStatus, setRefreshingStatus] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    const serverId = selectedServerId || null
    const [s, st, r, a, h] = await Promise.all([
      withTimeout(getDashboardSummary(serverId), EMPTY_SUMMARY),
      withTimeout(getEventStats(serverId), EMPTY_STATS),
      withTimeout(getRecentEvents(10, serverId), []),
      withTimeout(getAlertSummary(serverId), EMPTY_ALERTS),
      withTimeout(getHealth(), { database: 'unknown' }),
    ])
    setSummary({ ...EMPTY_SUMMARY, ...(s || {}) })
    setStats({ ...EMPTY_STATS, ...(st || {}) })
    setRecent(Array.isArray(r) ? r : [])
    setAlerts({ ...EMPTY_ALERTS, ...(a || {}) })
    setHealth(h || { database: 'unknown' })
    await refreshServers()
    setLoading(false)
  }, [selectedServerId, refreshServers])

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

  if (loading || !summary || !stats) return <LoadingSpinner label="Loading Security Monitoring..." />

  const onlineRate = summary.total_servers ? Math.round((summary.online_servers / summary.total_servers) * 100) : 0
  const scopeLabel = isAllServers ? 'All Servers' : selectedServer?.server_name || 'Selected Server'

  return (
    <div className="page-shell">
      <PageHeader
        title="DefenSync"
        subtitle={`Security Monitoring - ${scopeLabel} - ${health?.database || 'connected'} database`}
        actions={(
          <>
            <Button variant="secondary" onClick={handleRefreshStatus} disabled={refreshingStatus}>
              {refreshingStatus ? 'Checking...' : 'Refresh Status'}
            </Button>
            <Button variant="secondary" onClick={() => load()}>Refresh</Button>
          </>
        )}
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
        <CompactMetric label="Events" value={summary.total_events} icon={TerminalSquare} />
        <CompactMetric label="Alerts" value={alerts?.unacknowledged ?? 0} icon={ShieldAlert} caption={`${alerts?.critical ?? 0} critical`} />
        <CompactMetric label="Detections" value={alerts?.ml_anomaly ?? 0} icon={BrainCircuit} />
        <CompactMetric label="Failed Login" value={summary.failed_logins} icon={AlertTriangle} />
        <CompactMetric label="Servers" value={summary.total_servers} icon={Server} caption={`${summary.online_servers} online`} />
        <CompactMetric label="Availability" value={`${onlineRate}%`} icon={CheckCircle2} caption={`${summary.offline_servers} offline`} />
      </section>

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-5">
        <CompactMetric label="Healthy" value={summary.healthy_servers ?? summary.online_servers} caption="Passing health checks" />
        <CompactMetric label="Errors" value={summary.servers_with_errors ?? 0} caption="Auth / connection issues" />
        <CompactMetric label="Avg Latency" value={`${summary.average_ssh_latency_ms ?? 0}ms`} caption="SSH probe time" />
        <CompactMetric label="Recent Online" value={summary.recently_connected ?? 0} caption="Connected recently" />
        <CompactMetric label="Recent Offline" value={summary.recently_disconnected ?? 0} caption="Failed recently" />
      </section>

      <section className="grid gap-4 xl:grid-cols-12">
        <div className="grid gap-4 xl:col-span-8">
          <Card title="Threat Overview" subtitle={`Risk, alerts and auth pressure - ${scopeLabel}`}>
            <div className="grid gap-4 lg:grid-cols-[180px_1fr]">
              <RiskWidget score={summary.average_risk_score} label="Risk Score" size="md" />
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <CompactMetric label="Events" value={summary.total_events} />
                <CompactMetric label="Alerts" value={alerts?.unacknowledged ?? 0} />
                <CompactMetric label="Detections" value={alerts?.ml_anomaly ?? 0} />
                <CompactMetric label="Failed Login" value={summary.failed_logins} />
              </div>
            </div>
          </Card>

          <Card title="Security Activity Timeline" subtitle="Newest events" className="flex flex-col">
            <div className="max-h-[320px] space-y-3 overflow-y-auto pr-1">
              {recent.slice(0, 8).map((event, index) => (
                <div key={event.event_id || event.id || index} className="rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={event.severity} />
                    <span className="rounded-full border border-[var(--panel-border)] px-2 py-0.5 text-[10px] muted-text">{event.event_type || 'event'}</span>
                    <span className="ml-auto font-mono text-[10px] muted-text">
                      {event.timestamp ? new Date(event.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '--:--'}
                    </span>
                  </div>
                  <p className="mt-2 line-clamp-1 text-sm cyber-text">{event.message || event.raw_log || 'No message available'}</p>
                  <p className="mt-1 text-[11px] muted-text">{event.hostname || event.server_id || 'Unknown host'}</p>
                </div>
              ))}
              {!recent.length && <p className="py-8 text-center text-sm muted-text">No recent activity yet.</p>}
            </div>
          </Card>

          <div className="grid gap-4 lg:grid-cols-2">
            <Card title="Collection Timeline" subtitle="Hourly activity">
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={hourly}>
                  <defs>
                    <linearGradient id="monoEvents" x1="0" x2="0" y1="0" y2="1">
                      <stop offset="0%" stopColor="#D4D4D4" stopOpacity={0.28} />
                      <stop offset="100%" stopColor="#D4D4D4" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="rgba(148,163,184,0.12)" strokeDasharray="3 3" />
                  <XAxis dataKey="hour" tick={{ fill: '#A5A5A5', fontSize: 10 }} interval="preserveStartEnd" />
                  <YAxis tick={{ fill: '#A5A5A5', fontSize: 10 }} width={32} />
                  <Tooltip {...CHART_TOOLTIP} />
                  <Area type="monotone" dataKey="count" stroke="#D4D4D4" strokeWidth={2} fill="url(#monoEvents)" />
                </AreaChart>
              </ResponsiveContainer>
            </Card>

            <Card title="Risk Trend" subtitle="Event movement">
              <ResponsiveContainer width="100%" height={200}>
                <LineChart data={hourly}>
                  <CartesianGrid stroke="rgba(148,163,184,0.12)" strokeDasharray="3 3" />
                  <XAxis dataKey="hour" tick={{ fill: '#A5A5A5', fontSize: 10 }} />
                  <YAxis tick={{ fill: '#A5A5A5', fontSize: 10 }} width={32} />
                  <Tooltip {...CHART_TOOLTIP} />
                  <Line type="monotone" dataKey="count" stroke="#D4D4D4" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </Card>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <Card title="Event Types" subtitle="Most frequent signals">
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={typeData} layout="vertical">
                  <CartesianGrid stroke="rgba(148,163,184,0.1)" strokeDasharray="3 3" />
                  <XAxis type="number" hide />
                  <YAxis dataKey="name" type="category" width={100} tick={{ fill: '#A5A5A5', fontSize: 10 }} />
                  <Tooltip {...CHART_TOOLTIP} />
                  <Bar dataKey="value" fill="#A3A3A3" radius={[0, 8, 8, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </Card>

            <Card title="Hourly Activity" subtitle="24-hour density">
              <ActivityHeatmap data={hourly} />
              <p className="mt-3 text-[11px] muted-text">Brighter blocks indicate higher collection volume.</p>
            </Card>
          </div>
        </div>

        <div className="grid gap-4 xl:col-span-4">
          <Card title="Server Health" subtitle={isAllServers ? 'Fleet status' : 'Selected server'}>
            <div className="space-y-2">
              {visibleServers.slice(0, 5).map((server) => (
                <div key={server.id} className="flex items-center justify-between gap-3 rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-3">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-semibold cyber-text">{server.server_name}</p>
                    <p className="truncate font-mono text-[11px] muted-text">{server.host}</p>
                  </div>
                  <HealthBadge healthStatus={server.health_status || server.status}>
                    {server.connection_state || server.status}
                  </HealthBadge>
                </div>
              ))}
              {!visibleServers.length && <p className="py-4 text-center text-sm muted-text">No registered servers yet.</p>}
            </div>
          </Card>

          <Card title="Alert Distribution" subtitle="Severity mix">
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie data={severityData} dataKey="value" nameKey="name" innerRadius={45} outerRadius={70} paddingAngle={3}>
                  {severityData.map((item) => <Cell key={item.name} fill={SEVERITY_COLORS[item.name] || '#737373'} />)}
                </Pie>
                <Tooltip {...CHART_TOOLTIP} />
              </PieChart>
            </ResponsiveContainer>
          </Card>

          <Card title="Recent Activity" subtitle="Compact feed">
            <div className="space-y-2">
              {recent.slice(0, 6).map((event, index) => (
                <div key={event.event_id || event.id || index} className="flex items-start gap-2 rounded-xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-2.5">
                  <Clock3 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-neutral-400" />
                  <div className="min-w-0">
                    <p className="truncate text-xs font-medium cyber-text">{event.event_type || 'Event'}</p>
                    <p className="truncate text-[11px] muted-text">{event.message || 'No message'}</p>
                  </div>
                </div>
              ))}
              {!recent.length && <p className="py-4 text-center text-sm muted-text">No events yet.</p>}
            </div>
          </Card>

          <Card title="System Health" subtitle="Platform status">
            <div className="grid gap-2">
              <CompactMetric label="Database" value={health?.database || 'unknown'} icon={DatabaseZap} />
              <CompactMetric label="Unique Users" value={summary.unique_users} icon={Activity} />
              <CompactMetric label="Detection Engine" value="IF + RF Active" icon={BrainCircuit} />
            </div>
          </Card>
        </div>
      </section>
    </div>
  )
}

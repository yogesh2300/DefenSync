import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  collectServer, getAnomalies, getServer, getServerLogs, getServerRisk, getServerStats, testServerConnection,
} from '../api/client'
import PageHeader from '../components/ui/PageHeader'
import StatCard from '../components/ui/StatCard'
import Card from '../components/ui/Card'
import Button from '../components/ui/Button'
import AlertBanner from '../components/ui/AlertBanner'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import DataTable from '../components/ui/DataTable'
import RiskWidget from '../components/ui/RiskWidget'
import { StatusBadge } from '../components/ui/Badge'

const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'logs', label: 'Logs' },
  { id: 'predictions', label: 'Predictions' },
  { id: 'alerts', label: 'Alerts' },
]

const FULL_LOG_SOURCES = [
  'journalctl', 'last', 'lastb', 'who', 'w', 'uptime', 'free', 'df', 'ps', 'ss', 'hostnamectl', 'uname',
]

function apiError(err) {
  const data = err.response?.data
  if (!data) return err.message || 'Request failed'
  if (typeof data.detail === 'string') return data.detail
  if (typeof data.error === 'string') return data.error
  if (Array.isArray(data.detail)) return data.detail.map((d) => d.msg).join(', ')
  return JSON.stringify(data.detail || data.error || data)
}

export default function ServerDetails() {
  const { serverId } = useParams()
  const [server, setServer] = useState(null)
  const [stats, setStats] = useState(null)
  const [logs, setLogs] = useState([])
  const [predictions, setPredictions] = useState([])
  const [risk, setRisk] = useState(null)
  const [tab, setTab] = useState('overview')
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const [srvR, stR, lgR, predR, rkR] = await Promise.allSettled([
        getServer(serverId),
        getServerStats(serverId),
        getServerLogs(serverId, 50),
        getAnomalies(15, serverId),
        getServerRisk(serverId),
      ])

      if (srvR.status === 'rejected') {
        throw srvR.reason
      }

      setServer(srvR.value)
      setStats(stR.status === 'fulfilled' ? stR.value : null)
      setLogs(lgR.status === 'fulfilled' && Array.isArray(lgR.value) ? lgR.value : [])
      setPredictions(predR.status === 'fulfilled' && Array.isArray(predR.value) ? predR.value : [])
      setRisk(rkR.status === 'fulfilled' ? rkR.value : null)

      const partialErrors = [stR, lgR, predR, rkR].filter((result) => result.status === 'rejected')
      if (partialErrors.length) {
        setError('Some server details could not be loaded. Showing available data.')
      }
    } catch (err) {
      setServer(null)
      setStats(null)
      setLogs([])
      setPredictions([])
      setRisk(null)
      setError(apiError(err))
    } finally {
      setLoading(false)
    }
  }, [serverId])

  useEffect(() => { load() }, [load])

  const handleTest = async () => {
    setBusy(true)
    setMessage('')
    try {
      const r = await testServerConnection(serverId)
      setMessage(r.success ? `Connection successful (${r.latency_ms}ms)` : r.message || 'Connection test failed.')
      await load()
    } catch (err) {
      setMessage(apiError(err))
    } finally {
      setBusy(false)
    }
  }

  const handleCollect = async () => {
    setBusy(true)
    setMessage('')
    try {
      setMessage('Running collection...')
      const r = await collectServer(serverId, { tail_lines: 500, log_sources: FULL_LOG_SOURCES })
      const detectionNote = r.detection?.message ? ` — ${r.detection.message}` : ''
      setMessage(`Done: ${r.collected_events ?? r.inserted} events collected${detectionNote}`)
      await load()
    } catch (err) {
      setMessage(apiError(err))
    } finally {
      setBusy(false)
    }
  }

  if (loading) return <LoadingSpinner label="Loading server details..." />

  if (!server) {
    return (
      <div className="page-shell">
        <AlertBanner type="error" message={error || 'Unable to load this server.'} />
        <Link to="/servers"><Button variant="secondary">Back to Servers</Button></Link>
      </div>
    )
  }

  const metricsLog = logs.find((e) => e.cpu_usage || e.memory_usage || e.disk_usage)
  const riskScore = risk?.high_risk_events?.[0]?.risk_score ?? (logs[0]?.risk_score || 0)

  return (
    <div className="space-y-6">
      <PageHeader
        title={server.server_name}
        subtitle="Security Monitoring"
        badge={<StatusBadge status={server.status} />}
        actions={
          <>
            <Link to="/servers"><Button variant="secondary">Back</Button></Link>
            <Link to={`/servers/${serverId}/edit`}><Button variant="secondary">Edit</Button></Link>
            <Button variant="secondary" onClick={handleTest} disabled={busy}>{busy ? 'Testing...' : 'Test SSH'}</Button>
            <Button onClick={handleCollect} disabled={busy}>{busy ? 'Collecting...' : 'Collect Logs'}</Button>
          </>
        }
      />

      {error && <AlertBanner type="error" message={error} />}
      <AlertBanner message={message} />

      <div className="flex flex-wrap gap-2">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
              tab === t.id
                ? 'bg-neutral-500/10 text-neutral-100 border border-neutral-500/20'
                : 'muted-text hover:bg-[var(--panel-strong)] border border-transparent'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'overview' && stats && (
        <>
          <div className="grid lg:grid-cols-4 gap-6">
            <div className="lg:col-span-3 grid grid-cols-2 md:grid-cols-3 gap-4">
              <StatCard label="Total Events" value={stats.event_count} accent="neutral" />
              <StatCard label="High Risk" value={risk?.high_risk_count ?? 0} accent="red" />
              <StatCard label="Collections" value={stats.recent_collections?.length ?? 0} accent="slate" />
              <StatCard label="CPU Usage" value={metricsLog?.cpu_usage != null ? `${metricsLog.cpu_usage}%` : '—'} accent="amber" />
              <StatCard label="Memory" value={metricsLog?.memory_usage != null ? `${metricsLog.memory_usage}%` : '—'} accent="amber" />
              <StatCard label="Disk" value={metricsLog?.disk_usage != null ? `${metricsLog.disk_usage}%` : '—'} accent="amber" />
            </div>
            <RiskWidget score={riskScore} label="Server Risk" size="lg" />
          </div>

          <Card title="Server Information">
            <dl className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4 text-sm">
              <div><dt className="text-xs font-semibold muted-text">Username</dt><dd className="cyber-text mt-1">{server.username}</dd></div>
              <div><dt className="text-xs font-semibold muted-text">Auth Type</dt><dd className="cyber-text mt-1">{server.authentication_type}</dd></div>
              <div><dt className="text-xs font-semibold muted-text">Host</dt><dd className="font-mono text-xs cyber-text mt-1">{server.host}:{server.port}</dd></div>
              <div><dt className="text-xs font-semibold muted-text">Last Connected</dt><dd className="font-mono text-xs cyber-text mt-1">{server.last_connected ? new Date(server.last_connected).toLocaleString() : 'Never'}</dd></div>
              <div><dt className="text-xs font-semibold muted-text">Description</dt><dd className="muted-text mt-1">{server.description || '—'}</dd></div>
            </dl>
          </Card>

          <Card title="Recent Collections">
            <DataTable
              columns={[
                { key: 'started_at', label: 'Started', render: (c) => new Date(c.started_at).toLocaleString() },
                { key: 'status', label: 'Status', render: (c) => <StatusBadge status={c.status} /> },
                { key: 'inserted', label: 'Inserted' },
                { key: 'duration_ms', label: 'Duration', render: (c) => c.duration_ms ? `${c.duration_ms}ms` : '—' },
              ]}
              rows={stats.recent_collections || []}
              emptyMessage="No collections yet."
              keyField="id"
            />
          </Card>
        </>
      )}

      {tab === 'overview' && !stats && (
        <Card title="Overview">
          <p className="text-sm muted-text">Server statistics are unavailable right now.</p>
        </Card>
      )}

      {tab === 'logs' && (
        <Card title="Collected Logs">
          <DataTable
            columns={[
              { key: 'timestamp', label: 'Time', render: (e) => <span className="font-mono text-xs">{new Date(e.timestamp).toLocaleString()}</span> },
              { key: 'event_type', label: 'Type' },
              { key: 'risk_score', label: 'Risk' },
              { key: 'message', label: 'Message', render: (e) => <span className="text-slate-400">{e.message?.slice(0, 100)}</span> },
            ]}
            rows={logs}
            emptyMessage="No logs collected yet."
          />
        </Card>
      )}

      {tab === 'predictions' && (
        <Card title="Predictions">
          <DataTable
            columns={[
              { key: 'timestamp', label: 'Time', render: (p) => <span className="font-mono text-xs">{p.timestamp ? new Date(p.timestamp).toLocaleString() : '—'}</span> },
              { key: 'event_type', label: 'Type' },
              { key: 'detection_type', label: 'Detection', render: (p) => <span className="cyber-text text-xs">{p.detection_type}</span> },
              { key: 'score', label: 'Score', render: (p) => p.anomaly_score ?? p.risk_score },
              { key: 'message', label: 'Message', render: (p) => <span className="text-slate-400">{p.message?.slice(0, 80)}</span> },
            ]}
            rows={predictions}
            keyField="event_id"
            emptyMessage="No predictions yet. Collect logs to run detection automatically."
          />
        </Card>
      )}

      {tab === 'alerts' && (
        <Card title="High-Risk Alerts">
          <DataTable
            columns={[
              { key: 'event_type', label: 'Type' },
              { key: 'risk_score', label: 'Risk', render: (e) => <span className="text-red-400 font-semibold">{e.risk_score}</span> },
              { key: 'message', label: 'Message', render: (e) => e.message?.slice(0, 100) },
            ]}
            rows={risk?.high_risk_events || []}
            keyField="event_id"
            emptyMessage="No high-risk alerts for this server."
          />
        </Card>
      )}
    </div>
  )
}

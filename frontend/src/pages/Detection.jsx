import { useCallback, useEffect, useMemo, useState } from 'react'
import { motion } from 'framer-motion'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { BrainCircuit, Cpu, GitBranch, Network, Radar, RefreshCw, ShieldAlert } from 'lucide-react'
import { getAnomalies, getDetectionStatus } from '../api/client'
import { useSelectedServer } from '../context/SelectedServerContext'
import AlertBanner from '../components/ui/AlertBanner'
import Button from '../components/ui/Button'
import Card from '../components/ui/Card'
import DataTable from '../components/ui/DataTable'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import PageHeader from '../components/ui/PageHeader'
import RiskWidget from '../components/ui/RiskWidget'

const TOOLTIP = {
  contentStyle: {
    background: 'var(--panel-strong)',
    border: '1px solid var(--panel-border)',
    borderRadius: 16,
    color: 'var(--text-main)',
    fontSize: 12,
  },
}

const PIPELINE = [
  { title: 'Vectorize', text: 'Normalize SSH, auth, process and network telemetry', icon: Cpu },
  { title: 'Separate', text: 'Isolation Forest scores unusual behavior', icon: GitBranch },
  { title: 'Classify', text: 'Random Forest labels suspicious activity', icon: BrainCircuit },
  { title: 'Score', text: 'Risk engine stores confidence and alerts', icon: Radar },
]

function MiniPanel({ label, value, icon: Icon, caption }) {
  return (
    <div className="rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-4">
      <div className="mb-3 flex items-center justify-between gap-2">
        <p className="text-[11px] font-semibold uppercase tracking-wide muted-text">{label}</p>
        {Icon && <Icon className="h-4 w-4 text-[#A5A5A5]" />}
      </div>
      <p className="text-2xl font-bold cyber-text">{value}</p>
      {caption && <p className="mt-1 text-[11px] muted-text">{caption}</p>}
    </div>
  )
}

export default function Detection() {
  const { selectedServerId, selectedServer, isAllServers } = useSelectedServer()
  const [status, setStatus] = useState(null)
  const [anomalies, setAnomalies] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    const serverId = selectedServerId || null
    try {
      const [s, a] = await Promise.allSettled([getDetectionStatus(serverId), getAnomalies(25, serverId)])
      if (s.status === 'fulfilled') setStatus(s.value)
      else {
        setStatus({ engine: 'DefenSync Hybrid Detection', events_in_db: 0, ready: false, alerts: {} })
        setError(s.reason?.response?.data?.error || s.reason?.message || 'Failed to load detection status.')
      }
      if (a.status === 'fulfilled') setAnomalies(Array.isArray(a.value) ? a.value : [])
      else {
        setAnomalies([])
        setError(a.reason?.response?.data?.error || a.reason?.message || 'Failed to load anomalies.')
      }
    } catch (err) {
      setStatus({ engine: 'DefenSync Hybrid Detection', events_in_db: 0, ready: false, alerts: {} })
      setAnomalies([])
      setError(err.response?.data?.error || err.response?.data?.detail || err.message || 'Failed to load detection.')
    } finally {
      setLoading(false)
    }
  }, [selectedServerId])

  useEffect(() => {
    load()
    const onRefresh = () => load()
    window.addEventListener('defensync:data-refresh', onRefresh)
    window.addEventListener('defensync:server-changed', onRefresh)
    return () => {
      window.removeEventListener('defensync:data-refresh', onRefresh)
      window.removeEventListener('defensync:server-changed', onRefresh)
    }
  }, [load])

  const anomalySeries = useMemo(() => anomalies.map((item, index) => ({
    name: `D${index + 1}`,
    risk: item.risk_score || 0,
    score: Math.round((item.anomaly_score || 0) * 100),
  })), [anomalies])

  const featureData = [
    { feature: 'Risk', value: anomalies.filter((item) => item.classification === 'Suspicious').length },
    { feature: 'Anomaly', value: anomalies.filter((item) => item.anomaly_score).length },
    { feature: 'Alerts', value: status?.alerts?.unacknowledged ?? 0 },
    { feature: 'Events', value: Math.min(status?.events_in_db ?? 0, 100) },
  ]

  // Derive a live anomaly rate (0-100) from actual DB data for the risk gauge.
  // This is NOT a model accuracy figure; it represents the fraction of
  // flagged events relative to total events in the DB (capped for display).
  const anomalyRate = useMemo(() => {
    const total = status?.events_in_db ?? 0
    if (!total) return 0
    const flagged = anomalies.length
    return Math.min(100, Math.round((flagged / Math.max(total, flagged)) * 100))
  }, [anomalies.length, status?.events_in_db])

  return (
    <div className="page-shell">
      <PageHeader
        title="Detection"
        subtitle={
          isAllServers
            ? 'Security Monitoring - All Servers - updates after log collection'
            : `Security Monitoring - ${selectedServer?.server_name || 'Selected Server'}`
        }
        actions={
          <Button variant="secondary" onClick={load} disabled={loading}>
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        }
      />

      {error && <AlertBanner type="error" message={error} />}

      <section className="grid gap-4 lg:grid-cols-3">
        <Card title="Detection Engine" subtitle={status?.engine || 'Hybrid ML Detection'}>
          <div className="grid gap-4 sm:grid-cols-[160px_1fr]">
            <RiskWidget score={anomalyRate} label="Anomaly %" size="md" />
            <div className="grid gap-3 sm:grid-cols-2">
              <MiniPanel label="Events in DB" value={status?.events_in_db ?? 0} icon={Network} caption="Available for detection" />
              <MiniPanel label="Engine Ready" value={status?.ready ? 'Yes' : 'No'} icon={Cpu} caption={status?.ready ? 'Isolation Forest + Random Forest' : 'Need 10+ events'} />
            </div>
          </div>
        </Card>

        <Card title="Detection Timeline" subtitle="Risk movement">
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={anomalySeries}>
              <defs>
                <linearGradient id="riskGradient" x1="0" x2="0" y1="0" y2="1">
                  <stop offset="0%" stopColor="#B76E79" stopOpacity={0.34} />
                  <stop offset="100%" stopColor="#B76E79" stopOpacity={0.03} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="rgba(148,163,184,0.12)" strokeDasharray="3 3" />
              <XAxis dataKey="name" tick={{ fill: '#A5A5A5', fontSize: 10 }} />
              <YAxis tick={{ fill: '#A5A5A5', fontSize: 10 }} width={28} />
              <Tooltip {...TOOLTIP} />
              <Area dataKey="risk" stroke="#B76E79" fill="url(#riskGradient)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </Card>

        <Card title="Pipeline" subtitle="Processing stages">
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-1">
            {PIPELINE.map((stage, index) => {
              const Icon = stage.icon
              return (
                <motion.div
                  key={stage.title}
                  initial={{ opacity: 0, x: 8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.04 }}
                  className="rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-3"
                >
                  <div className="flex gap-2.5">
                    <div className="rounded-xl border border-neutral-500/20 bg-neutral-500/10 p-2 text-neutral-400">
                      <Icon className="h-4 w-4" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-sm font-semibold cyber-text">{stage.title}</p>
                      <p className="mt-0.5 text-[11px] muted-text">{stage.text}</p>
                    </div>
                  </div>
                </motion.div>
              )
            })}
          </div>
        </Card>
      </section>

      <section className="grid gap-4 lg:grid-cols-[minmax(280px,0.8fr)_minmax(0,1.2fr)]">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-1">
          <Card title="Detection Breakdown" subtitle="Event counts by signal type">
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={featureData}>
                <CartesianGrid stroke="rgba(148,163,184,0.12)" strokeDasharray="3 3" />
                <XAxis dataKey="feature" tick={{ fill: '#A5A5A5', fontSize: 10 }} />
                <YAxis tick={{ fill: '#A5A5A5', fontSize: 10 }} width={28} />
                <Tooltip {...TOOLTIP} />
                <Bar dataKey="value" fill="#A3A3A3" radius={[8, 8, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </Card>

          <Card title="Model Statistics" subtitle="Security Monitoring">
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-1">
              <MiniPanel label="Open Alerts" value={status?.alerts?.unacknowledged ?? 0} icon={ShieldAlert} />
              <MiniPanel label="Detections" value={anomalies.length} icon={BrainCircuit} />
              <MiniPanel label="Anomaly Rate" value={`${anomalyRate}%`} icon={Radar} />
              <MiniPanel label="Prediction Time" value="<1s" icon={Cpu} />
            </div>
          </Card>
        </div>

        <Card title="Recent Predictions" subtitle="Expandable prediction records">
          {loading ? (
            <LoadingSpinner label="Loading detections..." />
          ) : (
            <DataTable
              columns={[
                { key: 'timestamp', label: 'Time', render: (item) => <span className="font-mono text-xs">{item.timestamp ? new Date(item.timestamp).toLocaleString() : '-'}</span> },
                { key: 'hostname', label: 'Host' },
                { key: 'event_type', label: 'Type' },
                { key: 'classification', label: 'Prediction', render: (item) => <span className={item.classification === 'Malicious' ? 'text-red-500 font-semibold' : 'text-amber-600 font-semibold'}>{item.classification || '-'}</span> },
                { key: 'risk_score', label: 'Risk', render: (item) => <span className="font-semibold cyber-text">{item.risk_score}</span> },
              ]}
              rows={anomalies}
              keyField="event_id"
              emptyMessage="No detections yet. Collect logs from a server to run the ML pipeline automatically."
            />
          )}
        </Card>
      </section>
    </div>
  )
}

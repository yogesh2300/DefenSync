import { useCallback, useEffect, useMemo, useState } from 'react'
import { AlertOctagon, CheckCircle2, Clock3, Fingerprint, ShieldAlert } from 'lucide-react'
import { acknowledgeAlert, getAlerts } from '../api/client'
import { useSelectedServer } from '../context/SelectedServerContext'
import AlertBanner from '../components/ui/AlertBanner'
import Button from '../components/ui/Button'
import Card from '../components/ui/Card'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import PageHeader from '../components/ui/PageHeader'
import { SeverityBadge, StatusBadge } from '../components/ui/Badge'
import { Select } from '../components/ui/Input'

const ALERTS_LIMIT = 500

function AlertMetric({ label, value, icon: Icon }) {
  return (
    <div className="rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-4">
      <div className="flex items-center justify-between gap-2">
        <p className="text-[11px] font-semibold uppercase tracking-wide muted-text">{label}</p>
        <Icon className="h-4 w-4 text-[#A5A5A5]" />
      </div>
      <p className="mt-2 text-2xl font-bold cyber-text">{value}</p>
    </div>
  )
}

function AlertRow({ alert, selected, onSelect }) {
  return (
    <button
      type="button"
      onClick={() => onSelect(alert.id)}
      className={`w-full rounded-2xl border p-3 text-left transition hover:-translate-y-0.5 ${
        selected ? 'border-neutral-300 bg-[var(--panel-strong)]' : 'border-[var(--panel-border)] bg-[var(--panel)]'
      }`}
    >
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0 flex-1">
          <div className="mb-1.5 flex flex-wrap items-center gap-2">
            <SeverityBadge severity={alert.severity} />
            <StatusBadge status={alert.acknowledged ? 'online' : 'medium'}>{alert.acknowledged ? 'Resolved' : 'Open'}</StatusBadge>
          </div>
          <p className="text-sm font-semibold cyber-text">{alert.title}</p>
          <p className="mt-0.5 break-words text-xs leading-5 muted-text">{alert.message}</p>
        </div>
        <span className="shrink-0 font-mono text-[10px] muted-text">{new Date(alert.created_at).toLocaleString()}</span>
      </div>
    </button>
  )
}

export default function Alerts() {
  const { selectedServerId, selectedServer, isAllServers } = useSelectedServer()
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('open')
  const [error, setError] = useState('')
  const [selected, setSelected] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const params = { limit: ALERTS_LIMIT }
      if (filter === 'open') params.acknowledged = false
      if (filter === 'acked') params.acknowledged = true
      if (selectedServerId) params.server_id = selectedServerId
      const rows = await getAlerts(params)
      const next = Array.isArray(rows) ? rows : []
      setAlerts(next)
      setSelected((current) => (next.some((alert) => alert.id === current) ? current : next[0]?.id || null))
    } catch (err) {
      setAlerts([])
      setError(err.response?.data?.error || err.response?.data?.detail || err.message || 'Failed to load alerts.')
    } finally {
      setLoading(false)
    }
  }, [filter, selectedServerId])

  useEffect(() => {
    load()
    const id = setInterval(load, 20000)
    const onRefresh = () => load()
    window.addEventListener('defensync:server-changed', onRefresh)
    window.addEventListener('defensync:data-refresh', onRefresh)
    return () => {
      clearInterval(id)
      window.removeEventListener('defensync:server-changed', onRefresh)
      window.removeEventListener('defensync:data-refresh', onRefresh)
    }
  }, [load])

  const selectedAlert = alerts.find((alert) => alert.id === selected) || alerts[0]
  const openCount = alerts.filter((alert) => !alert.acknowledged).length
  const criticalCount = alerts.filter((alert) => alert.severity === 'critical' || alert.severity === 'high').length
  const grouped = useMemo(() => ({
    priority: alerts.filter((alert) => alert.severity === 'critical' || alert.severity === 'high'),
    watch: alerts.filter((alert) => alert.severity !== 'critical' && alert.severity !== 'high'),
  }), [alerts])

  return (
    <div className="page-shell page-fill">
      <PageHeader
        title="Alerts"
        subtitle={isAllServers ? 'Security Monitoring - All Servers' : `Security Monitoring - ${selectedServer?.server_name || 'Selected Server'}`}
        actions={
          <>
            <Select value={filter} onChange={(event) => setFilter(event.target.value)} className="w-44">
              <option value="all">All alerts</option>
              <option value="open">Open only</option>
              <option value="acked">Acknowledged</option>
            </Select>
            <Button variant="secondary" onClick={load}>Refresh</Button>
          </>
        }
      />

      {error && <AlertBanner type="error" message={error} />}

      <section className="grid shrink-0 grid-cols-2 gap-3 lg:grid-cols-4">
        <AlertMetric label="Total Alerts" value={alerts.length} icon={ShieldAlert} />
        <AlertMetric label="Open" value={openCount} icon={AlertOctagon} />
        <AlertMetric label="Priority" value={criticalCount} icon={Fingerprint} />
        <AlertMetric label="Resolved" value={alerts.length - openCount} icon={CheckCircle2} />
      </section>

      <section className="alerts-panels grid min-h-0 flex-1 gap-4 lg:grid-cols-[minmax(0,1.35fr)_minmax(320px,1fr)]">
        <Card padding={false} className="flex h-full min-h-0 flex-col overflow-hidden">
          <div className="shrink-0 border-b border-[var(--panel-border)] p-4">
            <h2 className="text-lg font-semibold cyber-text">Priority Board</h2>
            <p className="text-xs muted-text">Grouped alert cards — scroll inside this panel</p>
          </div>
          {loading ? (
            <LoadingSpinner label="Loading alerts..." />
          ) : (
            <div className="alerts-panel-body panel-scroll p-4 pb-6">
              {[
                ['Priority', grouped.priority],
                ['Watch List', grouped.watch],
              ].map(([label, items]) => (
                <div key={label} className="mb-5 last:mb-0">
                  <div className="sticky top-0 z-10 mb-2 flex items-center justify-between border-b border-[var(--panel-border)]/60 bg-[var(--panel)]/95 py-2 backdrop-blur-sm">
                    <p className="text-sm font-semibold cyber-text">{label}</p>
                    <span className="rounded-full border border-[var(--panel-border)] px-2 py-0.5 text-[11px] muted-text">{items.length}</span>
                  </div>
                  <div className="space-y-2">
                    {items.map((alert) => (
                      <AlertRow
                        key={alert.id}
                        alert={alert}
                        selected={selectedAlert?.id === alert.id}
                        onSelect={setSelected}
                      />
                    ))}
                    {!items.length && (
                      <div className="rounded-2xl border border-dashed border-[var(--panel-border)] bg-[var(--panel-strong)] p-6 text-center">
                        <ShieldAlert className="mx-auto mb-2 h-6 w-6 muted-text" />
                        <p className="text-sm muted-text">No alerts in this group.</p>
                        <p className="mt-1 text-[11px] muted-text">Alerts appear when detection or risk rules trigger.</p>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card padding={false} className="flex h-full min-h-0 flex-col overflow-hidden">
          <div className="shrink-0 border-b border-[var(--panel-border)] p-4">
            <h2 className="text-base font-semibold cyber-text">Investigation Panel</h2>
            <p className="text-sm muted-text">Selected alert details</p>
          </div>
          {selectedAlert ? (
            <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
              <div className="alerts-panel-body panel-scroll p-4">
                <div className="mb-4 flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={selectedAlert.severity} />
                  <StatusBadge status={selectedAlert.acknowledged ? 'online' : 'medium'}>{selectedAlert.acknowledged ? 'Resolved' : 'Open'}</StatusBadge>
                </div>
                <h3 className="break-words text-xl font-semibold cyber-text">{selectedAlert.title}</h3>
                <p className="mt-2 break-words text-sm leading-6 muted-text">{selectedAlert.message}</p>

                <div className="mt-4 grid grid-cols-2 gap-2">
                  <div className="rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-3">
                    <p className="text-[11px] muted-text">Risk Score</p>
                    <p className="mt-1 text-xl font-bold text-red-500">{selectedAlert.risk_score}</p>
                  </div>
                  <div className="rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-3">
                    <p className="text-[11px] muted-text">Created</p>
                    <p className="mt-1 font-mono text-[11px] cyber-text">{new Date(selectedAlert.created_at).toLocaleString()}</p>
                  </div>
                </div>

                <div className="mt-4 space-y-2 border-l border-[var(--panel-border)] pl-3">
                  {['Detected', 'Queued for review', selectedAlert.acknowledged ? 'Resolved' : 'Awaiting response'].map((item) => (
                    <div key={item} className="relative">
                      <span className="absolute -left-[17px] top-1.5 h-1.5 w-1.5 rounded-full bg-neutral-400" />
                      <p className="text-sm cyber-text">{item}</p>
                      <p className="text-[11px] muted-text">Security Monitoring</p>
                    </div>
                  ))}
                </div>

                <div className="mt-4">
                  <p className="mb-2 text-xs font-semibold uppercase tracking-wide muted-text">Raw Event Data</p>
                  <pre className="max-w-full overflow-x-auto whitespace-pre-wrap break-words rounded-2xl border border-[var(--panel-border)] bg-slate-950/80 p-3 text-xs leading-5 text-slate-200">
                    {JSON.stringify(selectedAlert, null, 2)}
                  </pre>
                </div>
              </div>

              <div className="shrink-0 border-t border-[var(--panel-border)] bg-[var(--panel)]/95 p-4 backdrop-blur-sm">
                {!selectedAlert.acknowledged ? (
                  <Button className="w-full sm:w-auto" onClick={() => acknowledgeAlert(selectedAlert.id).then(load)}>
                    <CheckCircle2 className="h-4 w-4" /> Resolve Alert
                  </Button>
                ) : (
                  <p className="text-sm muted-text">This alert has been resolved.</p>
                )}
              </div>
            </div>
          ) : (
            <div className="flex flex-1 flex-col items-center justify-center py-8 text-center">
              <Clock3 className="mb-3 h-8 w-8 muted-text" />
              <p className="text-sm font-medium cyber-text">No alert selected</p>
              <p className="mt-1 text-xs muted-text">Select an alert from the board to inspect details.</p>
            </div>
          )}
        </Card>
      </section>
    </div>
  )
}

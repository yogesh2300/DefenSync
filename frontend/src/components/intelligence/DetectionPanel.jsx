import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { RefreshCw } from 'lucide-react'
import { getDetectionStatus } from '../../api/client'
import { cloudDetectionUnsupportedMessage } from '../../detection/detectionPanel'
import { createQueuedDetectionRefreshController } from '../../detection/queuedDetectionRefresh'
import AlertBanner from '../ui/AlertBanner'
import Button from '../ui/Button'
import Card from '../ui/Card'
import LoadingSpinner from '../ui/LoadingSpinner'

function Metric({ label, value, caption }) {
  return (
    <div className="rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-3" data-detection-metric={label}>
      <p className="text-[10px] font-semibold uppercase tracking-wide muted-text">{label}</p>
      <p className="mt-1 text-xl font-bold tabular-nums cyber-text">{value}</p>
      {caption ? <p className="mt-1 text-[11px] muted-text">{caption}</p> : null}
    </div>
  )
}

export default function DetectionPanel({ isLinux, selectedServerId = null, selectedServer = null, isAllServers = true }) {
  const [status, setStatus] = useState(null)
  const [loading, setLoading] = useState(Boolean(isLinux))
  const [error, setError] = useState('')
  const [refreshNote, setRefreshNote] = useState('')
  const refreshControllerRef = useRef(null)
  if (!refreshControllerRef.current) {
    refreshControllerRef.current = createQueuedDetectionRefreshController()
  }

  const fetchStatus = useCallback(async () => {
    if (!isLinux) {
      setStatus(null)
      setLoading(false)
      setError('')
      return
    }
    setLoading(true)
    setError('')
    const serverId = selectedServerId || null
    try {
      setStatus(await getDetectionStatus(serverId))
    } catch (err) {
      setStatus(null)
      setError(err.response?.data?.error || err.response?.data?.detail || err.message || 'Failed to load detection status.')
    } finally {
      setLoading(false)
    }
  }, [isLinux, selectedServerId])

  const load = useCallback(async () => {
    await refreshControllerRef.current.runLoad(fetchStatus)
  }, [fetchStatus])

  const handleManualRefresh = useCallback(() => {
    refreshControllerRef.current.clear()
    setRefreshNote('')
    void load()
  }, [load])

  useEffect(() => {
    const controller = refreshControllerRef.current
    if (!isLinux) {
      controller.clear()
      setRefreshNote('')
      setStatus(null)
      setLoading(false)
      setError('')
      return undefined
    }

    void load()

    const onDataRefresh = (event) => {
      const outcome = controller.handleDataRefresh(event?.detail, fetchStatus)
      setRefreshNote(outcome.note || '')
    }
    const onServerChanged = () => {
      controller.clear()
      setRefreshNote('')
      void load()
    }

    window.addEventListener('defensync:data-refresh', onDataRefresh)
    window.addEventListener('defensync:server-changed', onServerChanged)
    return () => {
      window.removeEventListener('defensync:data-refresh', onDataRefresh)
      window.removeEventListener('defensync:server-changed', onServerChanged)
      controller.clear()
    }
  }, [fetchStatus, isLinux, load])

  const scopeLabel = isAllServers
    ? 'All accessible Linux servers'
    : (selectedServer?.server_name || 'Selected server')

  if (!isLinux) {
    return (
      <div data-detection-panel="cloud-unsupported">
        <Card title="Detection" subtitle="Linux workspace feature">
          <p className="text-sm muted-text">{cloudDetectionUnsupportedMessage()}</p>
          <div className="mt-3 flex flex-wrap gap-2">
            <Link to="/events" className="rounded-full border border-[var(--panel-border)] bg-white px-3 py-1.5 text-xs font-semibold cyber-text">Open Cloud Events</Link>
            <Link to="/alerts" className="rounded-full border border-[var(--panel-border)] bg-white px-3 py-1.5 text-xs font-semibold cyber-text">Open Cloud Alerts</Link>
          </div>
        </Card>
      </div>
    )
  }

  return (
    <section className="space-y-4" data-detection-panel="linux">
      <Card
        title="Detection"
        subtitle={`Operational counts for ${scopeLabel}. Detection runs automatically after a successful Linux collection.`}
        action={(
          <div className="flex flex-wrap gap-2">
            <Link to="/events" className="inline-flex items-center justify-center rounded-full border border-[#DADDD8] bg-white px-3 py-1.5 text-xs font-semibold text-[#111111] hover:bg-[#F2F3F1]">
              Events
            </Link>
            <Link to="/alerts" className="inline-flex items-center justify-center rounded-full border border-[#DADDD8] bg-white px-3 py-1.5 text-xs font-semibold text-[#111111] hover:bg-[#F2F3F1]">
              Alerts
            </Link>
            <Button variant="secondary" onClick={handleManualRefresh} disabled={loading} data-refresh-detection>
              <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
              Refresh status
            </Button>
          </div>
        )}
      >
        {refreshNote && (
          <div data-queued-detection-refresh-note>
            <AlertBanner type="info" message={refreshNote} />
          </div>
        )}
        {error && <AlertBanner type="error" message={error} />}
        {loading && !status ? (
          <LoadingSpinner label="Loading detection status..." />
        ) : (
          <div className="grid gap-3 sm:grid-cols-2" data-detection-ops-metrics>
            <Metric label="Events in DB" value={status?.events_in_db ?? '—'} caption="Private events in the current Linux scope" />
            <Metric label="Open alerts" value={status?.alerts?.unacknowledged ?? '—'} caption="Unacknowledged alerts from detection status" />
          </div>
        )}
        {!loading && !status && !error && (
          <p className="mt-3 text-sm muted-text">Detection status is unavailable.</p>
        )}
      </Card>
    </section>
  )
}

import { useCallback, useEffect, useMemo, useState } from 'react'
import { Copy, Filter, ListTree, Search } from 'lucide-react'
import { getEvents } from '../api/client'
import { useSelectedServer } from '../context/SelectedServerContext'
import AlertBanner from '../components/ui/AlertBanner'
import Button from '../components/ui/Button'
import Card from '../components/ui/Card'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import PageHeader from '../components/ui/PageHeader'
import { SeverityBadge } from '../components/ui/Badge'
import { Input, Select } from '../components/ui/Input'

export default function Events() {
  const { selectedServerId, servers, isAllServers } = useSelectedServer()
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('')
  const [eventType, setEventType] = useState('')
  const [username, setUsername] = useState('')
  const [startTime, setStartTime] = useState('')
  const [endTime, setEndTime] = useState('')
  const [error, setError] = useState('')
  const [selectedId, setSelectedId] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const params = { limit: 1000, sort_order: 'newest' }
      if (search) params.search = search
      if (severity) params.severity = severity
      if (eventType) params.event_type = eventType
      if (selectedServerId) params.server_id = selectedServerId
      if (username) params.username = username
      if (startTime) params.start_time = new Date(startTime).toISOString()
      if (endTime) params.end_time = new Date(endTime).toISOString()
      const rows = await getEvents(params)
      const next = Array.isArray(rows) ? rows : rows?.items || []
      setEvents(next)
      setSelectedId((current) => current || next[0]?.event_id || next[0]?.id || null)
    } catch (err) {
      setEvents([])
      setError(err.response?.data?.error || err.response?.data?.detail || err.message || 'Failed to load events.')
    } finally {
      setLoading(false)
    }
  }, [search, severity, eventType, selectedServerId, username, startTime, endTime])

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

  const selectedEvent = useMemo(
    () => events.find((event) => (event.event_id || event.id) === selectedId) || events[0],
    [events, selectedId],
  )

  const severityCounts = useMemo(() => events.reduce((acc, event) => {
    const key = event.severity || 'info'
    acc[key] = (acc[key] || 0) + 1
    return acc
  }, {}), [events])

  const copySelected = () => {
    if (!selectedEvent) return
    navigator.clipboard?.writeText(JSON.stringify(selectedEvent, null, 2))
  }

  return (
    <div className="page-shell page-fill flex flex-col">
      <PageHeader
        title="Event Explorer"
        subtitle={`Security Monitoring - ${events.length} events${isAllServers ? '' : ` - ${servers.find((s) => s.id === selectedServerId)?.server_name || 'filtered'}`}`}
        actions={<Button variant="secondary" onClick={load}>Refresh</Button>}
      />

      {error && <AlertBanner type="error" message={error} />}

      <section className="grid min-h-0 flex-1 gap-4 lg:grid-cols-[220px_minmax(0,1fr)_minmax(280px,320px)]">
        <Card title="Filters" subtitle="Refine the stream" className="h-full lg:max-h-[calc(100vh-9.5rem)] lg:overflow-y-auto">
          <div className="space-y-4">
            <Input label="Search" placeholder="Message, IP, host..." value={search} onChange={(e) => setSearch(e.target.value)} />
            {!isAllServers && (
              <div className="rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-3 text-sm">
                <p className="text-xs muted-text">Server scope</p>
                <p className="mt-1 font-medium cyber-text">
                  {servers.find((server) => server.id === selectedServerId)?.server_name || 'Selected server'}
                </p>
              </div>
            )}
            <Select label="Severity" value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="">All severities</option>
              {['critical', 'high', 'medium', 'low', 'info'].map((item) => <option key={item} value={item}>{item}</option>)}
            </Select>
            <Input label="User" value={username} onChange={(e) => setUsername(e.target.value)} />
            <Input label="Event Type" value={eventType} onChange={(e) => setEventType(e.target.value)} />
            <Input label="Start" type="datetime-local" value={startTime} onChange={(e) => setStartTime(e.target.value)} />
            <Input label="End" type="datetime-local" value={endTime} onChange={(e) => setEndTime(e.target.value)} />
            <Button className="w-full" onClick={load}><Filter className="h-4 w-4" /> Apply</Button>
          </div>
        </Card>

        <Card padding={false} className="flex h-full min-h-[480px] flex-col overflow-hidden lg:max-h-[calc(100vh-9.5rem)]">
          <div className="shrink-0 border-b border-[var(--panel-border)] p-4">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <h2 className="text-lg font-semibold cyber-text">Timeline</h2>
                <p className="text-xs muted-text">Click an event to inspect details.</p>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(severityCounts).map(([key, value]) => (
                  <span key={key} className="rounded-full border border-[var(--panel-border)] px-2.5 py-0.5 text-[11px] muted-text">
                    {key}: {value}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {loading ? (
            <LoadingSpinner label="Loading events..." />
          ) : (
            <div className="min-h-0 flex-1 space-y-2 overflow-y-auto p-4">
              {events.map((event, index) => {
                const id = event.event_id || event.id || index
                const selected = selectedEvent && (selectedEvent.event_id || selectedEvent.id) === id
                return (
                  <button
                    key={id}
                    type="button"
                    onClick={() => setSelectedId(id)}
                    className={`w-full rounded-3xl border p-4 text-left transition hover:-translate-y-0.5 ${
                      selected ? 'border-neutral-300 bg-[var(--panel-strong)]' : 'border-[var(--panel-border)] bg-[var(--panel)]'
                    }`}
                  >
                    <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                      <div className="min-w-0">
                        <div className="mb-2 flex flex-wrap items-center gap-2">
                          <SeverityBadge severity={event.severity} />
                          <span className="rounded-full border border-[var(--panel-border)] px-2.5 py-1 text-[11px] muted-text">{event.event_type || 'event'}</span>
                        </div>
                        <p className="line-clamp-2 text-sm cyber-text">{event.message || event.raw_log || 'No message available'}</p>
                        <p className="mt-2 font-mono text-xs muted-text">{event.hostname || event.server_id || 'unknown'} - {event.source_ip || 'local'}</p>
                      </div>
                      <span className="font-mono text-xs muted-text">{event.timestamp ? new Date(event.timestamp).toLocaleString() : '-'}</span>
                    </div>
                  </button>
                )
              })}
              {!events.length && (
                <div className="flex min-h-[240px] flex-col items-center justify-center text-center">
                  <Search className="mb-3 h-8 w-8 muted-text" />
                  <p className="text-base font-semibold cyber-text">No events found</p>
                  <p className="mt-1 max-w-sm text-sm muted-text">Adjust filters or collect logs from a registered server.</p>
                </div>
              )}
            </div>
          )}
        </Card>

        <Card title="Selected Event" subtitle="Raw and normalized details" className="flex h-full min-h-[480px] flex-col lg:max-h-[calc(100vh-9.5rem)]">
          {selectedEvent ? (
            <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto">
              <div className="rounded-3xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-4">
                <div className="mb-3 flex items-center justify-between gap-3">
                  <SeverityBadge severity={selectedEvent.severity} />
                  <Button variant="ghost" size="sm" onClick={copySelected}><Copy className="h-4 w-4" /> Copy</Button>
                </div>
                <p className="text-sm cyber-text">{selectedEvent.message || selectedEvent.raw_log || 'No message available'}</p>
              </div>
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div className="rounded-2xl border border-[var(--panel-border)] p-3">
                  <p className="text-xs muted-text">Host</p>
                  <p className="mt-1 truncate cyber-text">{selectedEvent.hostname || '-'}</p>
                </div>
                <div className="rounded-2xl border border-[var(--panel-border)] p-3">
                  <p className="text-xs muted-text">User</p>
                  <p className="mt-1 truncate cyber-text">{selectedEvent.username || '-'}</p>
                </div>
                <div className="rounded-2xl border border-[var(--panel-border)] p-3">
                  <p className="text-xs muted-text">Risk</p>
                  <p className="mt-1 cyber-text">{selectedEvent.risk_score ?? 0}</p>
                </div>
                <div className="rounded-2xl border border-[var(--panel-border)] p-3">
                  <p className="text-xs muted-text">Source</p>
                  <p className="mt-1 truncate font-mono text-xs cyber-text">{selectedEvent.source_ip || '-'}</p>
                </div>
              </div>
              <div className="min-h-0 flex-1">
                <div className="mb-2 flex items-center gap-2 text-sm font-semibold cyber-text">
                  <ListTree className="h-4 w-4" />
                  JSON
                </div>
                <pre className="h-full max-h-[280px] overflow-auto rounded-2xl border border-[var(--panel-border)] bg-slate-950/80 p-3 text-xs text-slate-200">
                  {JSON.stringify(selectedEvent, null, 2)}
                </pre>
              </div>
            </div>
          ) : (
            <p className="py-12 text-center text-sm muted-text">Select an event to inspect details.</p>
          )}
        </Card>
      </section>
    </div>
  )
}

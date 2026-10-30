import { useCallback, useEffect, useMemo, useState } from 'react'
import { Copy, Filter, ListTree, Search, X } from 'lucide-react'
import { useSearchParams } from 'react-router-dom'
import { getEvents } from '../api/client'
import { EVENT_IDS_FILTER_HINT, parseEventIdsParam } from '../cloud/cloudInvestigation'
import { buildEventsListParams } from '../events/eventsQuery'
import { useEnvironment } from '../context/EnvironmentContext'
import { useSelectedServer } from '../context/SelectedServerContext'
import { ENVIRONMENT_LABELS, LINUX } from '../environment'
import {
  RECORD_KIND_FILTERS, clockNote, collectionTime, formatInstant, primaryTime, primaryTimeLabel, timelineTimeText,
} from '../eventTime'
import AlertBanner from '../components/ui/AlertBanner'
import Button from '../components/ui/Button'
import Card from '../components/ui/Card'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import PageHeader from '../components/ui/PageHeader'
import { SeverityBadge } from '../components/ui/Badge'
import { Input, Select } from '../components/ui/Input'
import { eventRiskFractionClass, formatEventRiskFraction } from '../intelligence/investigation'

const PRESENTATION_ORIGIN = 'PRESENTATION_SIMULATED'

function isPresentationSimulated(event) {
  return (event?.data_origin || '') === PRESENTATION_ORIGIN
}

function eventCollectionId(event) {
  try {
    const meta = typeof event?.normalized_data === 'string' ? JSON.parse(event.normalized_data) : event?.normalized_data
    return meta?.collection_id || meta?.collection_run_id || null
  } catch {
    return null
  }
}

function eventRiskLevelLabel(event) {
  const score = Number(event?.risk_score)
  if (!Number.isFinite(score)) return null
  if (score >= 85) return 'Critical'
  if (score >= 70) return 'High'
  if (score >= 40) return 'Medium'
  return 'Low'
}

export default function Events() {
  const { selectedServerId: linuxServerId, servers } = useSelectedServer()
  const { environment } = useEnvironment()
  const [searchParams, setSearchParams] = useSearchParams()
  const isLinux = environment === LINUX
  const selectedServerId = isLinux ? linuxServerId : ''
  const isAllServers = !selectedServerId
  const eventIdsFilter = useMemo(
    () => parseEventIdsParam(searchParams.get('event_ids')),
    [searchParams],
  )
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('')
  const [eventType, setEventType] = useState('')
  const [recordKind, setRecordKind] = useState('')
  const [username, setUsername] = useState('')
  const [startTime, setStartTime] = useState('')
  const [endTime, setEndTime] = useState('')
  const [error, setError] = useState('')
  const [selectedId, setSelectedId] = useState(null)

  const clearEventIdsFilter = () => {
    const next = new URLSearchParams(searchParams)
    next.delete('event_ids')
    setSearchParams(next, { replace: true })
  }

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const params = buildEventsListParams({
        environment,
        eventIds: eventIdsFilter,
        search,
        severity,
        eventType,
        recordKind,
        selectedServerId,
        username,
        startTime,
        endTime,
      })
      const rows = await getEvents(params)
      const next = Array.isArray(rows) ? rows : rows?.items || []
      setEvents(next)
      setSelectedId(next[0]?.event_id || next[0]?.id || null)
    } catch (err) {
      setEvents([])
      setSelectedId(null)
      setError(err.response?.data?.error || err.response?.data?.detail || err.message || 'Failed to load events.')
    } finally {
      setLoading(false)
    }
  }, [search, severity, eventType, recordKind, selectedServerId, username, startTime, endTime, environment, eventIdsFilter])

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
        subtitle={`${ENVIRONMENT_LABELS[environment]} security events - ${events.length} events${isAllServers ? '' : ` - ${servers.find((s) => s.id === selectedServerId)?.server_name || 'filtered'}`}`}
        actions={<Button variant="secondary" onClick={load}>Refresh</Button>}
      />

      {error && <AlertBanner type="error" message={error} />}
      {eventIdsFilter.length > 0 && (
        <AlertBanner
          type="info"
          message={`${EVENT_IDS_FILTER_HINT} (${eventIdsFilter.length} requested ID${eventIdsFilter.length === 1 ? '' : 's'}).`}
        />
      )}

      <section className="grid min-h-0 flex-1 gap-4 lg:grid-cols-[220px_minmax(0,1fr)_minmax(280px,320px)]">
        <Card title="Filters" subtitle="Refine the stream" className="h-full lg:max-h-[calc(100vh-9.5rem)] lg:overflow-y-auto">
          <div className="space-y-4">
            {eventIdsFilter.length > 0 && (
              <div className="rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-3 text-sm" data-event-ids-filter>
                <p className="text-xs muted-text">Related event IDs</p>
                <p className="mt-1 font-mono text-[11px] cyber-text">{eventIdsFilter.join(', ')}</p>
                <Button className="mt-2 w-full" variant="secondary" onClick={clearEventIdsFilter} data-clear-event-ids>
                  <X className="h-4 w-4" /> Clear ID filter
                </Button>
              </div>
            )}
            <Input label="Search" placeholder={isLinux ? 'Message, IP, host...' : 'Message, IP, identity...'} value={search} onChange={(e) => setSearch(e.target.value)} />
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
            {isLinux && (
              <Select label="Record kind" value={recordKind} onChange={(e) => setRecordKind(e.target.value)}>
                {RECORD_KIND_FILTERS.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
              </Select>
            )}
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
                          <span
                            className={eventRiskFractionClass(event)}
                            data-event-risk-score
                            title="Individual event risk score"
                          >
                            {formatEventRiskFraction(event)}
                          </span>
                          <span className="rounded-full border border-[var(--panel-border)] px-2.5 py-1 text-[11px] muted-text">{event.event_type || 'event'}</span>
                          {isPresentationSimulated(event) && (
                            <span className="rounded-full border border-amber-500/40 bg-amber-500/10 px-2.5 py-1 text-[11px] font-semibold uppercase text-amber-800" data-presentation-simulated data-demo-label>
                              DEMO
                            </span>
                          )}
                          {eventRiskLevelLabel(event) && (
                            <span className="rounded-full border border-[var(--panel-border)] px-2.5 py-1 text-[11px] muted-text" data-event-risk-level>
                              {eventRiskLevelLabel(event)}
                            </span>
                          )}
                        </div>
                        <p className="line-clamp-2 text-sm cyber-text">{event.message || event.raw_log || 'No message available'}</p>
                        <p className="mt-2 font-mono text-xs muted-text">{event.hostname || event.server_id || 'unknown'} - {event.source_ip || 'local'}</p>
                      </div>
                      <span className="font-mono text-xs muted-text" title={primaryTimeLabel(event)}>{timelineTimeText(event)}</span>
                    </div>
                  </button>
                )
              })}
              {!events.length && (
                <div className="flex min-h-[240px] flex-col items-center justify-center text-center" data-events-empty>
                  <Search className="mb-3 h-8 w-8 muted-text" />
                  <p className="text-base font-semibold cyber-text">
                    {eventIdsFilter.length ? 'No authorized events matched' : 'No events found'}
                  </p>
                  <p className="mt-1 max-w-sm text-sm muted-text">
                    {eventIdsFilter.length
                      ? 'Requested event IDs were not returned under your account visibility and current environment filter. Absence of a match does not disclose whether an ID exists elsewhere.'
                      : (isLinux ? 'Adjust filters or collect logs from a registered server.' : 'Adjust filters or connect a cloud account to collect telemetry.')}
                  </p>
                  {eventIdsFilter.length > 0 && (
                    <div className="mt-4 flex flex-wrap justify-center gap-2">
                      <Button variant="secondary" onClick={clearEventIdsFilter}>Clear ID filter</Button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </Card>

        <Card title="Selected Event" subtitle="Raw and normalized details" className="flex h-full min-h-[480px] flex-col lg:max-h-[calc(100vh-9.5rem)]">
          {selectedEvent ? (
            <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto">
              <div className="rounded-3xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-4">
                <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={selectedEvent.severity} />
                    {isPresentationSimulated(selectedEvent) && (
                      <span className="rounded-full border border-amber-500/40 bg-amber-500/10 px-2.5 py-1 text-[11px] font-semibold uppercase text-amber-800" data-presentation-simulated data-demo-label>
                        DEMO — not from Azure
                      </span>
                    )}
                    {eventRiskLevelLabel(selectedEvent) && (
                      <span className="rounded-full border border-[var(--panel-border)] px-2.5 py-1 text-[11px] muted-text" data-event-risk-level>
                        {eventRiskLevelLabel(selectedEvent)}
                      </span>
                    )}
                  </div>
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
                  <p className="mt-1 cyber-text" data-event-risk-score>{formatEventRiskFraction(selectedEvent)}{eventRiskLevelLabel(selectedEvent) ? ` · ${eventRiskLevelLabel(selectedEvent)}` : ''}</p>
                </div>
                <div className="rounded-2xl border border-[var(--panel-border)] p-3">
                  <p className="text-xs muted-text">Data origin</p>
                  <p className="mt-1 truncate font-mono text-xs cyber-text">{selectedEvent.data_origin || 'N/A'}</p>
                </div>
                <div className="rounded-2xl border border-[var(--panel-border)] p-3">
                  <p className="text-xs muted-text">Collection ID</p>
                  <p className="mt-1 truncate font-mono text-xs cyber-text" data-event-collection-id>{eventCollectionId(selectedEvent) || 'N/A'}</p>
                </div>
                <div className="rounded-2xl border border-[var(--panel-border)] p-3">
                  <p className="text-xs muted-text">{primaryTimeLabel(selectedEvent)}</p>
                  <p className="mt-1 font-mono text-xs cyber-text">{formatInstant(primaryTime(selectedEvent))}</p>
                </div>
                <div className="rounded-2xl border border-[var(--panel-border)] p-3">
                  <p className="text-xs muted-text">Collected</p>
                  <p className="mt-1 font-mono text-xs cyber-text">{formatInstant(collectionTime(selectedEvent))}</p>
                </div>
              </div>
              {clockNote(selectedEvent) && (
                <p className="rounded-2xl border border-[var(--panel-border)] p-3 text-xs muted-text">{clockNote(selectedEvent)}</p>
              )}
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

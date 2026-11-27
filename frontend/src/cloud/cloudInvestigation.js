// Pure helpers for the Cloud Investigation panel (read-only baselines + sequence findings).

export const CLOUD_INVESTIGATION_PATH = '/cloud-investigation'
export const EVENTS_PATH = '/events'
export const MAX_RELATED_EVENT_IDS = 50

export const LOOKBACK_OPTIONS = [
  { value: 60, label: 'Last 1 hour' },
  { value: 360, label: 'Last 6 hours' },
  { value: 1440, label: 'Last 24 hours' },
  { value: 10080, label: 'Last 7 days' },
]

export const SEQUENCE_MINUTE_OPTIONS = [
  { value: 30, label: '30 minutes' },
  { value: 60, label: '60 minutes' },
  { value: 240, label: '4 hours' },
  { value: 1440, label: '24 hours' },
]

export const EMPTY_FINDINGS_MESSAGE =
  'No sequence patterns matched in this window. An empty result is not proof of zero risk.'

export const NO_AUTHORIZED_RELATED_EVENTS_MESSAGE =
  'No authorized related event IDs were available on this finding.'

export const EVENT_IDS_FILTER_HINT =
  'Showing only events that match the requested IDs and remain visible under your account, Cloud environment, and Azure live-origin filters.'

export function windowFromLookbackMinutes(lookbackMinutes, now = new Date()) {
  const minutes = Number(lookbackMinutes)
  if (!Number.isFinite(minutes) || minutes < 1) {
    return { error: 'Choose a lookback window of at least 1 minute.' }
  }
  const end = new Date(now)
  const start = new Date(end.getTime() - minutes * 60 * 1000)
  return { start_time: start.toISOString(), end_time: end.toISOString() }
}

export function validateInvestigationWindow({ start_time, end_time, sequence_minutes }) {
  if (!start_time || !end_time) return 'start_time and end_time are required.'
  const start = new Date(start_time)
  const end = new Date(end_time)
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) {
    return 'Start and end times must be valid timestamps.'
  }
  if (end <= start) return 'end_time must be after start_time.'
  const spanMs = end.getTime() - start.getTime()
  if (spanMs < 60 * 1000) return 'Time window is too short.'
  if (spanMs > 30 * 24 * 60 * 60 * 1000) return 'Time window must be at most 30 days.'
  const sequence = Number(sequence_minutes)
  if (!Number.isFinite(sequence) || sequence < 1 || sequence > 1440) {
    return 'sequence_minutes must be between 1 and 1440.'
  }
  return null
}

export function apiErrorMessage(err, fallback = 'Request failed.') {
  return err?.response?.data?.error || err?.response?.data?.detail || err?.message || fallback
}

export function identityLabel(findingOrBaseline) {
  const identity = findingOrBaseline?.cloud_identity || {}
  return (
    identity.user_principal_name
    || identity.display_name
    || identity.object_id
    || identity.caller
    || findingOrBaseline?.actor_id
    || 'Unknown identity'
  )
}

export function eventRefIds(finding) {
  const refs = Array.isArray(finding?.event_refs) ? finding.event_refs : []
  const ids = []
  const seen = new Set()
  for (const ref of refs) {
    const id = typeof ref?.event_id === 'string' ? ref.event_id.trim() : ''
    if (!id || seen.has(id)) continue
    seen.add(id)
    ids.push(id)
    if (ids.length >= MAX_RELATED_EVENT_IDS) break
  }
  return ids
}

export function parseEventIdsParam(value) {
  if (value == null || value === '') return []
  const parts = Array.isArray(value) ? value : String(value).split(',')
  const ids = []
  const seen = new Set()
  for (const part of parts) {
    const id = String(part || '').trim()
    if (!id || seen.has(id)) continue
    seen.add(id)
    ids.push(id)
    if (ids.length >= MAX_RELATED_EVENT_IDS) break
  }
  return ids
}

export function eventsPathForIds(eventIds) {
  const ids = parseEventIdsParam(eventIds)
  if (!ids.length) return EVENTS_PATH
  const params = new URLSearchParams()
  params.set('event_ids', ids.join(','))
  return `${EVENTS_PATH}?${params.toString()}`
}

// Navigates to Events with an explicit event_ids query filter supported by GET /api/v1/events.
// IDs alone never grant access; the Events API still applies account/environment visibility.
export function relatedEventsAction(finding) {
  const eventIds = eventRefIds(finding)
  return {
    path: eventsPathForIds(eventIds),
    deepLinkSupported: eventIds.length > 0,
    eventIds,
    emptyMessage: eventIds.length ? null : NO_AUTHORIZED_RELATED_EVENTS_MESSAGE,
  }
}

export function truncatedMessage(sequencePayload) {
  if (!sequencePayload?.summary?.truncated) return null
  const count = sequencePayload.summary.finding_count
  return `Findings are capped: showing ${count} result${count === 1 ? '' : 's'}. Narrow the window or actor filter to review the remainder.`
}

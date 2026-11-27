// Event Explorer timestamp semantics. The API sends event_time / collection_time as UTC
// instants; both are rendered with the same rules so they can be compared directly.

export const TIME_LABELS = {
  EVENT_TIME: 'Event Time',
  OBSERVED_AT: 'Observed At',
  COLLECTED_AT: 'Collected At (no source time)',
}

export const RECORD_KIND_FILTERS = [
  { value: '', label: 'All records' },
  { value: 'NOT_SNAPSHOT', label: 'Security + system events' },
  { value: 'SECURITY_EVENT', label: 'Security events' },
  { value: 'SYSTEM_EVENT', label: 'System events' },
  { value: 'SYSTEM_SNAPSHOT', label: 'System snapshots' },
]

// Timeline rows only spell out the label when the time is not a source occurrence time.
export function timelineTimeText(event, options) {
  const text = formatInstant(primaryTime(event), options)
  return event?.time_label && event.time_label !== 'EVENT_TIME' ? `${primaryTimeLabel(event)} ${text}` : text
}

export function primaryTimeLabel(event) {
  return TIME_LABELS[event?.time_label] || TIME_LABELS.EVENT_TIME
}

export function primaryTime(event) {
  return event?.event_time || event?.timestamp || null
}

export function collectionTime(event) {
  return event?.collection_time || event?.collection_timestamp || null
}

export function formatInstant(value, { locale, timeZone } = {}) {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '-'
  return date.toLocaleString(locale, { timeZone, timeZoneName: 'short' })
}

// Reported as recorded: the source and DefenSync clocks disagree; neither time is corrected.
export function clockNote(event) {
  const delay = event?.collection_delay_seconds
  if (typeof delay !== 'number' || delay >= 0) return ''
  return `Source time is ${Math.abs(delay).toFixed(1)}s later than collection: the source and DefenSync clocks disagree. Both times are shown as recorded.`
}

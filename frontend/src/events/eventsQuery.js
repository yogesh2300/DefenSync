// Pure Events list query builders (shared by Events page and Cloud Investigation navigation tests).

import { CLOUD } from '../environment.js'
import { parseEventIdsParam } from '../cloud/cloudInvestigation.js'

export const AZURE_LOG_ANALYTICS_ORIGIN = 'AZURE_LOG_ANALYTICS'

export function buildEventsListParams({
  environment,
  eventIds = [],
  search = '',
  severity = '',
  eventType = '',
  recordKind = '',
  selectedServerId = '',
  username = '',
  startTime = '',
  endTime = '',
  limit = 1000,
  sortOrder = 'newest',
} = {}) {
  const params = { limit, sort_order: sortOrder, environment }
  if (search) params.search = search
  if (severity) params.severity = severity
  if (eventType) params.event_type = eventType
  if (recordKind) params.record_kind = recordKind
  if (selectedServerId) params.server_id = selectedServerId
  if (username) params.username = username
  if (startTime) params.start_time = new Date(startTime).toISOString()
  if (endTime) params.end_time = new Date(endTime).toISOString()

  const ids = parseEventIdsParam(eventIds)
  if (ids.length) {
    params.event_ids = ids.join(',')
    // Defense in depth: Cloud Investigation related-event views request Azure live origin.
    // The API also forces this when event_ids + environment=CLOUD are combined.
    if (environment === CLOUD) {
      params.data_origin = AZURE_LOG_ANALYTICS_ORIGIN
    }
  }
  return params
}

export function emptyAuthorizedEventsMessage(hasEventIdsFilter) {
  if (!hasEventIdsFilter) return null
  return 'No authorized events matched'
}

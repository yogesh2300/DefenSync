import { CLOUD } from '../environment.js'
import { azureStatusLabel } from '../cloud/cloudSource.js'

/** Metric cards always reflect the environment summary, not the active list filter. */
export function alertMetricValues(summary) {
  if (!summary || typeof summary !== 'object') {
    return { total: 0, open: 0, priority: 0, resolved: 0 }
  }
  const total = Number(summary.total) || 0
  const open = Number(summary.unacknowledged) || 0
  const priority = Number(summary.priority ?? summary.critical) || 0
  const resolved = Math.max(0, total - open)
  return { total, open, priority, resolved }
}

/** Prefer API alert_priority (event-derived for ML); fall back to stored severity. */
export function alertPriorityLabel(alert) {
  const raw = (alert?.alert_priority || alert?.severity || 'low').toString().toLowerCase()
  return raw === 'info' ? 'low' : raw
}

export function groupAlertsByPriority(alerts) {
  const rows = Array.isArray(alerts) ? alerts : []
  return {
    priority: rows.filter((alert) => {
      const level = alertPriorityLabel(alert)
      return level === 'critical' || level === 'high'
    }),
    watch: rows.filter((alert) => {
      const level = alertPriorityLabel(alert)
      return level !== 'critical' && level !== 'high'
    }),
  }
}

/** Event risk for display: linked event score, else N/A (never invent 75). */
export function formatAlertEventRisk(alert) {
  if (!alert || alert.event_risk_score === null || alert.event_risk_score === undefined || alert.event_risk_score === '') {
    return 'N/A'
  }
  const n = Number(alert.event_risk_score)
  if (!Number.isFinite(n)) return 'N/A'
  return `${n}/100`
}

export function formatAlertAnomalyScore(alert) {
  if (!alert || alert.anomaly_score === null || alert.anomaly_score === undefined || alert.anomaly_score === '') {
    return null
  }
  const n = Number(alert.anomaly_score)
  if (!Number.isFinite(n)) return null
  return n.toFixed(2)
}

/**
 * Empty-board copy. Distinguishes filter/result emptiness from missing ingestion.
 * Azure Connected in the header only means credentials tested successfully.
 */
export function alertEmptyState({
  environment,
  filter = 'open',
  summary = null,
  listError = '',
  cloudSources = null,
} = {}) {
  if (listError) {
    return {
      title: 'Alerts could not be loaded',
      detail: listError,
    }
  }

  const metrics = alertMetricValues(summary)
  const azureLabel = environment === CLOUD ? azureStatusLabel(cloudSources) : null
  const connected = Boolean(azureLabel && /Connected/i.test(azureLabel))

  if (metrics.total > 0 && filter === 'open' && metrics.open === 0) {
    return {
      title: 'No open alerts',
      detail: `${metrics.resolved} resolved alert${metrics.resolved === 1 ? '' : 's'} in this environment. Switch the filter to All alerts or Acknowledged to review them.`,
    }
  }

  if (metrics.total > 0 && filter === 'acked' && metrics.resolved === 0) {
    return {
      title: 'No resolved alerts',
      detail: `${metrics.open} open alert${metrics.open === 1 ? '' : 's'} still need review. Switch to Open only or All alerts.`,
    }
  }

  if (metrics.total === 0 && environment === CLOUD) {
    return {
      title: 'No cloud alerts yet',
      detail: connected
        ? 'Azure is connected, but that only confirms credentials. No matching cloud alerts were found for this account — collect Azure telemetry from Cloud Accounts, or no high-risk cloud events have been alerted yet.'
        : 'No cloud alerts for this account. Connect and collect an Azure Log Analytics source from Cloud Accounts before alerts can appear.',
    }
  }

  if (metrics.total === 0) {
    return {
      title: 'No alerts in this group',
      detail: 'Alerts appear when detection or risk rules trigger for the selected environment.',
    }
  }

  return {
    title: 'No alerts in this group',
    detail: 'Try another severity group or clear the filter.',
  }
}

export function alertListParams({ limit, environment, filter, serverId }) {
  const params = { limit, environment }
  if (filter === 'open') params.acknowledged = false
  if (filter === 'acked') params.acknowledged = true
  if (serverId) params.server_id = serverId
  return params
}

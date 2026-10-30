/**
 * Investigation helpers for DefenSync Intelligence.
 * Keep event risk, account/system risk, and confidence as separate concepts.
 */

import { primaryScoreSeverity } from './primaryScore.js'

const CLOUD_SOURCE_TYPES = new Set(['CLOUD', 'CLOUD_DATASET', 'AZURE'])

export function environmentOf(event) {
  const source = (event?.source_type || 'LINUX').toUpperCase()
  if (source === 'LINUX') return 'LINUX'
  if (CLOUD_SOURCE_TYPES.has(source)) return 'CLOUD'
  if (source === 'HPC') return 'HPC'
  if (source === 'BEHAVIORAL') return 'BEHAVIORAL'
  return 'UNKNOWN'
}

export function sourceOf(event) {
  const environment = environmentOf(event)
  const provider = (event?.provider || '').toUpperCase()
  if (environment === 'BEHAVIORAL') return 'Behavioral'
  if (environment === 'HPC' || provider === 'BGL') return 'BGL'
  if (provider === 'HDFS') return 'HDFS'
  if (environment === 'CLOUD') return provider === 'AZURE' ? 'Azure' : 'OpenStack'
  if (environment === 'UNKNOWN') return 'Unknown'
  return 'Linux'
}

export function actorOf(event) {
  return event?.actor_id || event?.username || event?.user_id || event?.source_ip || 'unknown'
}

export function eventTime(event) {
  const parsed = event?.timestamp ? new Date(event.timestamp).getTime() : 0
  return Number.isFinite(parsed) ? parsed : 0
}

/** Stable id for selection; never depends on list index. */
export function stableEventId(event) {
  if (!event) return ''
  if (event.event_id) return String(event.event_id)
  if (event.id) return String(event.id)
  return `${sourceOf(event)}-${eventTime(event)}-${actorOf(event)}`
}

/**
 * Resolve per-event risk without treating a behavioral 0 as authoritative for Linux rows.
 * Behavioral events use behavioral_risk_score; other families use risk_score first.
 * Missing values are reported as unavailable (not silently zero for display).
 */
export function resolveEventRisk(event) {
  if (!event) {
    return { available: false, score: null, reason: 'No event selected.' }
  }
  const isBehavioral = (event.source_type || '').toUpperCase() === 'BEHAVIORAL'
  if (isBehavioral) {
    if (event.behavioral_risk_score === null || event.behavioral_risk_score === undefined || event.behavioral_risk_score === '') {
      return { available: false, score: null, reason: 'Behavioral risk was not returned for this event.' }
    }
    const n = Number(event.behavioral_risk_score)
    if (!Number.isFinite(n)) {
      return { available: false, score: null, reason: 'Behavioral risk was malformed.' }
    }
    return { available: true, score: n, reason: null }
  }
  // Explicit zero is a valid score; only null/undefined/'' are missing.
  if (event.risk_score !== null && event.risk_score !== undefined && event.risk_score !== '') {
    const n = Number(event.risk_score)
    if (!Number.isFinite(n)) {
      return { available: false, score: null, reason: 'Event risk_score was malformed.' }
    }
    return { available: true, score: n, reason: null }
  }
  // Number 0 is falsy in boolean checks elsewhere; accept it here via typeof.
  if (typeof event.risk_score === 'number' && Number.isFinite(event.risk_score)) {
    return { available: true, score: event.risk_score, reason: null }
  }
  return { available: false, score: null, reason: 'Event risk was not returned by the API.' }
}

/** Numeric helper for sorting/filters; missing risk sorts as 0 without claiming it is measured. */
export function riskOf(event) {
  const resolved = resolveEventRisk(event)
  return resolved.available ? resolved.score : 0
}

export function formatEventRisk(event) {
  const resolved = resolveEventRisk(event)
  if (!resolved.available) return 'Unavailable'
  return resolved.score
}

/** Compact UI label: `65/100`, `0/100`, or `N/A` when the API omitted risk. */
export function formatEventRiskFraction(event) {
  const resolved = resolveEventRisk(event)
  if (!resolved.available) return 'N/A'
  return `${resolved.score}/100`
}

/** Color class for individual event scores (same bands as RiskWidget / primaryScoreSeverity). */
export function eventRiskFractionClass(event) {
  const resolved = resolveEventRisk(event)
  if (!resolved.available) return 'text-xs font-semibold tabular-nums muted-text'
  const level = primaryScoreSeverity(resolved.score).level
  const tone = {
    critical: 'text-red-400',
    high: 'text-orange-400',
    medium: 'text-amber-400',
    low: 'text-emerald-400',
  }[level] || 'cyber-text'
  return `text-xs font-semibold tabular-nums ${tone}`
}

/**
 * Prefer backend incidents that hydrate against loaded events; otherwise keep local correlations.
 */
export function mergeCorrelations(backendIncidents, localCorrelations, events) {
  if (!Array.isArray(backendIncidents) || backendIncidents.length === 0) {
    return localCorrelations || []
  }
  const mapped = backendIncidents.map((item) => {
    const related = (item.event_ids || [])
      .map((id) => (events || []).find((event) => event.event_id === id || event.id === id))
      .filter(Boolean)
    return {
      id: item.incident_id || item.id,
      actor: item.actor,
      environment: item.environment || 'UNKNOWN',
      confidence: item.confidence,
      evidence: item.evidence || [],
      relatedEvents: related,
      latestEvent: related[related.length - 1],
      score: item.risk_score,
      sources: String(item.source || '').split(',').filter(Boolean),
      explanation: item.explanation,
      recommendation: item.recommendation,
    }
  })
  const usable = mapped.filter(
    (item) => (item.relatedEvents && item.relatedEvents.length > 0) || (item.evidence && item.evidence.length >= 2),
  )
  return usable.length ? usable : (localCorrelations || [])
}

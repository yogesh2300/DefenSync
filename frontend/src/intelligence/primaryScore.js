/**
 * Authoritative account/system risk for Dashboard Security Pulse and Intelligence.
 * Source of truth: backend average_risk_score (AVG of in-scope security event risk_score).
 * Same field is returned by GET /dashboard and GET /account/summary.
 *
 * Admin account filtering uses GET /account/summary?account_id=… only. The backend rejects
 * account_id for non-admins. GET /dashboard never accepts account_id.
 */

export const PRIMARY_SCORE_LABEL = 'Account / system risk'

export const PRIMARY_SCORE_EXPLANATION =
  'Average of in-scope security event risk scores (0–100). Same calculation as the Dashboard Security Pulse. Not Isolation Forest readiness, not stored prediction count, and not investigation confidence.'

/** Severity bands shared by Dashboard RiskWidget and Intelligence primary score badge. */
export function primaryScoreSeverity(score) {
  const normalized = Math.min(100, Math.max(0, Number(score) || 0))
  if (normalized >= 80) return { label: 'Critical', variant: 'critical', level: 'critical' }
  if (normalized >= 60) return { label: 'High', variant: 'high', level: 'high' }
  if (normalized >= 40) return { label: 'Medium', variant: 'medium', level: 'medium' }
  return { label: 'Low', variant: 'low', level: 'low' }
}

/**
 * Only admins may request a foreign account summary. Ordinary users always send null;
 * the backend still enforces AuthorizationError if account_id is forged.
 */
export function accountIdForSummaryRequest({ isAdmin = false, selectedAccountId = null } = {}) {
  if (!isAdmin) return null
  if (selectedAccountId == null) return null
  const id = String(selectedAccountId).trim()
  return id || null
}

function eventCount(source) {
  return Number(source?.total_events ?? source?.events ?? 0)
}

function environmentMatches(source, expectedEnvironment) {
  if (!expectedEnvironment || !source?.environment) return true
  return String(source.environment).toUpperCase() === String(expectedEnvironment).toUpperCase()
}

/** True when a summary has in-scope events and a finite average_risk_score. */
export function isUsableScoreSource(source) {
  if (!source || typeof source !== 'object') return false
  const events = eventCount(source)
  if (!Number.isFinite(events) || events <= 0) return false
  if (source.average_risk_score === null || source.average_risk_score === undefined) return false
  return Number.isFinite(Number(source.average_risk_score))
}

/**
 * Choose the score payload without mixing admin-selected account scope with platform dashboard.
 * When selectedAccountId is set (admin), only the matching account summary is eligible.
 */
export function pickScoreSource(
  summary = null,
  accountSummary = null,
  {
    selectedAccountId = null,
    isAdmin = false,
    expectedEnvironment = null,
  } = {},
) {
  const scopedAccountId = accountIdForSummaryRequest({ isAdmin, selectedAccountId })

  if (scopedAccountId) {
    if (
      isUsableScoreSource(accountSummary)
      && String(accountSummary.account_id || '') === scopedAccountId
      && environmentMatches(accountSummary, expectedEnvironment)
    ) {
      return accountSummary
    }
    // Never fall back to platform/dashboard averages for a different account.
    return null
  }

  if (isUsableScoreSource(summary) && environmentMatches(summary, expectedEnvironment)) {
    return summary
  }

  if (isUsableScoreSource(accountSummary) && environmentMatches(accountSummary, expectedEnvironment)) {
    // Admin platform overview: do not silently use a tenant-specific account summary.
    if (isAdmin && accountSummary.account_id) return isUsableScoreSource(summary) ? summary : null
    return accountSummary
  }

  return null
}

/**
 * Resolve the shared primary security score without inventing a competing formula.
 * Missing or empty scope → unavailable (never treat as zero-risk).
 */
export function resolvePrimarySecurityScore({
  summary = null,
  accountSummary = null,
  loaded = true,
  selectedAccountId = null,
  isAdmin = false,
  expectedEnvironment = null,
} = {}) {
  if (!loaded) {
    return unavailable('Security score is still loading.')
  }

  const scopedAccountId = accountIdForSummaryRequest({ isAdmin, selectedAccountId })
  const source = pickScoreSource(summary, accountSummary, {
    selectedAccountId,
    isAdmin,
    expectedEnvironment,
  })

  if (scopedAccountId && source == null) {
    if (!accountSummary) {
      return unavailable('Account / system risk is unavailable for the selected account because account summary did not load.')
    }
    if (String(accountSummary.account_id || '') !== scopedAccountId) {
      return unavailable('Account / system risk is unavailable because the loaded summary does not match the selected account.')
    }
    if (!environmentMatches(accountSummary, expectedEnvironment)) {
      return unavailable('Account / system risk is unavailable because the loaded summary does not match the selected environment.')
    }
    return unavailable('Insufficient data: no in-scope security events to average for the selected account yet.')
  }

  if (source == null) {
    const candidate = summary ?? accountSummary
    if (candidate) {
      if (eventCount(candidate) <= 0) {
        return unavailable('Insufficient data: no in-scope security events to average yet.')
      }
      if (candidate.average_risk_score === null || candidate.average_risk_score === undefined) {
        return unavailable('Insufficient data: average risk score was not returned by the API.')
      }
      if (!Number.isFinite(Number(candidate.average_risk_score))) {
        return unavailable('Insufficient data: average risk score was not a valid number.')
      }
    }
    return unavailable('Security score is unavailable because risk summary data did not load for the current scope.')
  }

  const events = eventCount(source)
  if (!Number.isFinite(events) || events <= 0) {
    return unavailable('Insufficient data: no in-scope security events to average yet.')
  }

  if (source.average_risk_score === null || source.average_risk_score === undefined) {
    return unavailable('Insufficient data: average risk score was not returned by the API.')
  }

  const numeric = Number(source.average_risk_score)
  if (!Number.isFinite(numeric)) {
    return unavailable('Insufficient data: average risk score was not a valid number.')
  }

  return {
    available: true,
    score: Math.min(100, Math.max(0, Math.round(numeric))),
    label: PRIMARY_SCORE_LABEL,
    explanation: PRIMARY_SCORE_EXPLANATION,
    reason: null,
    environment: source.environment || expectedEnvironment || null,
    accountId: source.account_id ?? null,
    scope: scopedAccountId ? 'account' : (source.scope || null),
  }
}

function unavailable(reason) {
  return {
    available: false,
    score: null,
    label: PRIMARY_SCORE_LABEL,
    explanation: PRIMARY_SCORE_EXPLANATION,
    reason,
    environment: null,
    accountId: null,
    scope: null,
  }
}

/** Count primary score gauges meant for account/system risk on the Intelligence page markup. */
export function countPrimaryScoreGaugeMarkers(source) {
  const markers = [
    /data-primary-security-score/g,
    /data-risk-analysis-primary-gauge/g,
  ]
  return markers.reduce((sum, pattern) => sum + ((String(source).match(pattern) || []).length), 0)
}

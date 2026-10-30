import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { readFileSync } from 'node:fs'
import {
  eventRiskFractionClass,
  formatEventRisk,
  formatEventRiskFraction,
  mergeCorrelations,
  resolveEventRisk,
  riskOf,
  stableEventId,
} from '../src/intelligence/investigation.js'
import {
  isUsableScoreSource,
  pickScoreSource,
  resolvePrimarySecurityScore,
} from '../src/intelligence/primaryScore.js'

const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), 'utf8')

describe('investigation risk and correlation mapping', () => {
  it('does not let behavioral_risk_score 0 hide Linux risk_score', () => {
    const linux = {
      source_type: 'LINUX',
      event_id: 'linux-1',
      behavioral_risk_score: 0,
      risk_score: 65,
      behavioral_classification: 'INSUFFICIENT_BASELINE',
    }
    assert.deepEqual(resolveEventRisk(linux), { available: true, score: 65, reason: null })
    assert.equal(riskOf(linux), 65)
    assert.equal(formatEventRisk(linux), 65)
  })

  it('keeps behavioral risk for behavioral events and marks missing risk unavailable', () => {
    assert.equal(resolveEventRisk({ source_type: 'BEHAVIORAL', behavioral_risk_score: 72 }).score, 72)
    assert.equal(resolveEventRisk({ source_type: 'LINUX', event_id: 'x' }).available, false)
    assert.equal(formatEventRisk({ source_type: 'LINUX', event_id: 'x' }), 'Unavailable')
    assert.equal(formatEventRisk(null), 'Unavailable')
  })

  it('formats individual event risk as N/A, 0/100, or score/100 without confusing average risk', () => {
    assert.equal(formatEventRiskFraction({ source_type: 'LINUX', risk_score: 65 }), '65/100')
    assert.equal(formatEventRiskFraction({ source_type: 'CLOUD', risk_score: 0 }), '0/100')
    assert.equal(formatEventRiskFraction({ source_type: 'LINUX', event_id: 'missing' }), 'N/A')
    assert.equal(formatEventRiskFraction(null), 'N/A')
    assert.match(eventRiskFractionClass({ source_type: 'LINUX', risk_score: 85 }), /text-red-400/)
    assert.match(eventRiskFractionClass({ source_type: 'LINUX', risk_score: 20 }), /text-emerald-400/)
    assert.match(eventRiskFractionClass({ source_type: 'LINUX', event_id: 'x' }), /muted-text/)

    const dashboard = source('pages/Dashboard.jsx')
    const eventsPage = source('pages/Events.jsx')
    const intelligence = source('pages/Intelligence.jsx')
    assert.match(dashboard, /formatEventRiskFraction/)
    assert.match(dashboard, /data-event-risk-score/)
    assert.match(dashboard, /data-risk-score-caption/)
    assert.match(dashboard, /Overall Risk Score represents the average risk/)
    assert.match(dashboard, /RiskWidget/)
    assert.match(eventsPage, /formatEventRiskFraction/)
    assert.match(eventsPage, /data-event-risk-score/)
    assert.match(intelligence, /EvidenceTimeline/)
    assert.match(intelligence, /formatEventRiskFraction/)
    assert.doesNotMatch(intelligence, /anomaly_score.*formatEventRiskFraction|formatEventRiskFraction.*anomaly_score/)
  })

  it('uses stable event ids without list index', () => {
    const event = { event_id: 'abc', source_type: 'LINUX' }
    assert.equal(stableEventId(event), 'abc')
    assert.equal(stableEventId({ id: 'legacy', source_type: 'LINUX' }), 'legacy')
    const intelligence = source('pages/Intelligence.jsx')
    assert.match(intelligence, /stableEventId/)
    assert.match(intelligence, /mergeCorrelations/)
    assert.match(intelligence, /formatEventRisk/)
  })

  it('falls back to local correlations when backend incidents do not hydrate', () => {
    const local = [{ id: 'local-1', actor: 'root', evidence: ['a', 'b'], relatedEvents: [{ event_id: 'e1' }] }]
    const backend = [{ incident_id: 'inc-1', actor: 'root', event_ids: ['missing'], evidence: ['only-one'], risk_score: 90 }]
    const merged = mergeCorrelations(backend, local, [{ event_id: 'e1' }])
    assert.equal(merged, local)
    const hydrated = mergeCorrelations(
      [{ incident_id: 'inc-2', actor: 'root', event_ids: ['e1'], evidence: ['a', 'b'], risk_score: 80, confidence: 70 }],
      local,
      [{ event_id: 'e1' }],
    )
    assert.equal(hydrated.length, 1)
    assert.equal(hydrated[0].id, 'inc-2')
    assert.equal(hydrated[0].relatedEvents.length, 1)
  })
})

describe('primary score source fallback', () => {
  it('prefers account summary when dashboard summary is empty or timed out for ordinary scope', () => {
    assert.equal(isUsableScoreSource({ total_events: 0, average_risk_score: 0 }), false)
    assert.equal(isUsableScoreSource({ events: 45, average_risk_score: 40 }), true)
    const picked = pickScoreSource(
      { total_events: 0, average_risk_score: 0 },
      { events: 45, average_risk_score: 40, environment: 'LINUX' },
      { isAdmin: false, expectedEnvironment: 'LINUX' },
    )
    assert.equal(picked.average_risk_score, 40)
    const resolved = resolvePrimarySecurityScore({
      summary: { total_events: 0, average_risk_score: 0 },
      accountSummary: { events: 45, average_risk_score: 40, environment: 'LINUX' },
      loaded: true,
      isAdmin: false,
      expectedEnvironment: 'LINUX',
    })
    assert.equal(resolved.available, true)
    assert.equal(resolved.score, 40)
  })

  it('keeps Dashboard and Intelligence on the same resolver with account fallback', () => {
    const dashboard = source('pages/Dashboard.jsx')
    const intelligence = source('pages/Intelligence.jsx')
    assert.match(dashboard, /accountSummary=\{accountSummary\}/)
    assert.match(dashboard, /loaded=\{!loading\}/)
    assert.match(dashboard, /selectedAccountId=\{adminAccountId\}/)
    assert.match(intelligence, /resolvePrimarySecurityScore/)
    assert.match(intelligence, /getDashboardSummary\(serverId, environment\)/)
    assert.match(intelligence, /accountIdForSummaryRequest/)
  })
})

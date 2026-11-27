import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import {
  alertEmptyState,
  alertListParams,
  alertMetricValues,
  alertPriorityLabel,
  formatAlertAnomalyScore,
  formatAlertEventRisk,
  groupAlertsByPriority,
} from '../src/alerts/alertBoard.js'
import { readFileSync } from 'node:fs'

describe('cloud alert board mapping', () => {
  it('uses summary totals independent of the open-only list filter', () => {
    assert.deepEqual(
      alertMetricValues({ total: 1, unacknowledged: 0, priority: 1, critical: 0 }),
      { total: 1, open: 0, priority: 1, resolved: 1 },
    )
    assert.deepEqual(alertMetricValues(null), { total: 0, open: 0, priority: 0, resolved: 0 })
    assert.deepEqual(
      alertListParams({ limit: 500, environment: 'CLOUD', filter: 'open', serverId: null }),
      { limit: 500, environment: 'CLOUD', acknowledged: false },
    )
    assert.equal(
      alertListParams({ limit: 500, environment: 'CLOUD', filter: 'all', serverId: null }).acknowledged,
      undefined,
    )
  })

  it('groups severity for the priority board without inventing alerts', () => {
    const grouped = groupAlertsByPriority([
      { id: '1', severity: 'high' },
      { id: '2', severity: 'critical' },
      { id: '3', severity: 'medium' },
    ])
    assert.equal(grouped.priority.length, 2)
    assert.equal(grouped.watch.length, 1)
  })

  it('uses alert_priority over legacy inflated severity and formats event vs anomaly scores', () => {
    assert.equal(alertPriorityLabel({ severity: 'high', alert_priority: 'low' }), 'low')
    assert.equal(formatAlertEventRisk({ event_risk_score: 0 }), '0/100')
    assert.equal(formatAlertEventRisk({ event_risk_score: 65 }), '65/100')
    assert.equal(formatAlertEventRisk({}), 'N/A')
    assert.equal(formatAlertEventRisk({ event_risk_score: null }), 'N/A')
    assert.equal(formatAlertAnomalyScore({ anomaly_score: 0.68 }), '0.68')
    assert.equal(formatAlertAnomalyScore({}), null)
    const grouped = groupAlertsByPriority([
      { id: 'legacy-ml', severity: 'high', alert_priority: 'low', event_risk_score: 0 },
      { id: 'real-high', severity: 'high', alert_priority: 'high', event_risk_score: 85 },
    ])
    assert.equal(grouped.priority.map((a) => a.id).join(','), 'real-high')
    assert.equal(grouped.watch.map((a) => a.id).join(','), 'legacy-ml')
    const page = readFileSync(new URL('../src/pages/Alerts.jsx', import.meta.url), 'utf8')
    assert.match(page, /formatAlertEventRisk/)
    assert.match(page, /formatAlertAnomalyScore/)
    assert.match(page, /Event Risk Score/)
    assert.match(page, /ML Anomaly Score/)
    assert.match(page, /Alert Priority/)
    assert.match(page, /Event Severity/)
  })

  it('explains open-filter emptiness when only resolved cloud alerts exist', () => {
    const copy = alertEmptyState({
      environment: 'CLOUD',
      filter: 'open',
      summary: { total: 1, unacknowledged: 0, priority: 1 },
      cloudSources: { sources: [{ connection_status: 'CONNECTED' }] },
    })
    assert.match(copy.title, /No open alerts/i)
    assert.match(copy.detail, /resolved/i)
    assert.match(copy.detail, /All alerts|Acknowledged/i)
  })

  it('explains Azure Connected does not mean alerts were ingested', () => {
    const copy = alertEmptyState({
      environment: 'CLOUD',
      filter: 'all',
      summary: { total: 0, unacknowledged: 0, priority: 0 },
      cloudSources: [{ connection_status: 'CONNECTED' }],
    })
    assert.match(copy.title, /No cloud alerts/i)
    assert.match(copy.detail, /connected/i)
    assert.match(copy.detail, /credentials|telemetry|Cloud Accounts/i)
  })

  it('keeps Linux empty copy free of Azure connection wording', () => {
    const copy = alertEmptyState({
      environment: 'LINUX',
      filter: 'open',
      summary: { total: 0, unacknowledged: 0, priority: 0 },
    })
    assert.doesNotMatch(copy.detail, /Azure/i)
  })

  it('surfaces API errors without fabricating counts', () => {
    const copy = alertEmptyState({
      environment: 'CLOUD',
      listError: 'Failed to load alerts.',
      summary: { total: 9, unacknowledged: 9, priority: 9 },
    })
    assert.match(copy.title, /could not be loaded/i)
    assert.equal(copy.detail, 'Failed to load alerts.')
  })
})

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { describe, it } from 'node:test'
import {
  PRIMARY_SCORE_LABEL,
  countPrimaryScoreGaugeMarkers,
  primaryScoreSeverity,
  resolvePrimarySecurityScore,
} from '../src/intelligence/primaryScore.js'
import {
  additionalEligibleEventsNeeded,
  linuxModelView,
  predictionsEmptyGuidance,
} from '../src/detection/linuxStatus.js'

const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), 'utf8')

describe('primary security score consolidation', () => {
  it('uses the same severity bands for a score of 40 on Dashboard and Intelligence', () => {
    assert.equal(primaryScoreSeverity(40).level, 'medium')
    assert.equal(primaryScoreSeverity(40).label, 'Medium')
    assert.equal(primaryScoreSeverity(39).level, 'low')
    assert.equal(primaryScoreSeverity(60).level, 'high')
    assert.equal(primaryScoreSeverity(80).level, 'critical')
    const widget = source('components/ui/RiskWidget.jsx')
    assert.match(widget, /primaryScoreSeverity/)
    const intelligence = source('pages/Intelligence.jsx')
    assert.match(intelligence, /primaryScoreSeverity/)
    assert.doesNotMatch(intelligence, /function postureLevel/)
  })

  it('shares Dashboard average_risk_score as the authoritative account/system risk', () => {
    const fromDashboard = resolvePrimarySecurityScore({
      summary: { total_events: 45, average_risk_score: 40, environment: 'LINUX' },
      loaded: true,
    })
    const fromAccount = resolvePrimarySecurityScore({
      accountSummary: { events: 45, average_risk_score: 40, environment: 'LINUX' },
      loaded: true,
    })
    assert.equal(fromDashboard.available, true)
    assert.equal(fromDashboard.score, 40)
    assert.equal(fromDashboard.label, PRIMARY_SCORE_LABEL)
    assert.equal(fromAccount.score, 40)
    assert.equal(fromDashboard.score, fromAccount.score)
  })

  it('never converts missing score data into a misleading zero-risk result', () => {
    assert.equal(resolvePrimarySecurityScore({ loaded: false }).available, false)
    assert.equal(resolvePrimarySecurityScore({ loaded: false }).score, null)
    assert.match(resolvePrimarySecurityScore({ summary: null, loaded: true }).reason, /did not load/i)
    assert.match(
      resolvePrimarySecurityScore({ summary: { total_events: 0, average_risk_score: 0 }, loaded: true }).reason,
      /Insufficient data/i,
    )
    assert.match(
      resolvePrimarySecurityScore({ summary: { total_events: 10, average_risk_score: null }, loaded: true }).reason,
      /not returned/i,
    )
    const zeroEventsLookLikeRisk = resolvePrimarySecurityScore({
      summary: { total_events: 0, average_risk_score: 0 },
      loaded: true,
    })
    assert.notEqual(zeroEventsLookLikeRisk.score, 0)
    assert.equal(zeroEventsLookLikeRisk.available, false)
    const malformed = resolvePrimarySecurityScore({
      summary: { total_events: 5, average_risk_score: 'not-a-number' },
      loaded: true,
    })
    assert.equal(malformed.available, false)
    assert.match(malformed.reason, /not a valid number/i)
  })

  it('preserves a legitimate zero average when events exist', () => {
    const result = resolvePrimarySecurityScore({
      summary: { total_events: 3, average_risk_score: 0 },
      loaded: true,
    })
    assert.equal(result.available, true)
    assert.equal(result.score, 0)
  })

  it('keeps Dashboard and Intelligence on the same average_risk_score field and scope helpers', () => {
    const intelligence = source('pages/Intelligence.jsx')
    const dashboard = source('pages/Dashboard.jsx')
    assert.match(intelligence, /resolvePrimarySecurityScore/)
    assert.match(intelligence, /getDashboardSummary\(serverId, environment\)/)
    assert.match(intelligence, /getAccountSummary\(serverId, summaryAccountId, environment\)/)
    assert.match(intelligence, /accountIdForSummaryRequest/)
    assert.match(intelligence, /data-primary-security-score/)
    assert.doesNotMatch(intelligence, /data-risk-analysis-primary-gauge/)
    assert.doesNotMatch(intelligence, /RiskWidget/)
    assert.match(dashboard, /resolvePrimarySecurityScore/)
    assert.match(dashboard, /PRIMARY_SCORE_LABEL/)
    assert.match(dashboard, /getAccountSummary\(serverId, summaryAccountId, environment\)/)
    assert.doesNotMatch(dashboard, /GLOBAL SECURITY INTELLIGENCE|getGlobalIntelligenceSummary|GLOBAL_CORPORA|Synthetic Demo/)
    assert.equal(countPrimaryScoreGaugeMarkers(intelligence), 1)
  })

  it('does not display unsupported behavioral keystroke metrics or empty reference panels', () => {
    const intelligence = source('pages/Intelligence.jsx')
    const dashboard = source('pages/Dashboard.jsx')
    assert.doesNotMatch(intelligence, /Typing Speed/)
    assert.doesNotMatch(intelligence, /Command Rate/)
    assert.doesNotMatch(intelligence, /Idle Time/)
    assert.doesNotMatch(intelligence, /Session Duration/)
    assert.doesNotMatch(intelligence, /average_typing_speed/)
    assert.doesNotMatch(intelligence, /data-behavioral-panel/)
    assert.doesNotMatch(intelligence, /GLOBAL SECURITY INTELLIGENCE/)
    assert.doesNotMatch(intelligence, /Activity trend|data-activity-trend|Selected finding risk/)
    assert.doesNotMatch(intelligence, /Load Behavioral Demo Data/)
    assert.doesNotMatch(intelligence, /label: 'OpenStack'|label: 'HDFS'|Synthetic Demo/)
    assert.doesNotMatch(dashboard, /GLOBAL SECURITY INTELLIGENCE|Synthetic Demo/)
    assert.match(intelligence, /DetectionPanel/)
    assert.match(intelligence, /data-primary-security-score/)
  })

  it('explains Isolation Forest readiness at 45\/100 and keeps RF unavailable without labels', () => {
    const linux = {
      isolation_forest_status: 'insufficient_baseline',
      training_status: 'not_trained',
      eligible_count: 45,
      minimum_required: 100,
      random_forest_status: 'no_valid_linux_labels',
      valid_label_count: 0,
      model_present: false,
    }
    const view = linuxModelView(linux)
    assert.equal(additionalEligibleEventsNeeded(linux), 55)
    assert.equal(view.isolationForest.trained, false)
    assert.match(view.isolationForest.note, /45 eligible LIVE_LINUX security events are below the 100-event minimum/)
    assert.match(view.isolationForest.note, /55 more needed/)
    assert.match(view.isolationForest.note, /not private LIVE_LINUX telemetry/)
    assert.deepEqual(view.isolationForest.details.find((row) => row.label === 'Additional events needed'), {
      label: 'Additional events needed',
      value: 55,
    })
    assert.equal(view.randomForest.trained, false)
    assert.match(view.randomForest.note, /0 valid analyst-verified Linux labels/)
    assert.match(predictionsEmptyGuidance(linux), /45 of 100 eligible/)
    assert.match(predictionsEmptyGuidance(linux), /does not mean there are no threats/)
  })

  it('does not treat queued refresh as completed detection', () => {
    assert.match(
      predictionsEmptyGuidance({ eligible_count: 45, minimum_required: 100, training_status: 'not_trained', model_present: false }, { refreshPending: true }),
      /do not confirm that detection finished/i,
    )
    const panel = source('components/intelligence/DetectionPanel.jsx')
    assert.match(panel, /createQueuedDetectionRefreshController/)
    assert.match(panel, /data-queued-detection-refresh-note/)
    assert.doesNotMatch(panel, /predictionsEmptyGuidance|Recent predictions/)
    assert.doesNotMatch(panel, /detection has completed|Detection completed/)
  })

  it('keeps Cloud workspace off Linux detection endpoints', () => {
    const panel = source('components/intelligence/DetectionPanel.jsx')
    const intelligence = source('pages/Intelligence.jsx')
    assert.match(panel, /if \(!isLinux\)/)
    assert.match(panel, /cloudDetectionUnsupportedMessage/)
    assert.match(intelligence, /DetectionPanel/)
    assert.match(intelligence, /isLinux=\{isLinux\}/)
  })
})

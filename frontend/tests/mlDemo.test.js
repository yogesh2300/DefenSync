import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import {
  BEHAVIORAL_FEATURES, DATA_SOURCES, DEFAULT_SESSION, LIVE_AZURE, OPENSTACK_DEMO, SYNTHETIC_BEHAVIORAL,
  behavioralView, isTrained, openStackView, percent, sessionPayload, statusText,
} from '../src/mlDemo/mlDemo.js'

const openstackReport = {
  status: 'trained',
  data_source: 'OPENSTACK_PUBLIC_DATASET',
  is_azure: false,
  is_live: false,
  disclaimer: 'OpenStack cloud-infrastructure/API telemetry from a public dataset. Not Azure telemetry and not live data.',
  model_version: 'openstack-if-v1',
  feature_version: 'openstack-v1',
  aggregation_unit: 'Fixed 5-minute windows',
  feature_names: ['events_total', 'api_requests'],
  excluded_fields: { source_file: 'x', request_id: 'y' },
  dataset: { records_parsed: 207820 },
  summary: { windows_scored: 3, anomalous_windows: 1, threshold: 0.54 },
  window_scores: [
    { window_start: '2017-05-16T00:00:00', anomaly_score: 0.41, result: 'normal' },
    { window_start: '2017-05-16T00:05:00', anomaly_score: 0.71, result: 'anomalous' },
  ],
  top_anomalies: [{
    window_start: '2017-05-16T00:05:00',
    anomaly_score: 0.71,
    evidence: [{ feature: 'latency_p95', direction: 'above', value: 4.2, baseline_median: 0.3 }],
  }],
  evaluation: { purpose: 'Post-hoc check only.', windows_with_labelled_instances: 3, flagged_with_labelled_instances: 2, flagged_windows: 18 },
}

const behavioralReport = {
  status: 'trained',
  demonstration: 'Synthetic behavioral-pattern classification demonstration.',
  data_source: 'SYNTHETIC_BEHAVIORAL_DATASET',
  is_synthetic: true,
  disclaimer: 'Trained on synthetic generated sessions.',
  model_version: 'behavioral-rf-v1',
  classes: ['NORMAL', 'AUTOMATED_ACTIVITY'],
  excluded_columns: { is_anomaly: 'a', behavior_class: 'b' },
  model: {
    train_rows: 776,
    test_rows: 259,
    class_distribution: { all: { NORMAL: 825, AUTOMATED_ACTIVITY: 64 } },
    feature_importance: [{ feature: 'repeated_command_ratio', importance: 0.27 }],
    evaluation: {
      accuracy: 0.9961,
      macro_f1: 0.9862,
      weighted_f1: 0.9963,
      per_class: { NORMAL: { precision: 1, recall: 0.9951, f1: 0.9976, support: 206 }, AUTOMATED_ACTIVITY: { precision: 1, recall: 1, f1: 1, support: 16 } },
      confusion_matrix: { labels: ['NORMAL', 'AUTOMATED_ACTIVITY'], matrix: [[205, 1], [0, 16]] },
    },
  },
}

describe('ML demonstration source labelling', () => {
  it('distinguishes live Azure telemetry from the two dataset demonstrations', () => {
    assert.deepEqual(DATA_SOURCES.map((s) => s.key), [LIVE_AZURE, OPENSTACK_DEMO, SYNTHETIC_BEHAVIORAL])
    assert.deepEqual(DATA_SOURCES.map((s) => s.label), [
      'LIVE AZURE TELEMETRY', 'OPENSTACK ML DEMONSTRATION', 'SYNTHETIC BEHAVIORAL RF DEMONSTRATION',
    ])
    assert.deepEqual(DATA_SOURCES.filter((s) => s.live).map((s) => s.key), [LIVE_AZURE])
    const openstack = DATA_SOURCES.find((s) => s.key === OPENSTACK_DEMO)
    assert.match(openstack.description, /Not Azure/)
    assert.match(DATA_SOURCES.find((s) => s.key === SYNTHETIC_BEHAVIORAL).description, /Not real telemetry/)
  })

  it('maps model status text', () => {
    assert.equal(statusText('trained'), 'Trained')
    assert.match(statusText('stale'), /retrain/)
    assert.equal(statusText('bogus'), 'Unknown')
    assert.equal(isTrained({ status: 'stale' }), true)
    assert.equal(isTrained({ status: 'not_trained' }), false)
    assert.equal(percent(0.98625), '98.6%')
    assert.equal(percent(null), 'n/a')
  })
})

describe('OpenStack Isolation Forest view', () => {
  it('summarises a trained report under the OpenStack source', () => {
    const view = openStackView(openstackReport)
    assert.equal(view.sourceKey, OPENSTACK_DEMO)
    assert.equal(view.trained, true)
    assert.equal(view.featureCount, 2)
    assert.deepEqual(view.excluded, ['source_file', 'request_id'])
    assert.equal(view.stats.find((s) => s.label === 'Anomalous windows').value, 1)
    assert.deepEqual(view.series.map((p) => p.anomalous), [null, 0.71])
    assert.match(view.topAnomalies[0].evidence[0], /latency_p95 above baseline/)
    assert.match(view.evaluation.text, /2 of 3 windows/)
  })

  it('handles untrained and missing reports', () => {
    assert.equal(openStackView(null), null)
    const view = openStackView({ status: 'not_trained', message: 'Train the OpenStack demonstration to see results.' })
    assert.equal(view.trained, false)
    assert.deepEqual(view.stats, [])
    assert.equal(view.evaluation, null)
    assert.match(view.message, /Train/)
  })
})

describe('Synthetic behavioral Random Forest view', () => {
  it('summarises metrics, confusion matrix and importance under the synthetic source', () => {
    const view = behavioralView(behavioralReport)
    assert.equal(view.sourceKey, SYNTHETIC_BEHAVIORAL)
    assert.equal(view.demonstration, 'Synthetic behavioral-pattern classification demonstration.')
    assert.equal(view.stats.find((s) => s.label === 'Macro F1').value, '98.6%')
    assert.deepEqual(view.classRows.map((r) => [r.name, r.total, r.support]), [['NORMAL', 825, 206], ['AUTOMATED_ACTIVITY', 64, 16]])
    assert.deepEqual(view.confusion.matrix, [[205, 1], [0, 16]])
    assert.deepEqual(view.importance, [{ feature: 'repeated_command_ratio', importance: 0.27 }])
    assert.deepEqual(view.excluded, ['is_anomaly', 'behavior_class'])
  })

  it('builds a numeric predict payload with only the seven session features', () => {
    assert.deepEqual(BEHAVIORAL_FEATURES.map((f) => f.key), Object.keys(DEFAULT_SESSION))
    const payload = sessionPayload({ ...DEFAULT_SESSION, login_hour: '9.7', typing_speed_cpm: '200', is_anomaly: true })
    assert.equal(payload.login_hour, 9)
    assert.equal(payload.typing_speed_cpm, 200)
    assert.ok(!('is_anomaly' in payload))
    assert.equal(sessionPayload({ ...DEFAULT_SESSION, idle_time_seconds: '' }), null)
    assert.equal(sessionPayload({ ...DEFAULT_SESSION, command_error_rate: 'abc' }), null)
  })
})

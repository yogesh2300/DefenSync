import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { isLinuxModelTrained, linuxModelView, linuxRunSummary } from '../src/detection/linuxStatus.js'

const insufficient = {
  environment: 'LINUX',
  feature_version: 'linux-v1',
  isolation_forest_status: 'insufficient_baseline',
  training_status: 'not_trained',
  eligible_count: 42,
  minimum_required: 100,
  scored_count: 0,
  anomaly_count: 0,
  random_forest_status: 'no_valid_linux_labels',
  valid_label_count: 0,
  model_present: false,
  threshold: null,
}

const trained = {
  ...insufficient,
  isolation_forest_status: 'trained',
  training_status: 'trained',
  eligible_count: 150,
  scored_count: 150,
  anomaly_count: 2,
  model_present: true,
  threshold: 0.61234,
  training_metadata: { threshold_percentile: 99, training_count: 150 },
}

describe('Linux detection status view', () => {
  it('shows an insufficient baseline with eligible and minimum counts', () => {
    const view = linuxModelView(insufficient)
    assert.equal(view.isolationForest.title, 'Linux Isolation Forest')
    assert.equal(view.isolationForest.status, 'Insufficient baseline')
    assert.equal(view.isolationForest.trained, false)
    assert.deepEqual(view.isolationForest.details.slice(0, 2), [
      { label: 'Eligible events', value: 42 },
      { label: 'Minimum required', value: 100 },
    ])
    assert.match(view.isolationForest.note, /42 eligible LIVE_LINUX security events are below the 100-event minimum/)
    assert.match(view.isolationForest.note, /58 more needed/)
    assert.deepEqual(view.isolationForest.details.find((item) => item.label === 'Additional events needed'), {
      label: 'Additional events needed',
      value: 58,
    })
    assert.equal(view.isolationForest.details.some((item) => item.label === 'Threshold'), false)
  })

  it('surfaces exclusion counts that explain eligible vs account totals', () => {
    const view = linuxModelView({
      ...insufficient,
      excluded: { not_security_event: 80, collector_generated: 12 },
    })
    assert.deepEqual(view.isolationForest.details.find((item) => item.label === 'Excluded from ML baseline'), {
      label: 'Excluded from ML baseline',
      value: 92,
    })
    assert.equal(view.isolationForest.exclusions.length, 2)
    assert.deepEqual(view.isolationForest.exclusions.find((row) => row.value === 12), {
      label: 'Collector SSH logins',
      value: 12,
    })
    assert.deepEqual(view.isolationForest.exclusions.find((row) => row.value === 80), {
      label: 'System snapshots / system events',
      value: 80,
    })
  })

  it('shows the Linux Random Forest as having no valid labels', () => {
    const view = linuxModelView(insufficient)
    assert.equal(view.randomForest.title, 'Linux Random Forest')
    assert.equal(view.randomForest.status, 'No valid Linux labels')
    assert.equal(view.randomForest.trained, false)
    assert.match(view.randomForest.note, /0 valid analyst-verified Linux labels/)
  })

  it('never reports trained without a stored model', () => {
    assert.equal(isLinuxModelTrained({ ...trained, model_present: false }), false)
    assert.equal(isLinuxModelTrained({ ...insufficient, training_status: 'trained' }), false)
    assert.equal(isLinuxModelTrained(trained), true)
    assert.equal(linuxModelView(null), null)
  })

  it('shows the baseline-derived threshold once trained', () => {
    const view = linuxModelView(trained)
    assert.equal(view.isolationForest.status, 'Trained')
    assert.deepEqual(view.isolationForest.details.find((item) => item.label === 'Threshold'), {
      label: 'Threshold', value: '0.6123 (99th percentile of baseline)',
    })
  })

  it('summarises a detection run honestly', () => {
    assert.equal(
      linuxRunSummary(insufficient),
      'Linux Isolation Forest: Insufficient baseline (42/100 eligible events). Linux Random Forest: No valid Linux labels.',
    )
    assert.equal(
      linuxRunSummary(trained),
      'Linux Isolation Forest: Trained (2 of 150 eligible events above threshold). Linux Random Forest: No valid Linux labels.',
    )
    assert.equal(linuxRunSummary(undefined), '')
  })
})

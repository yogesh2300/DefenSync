// View helpers for the dataset-only ML demonstrations. Pure functions so the source labelling
// (live Azure vs OpenStack dataset vs synthetic sessions) can be tested without a browser.

export const LIVE_AZURE = 'LIVE_AZURE'
export const OPENSTACK_DEMO = 'OPENSTACK_DEMO'
export const SYNTHETIC_BEHAVIORAL = 'SYNTHETIC_BEHAVIORAL'

export const DATA_SOURCES = [
  {
    key: LIVE_AZURE,
    label: 'LIVE AZURE TELEMETRY',
    description: 'Real Entra sign-in and Azure Activity rows collected from your Cloud Accounts. Not used by either demonstration model.',
    live: true,
  },
  {
    key: OPENSTACK_DEMO,
    label: 'OPENSTACK ML DEMONSTRATION',
    description: 'Public OpenStack cloud-infrastructure/API logs (2017). Not Azure data and not live.',
    live: false,
  },
  {
    key: SYNTHETIC_BEHAVIORAL,
    label: 'SYNTHETIC BEHAVIORAL RF DEMONSTRATION',
    description: 'Generated session data. Not real telemetry; classes are synthetic patterns, not attack labels.',
    live: false,
  },
]

export const BEHAVIORAL_FEATURES = [
  { key: 'typing_speed_cpm', label: 'Typing speed (chars/min)', step: 1, min: 0 },
  { key: 'command_rate_per_minute', label: 'Commands per minute', step: 0.1, min: 0 },
  { key: 'command_error_rate', label: 'Command error rate (0-1)', step: 0.01, min: 0, max: 1 },
  { key: 'idle_time_seconds', label: 'Idle time (s)', step: 1, min: 0 },
  { key: 'repeated_command_ratio', label: 'Repeated command ratio (0-1)', step: 0.01, min: 0, max: 1 },
  { key: 'session_duration_minutes', label: 'Session duration (min)', step: 1, min: 0 },
  { key: 'login_hour', label: 'Login hour (0-23)', step: 1, min: 0, max: 23 },
]

export const DEFAULT_SESSION = {
  typing_speed_cpm: 180,
  command_rate_per_minute: 3,
  command_error_rate: 0.08,
  idle_time_seconds: 90,
  repeated_command_ratio: 0.1,
  session_duration_minutes: 60,
  login_hour: 10,
}

const STATUS_TEXT = {
  trained: 'Trained',
  stale: 'Dataset changed since training - retrain',
  not_trained: 'Not trained',
  dataset_missing: 'Dataset files missing',
}

export function statusText(status) {
  return STATUS_TEXT[status] || 'Unknown'
}

export function isTrained(report) {
  return report?.status === 'trained' || report?.status === 'stale'
}

export function percent(value, digits = 1) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return 'n/a'
  return `${(Number(value) * 100).toFixed(digits)}%`
}

export function openStackView(report) {
  if (!report) return null
  const trained = isTrained(report)
  const summary = report.summary || {}
  const evaluation = report.evaluation || null
  const dataset = report.dataset || {}
  return {
    sourceKey: OPENSTACK_DEMO,
    trained,
    status: statusText(report.status),
    modelVersion: report.model_version,
    featureVersion: report.feature_version,
    dataSource: report.data_source,
    disclaimer: report.disclaimer,
    aggregation: report.aggregation_unit,
    featureCount: (report.feature_names || []).length,
    excluded: Object.keys(report.excluded_fields || {}),
    stats: trained
      ? [
          { label: 'Log lines parsed', value: (dataset.records_parsed ?? 0).toLocaleString() },
          { label: 'Windows scored', value: summary.windows_scored ?? 0 },
          { label: 'Anomalous windows', value: summary.anomalous_windows ?? 0 },
          { label: 'Threshold', value: summary.threshold ?? 'n/a' },
        ]
      : [],
    series: (report.window_scores || []).map((item, index) => ({
      index,
      window: item.window_start,
      score: item.anomaly_score,
      anomalous: item.result === 'anomalous' ? item.anomaly_score : null,
    })),
    topAnomalies: (report.top_anomalies || []).map((item) => ({
      window: item.window_start,
      score: item.anomaly_score,
      evidence: (item.evidence || []).slice(0, 3).map((e) => `${e.feature} ${e.direction} baseline (${e.value} vs ${e.baseline_median})`),
    })),
    evaluation: evaluation && {
      note: evaluation.purpose,
      text: `${evaluation.flagged_with_labelled_instances ?? 0} of ${evaluation.windows_with_labelled_instances ?? 0} windows containing the dataset's labelled abnormal VMs were flagged; ${evaluation.flagged_windows ?? 0} windows flagged in total.`,
    },
    message: report.message || '',
  }
}

export function behavioralView(report) {
  if (!report) return null
  const trained = isTrained(report)
  const model = report.model || {}
  const evaluation = model.evaluation || {}
  const classes = report.classes || []
  return {
    sourceKey: SYNTHETIC_BEHAVIORAL,
    trained,
    status: statusText(report.status),
    demonstration: report.demonstration,
    modelVersion: report.model_version,
    dataSource: report.data_source,
    disclaimer: report.disclaimer,
    excluded: Object.keys(report.excluded_columns || {}),
    stats: trained
      ? [
          { label: 'Sessions (train / test)', value: `${model.train_rows ?? 0} / ${model.test_rows ?? 0}` },
          { label: 'Hold-out accuracy', value: percent(evaluation.accuracy) },
          { label: 'Macro F1', value: percent(evaluation.macro_f1) },
          { label: 'Weighted F1', value: percent(evaluation.weighted_f1) },
        ]
      : [],
    classRows: trained
      ? classes.map((name) => ({
          name,
          total: model.class_distribution?.all?.[name] ?? 0,
          precision: percent(evaluation.per_class?.[name]?.precision),
          recall: percent(evaluation.per_class?.[name]?.recall),
          f1: percent(evaluation.per_class?.[name]?.f1),
          support: evaluation.per_class?.[name]?.support ?? 0,
        }))
      : [],
    confusion: trained ? evaluation.confusion_matrix || null : null,
    importance: (model.feature_importance || []).map((item) => ({ feature: item.feature, importance: item.importance })),
    message: report.message || '',
  }
}

// Numeric payload for /behavioral/predict; returns null when any field is not a finite number.
export function sessionPayload(form) {
  const payload = {}
  for (const { key } of BEHAVIORAL_FEATURES) {
    const value = Number(form?.[key])
    if (form?.[key] === '' || form?.[key] === null || !Number.isFinite(value)) return null
    payload[key] = key === 'login_hour' ? Math.trunc(value) : value
  }
  return payload
}

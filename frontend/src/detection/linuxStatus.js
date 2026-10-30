const ISOLATION_FOREST_STATUS = {
  insufficient_baseline: 'Insufficient baseline',
  not_trained: 'Not trained',
  trained: 'Trained',
}

const RANDOM_FOREST_STATUS = {
  no_valid_linux_labels: 'No valid Linux labels',
}

function label(value, labels) {
  if (!value) return 'Unknown'
  return labels[value] || String(value).replaceAll('_', ' ')
}

export function isLinuxModelTrained(linux) {
  return Boolean(linux && linux.training_status === 'trained' && linux.model_present === true)
}

export function additionalEligibleEventsNeeded(linux) {
  if (!linux) return null
  const eligible = Number(linux.eligible_count ?? 0)
  const minimum = Number(linux.minimum_required ?? 0)
  if (!Number.isFinite(eligible) || !Number.isFinite(minimum)) return null
  return Math.max(0, minimum - eligible)
}

const EXCLUSION_LABELS = {
  collector_generated: 'Collector SSH logins',
  not_security_event: 'System snapshots / system events',
  wrong_data_origin: 'Non-LIVE_LINUX origins',
  wrong_source_type: 'Non-Linux source types',
  no_source_event_time: 'Missing source event time',
  not_security_event_kind: 'Non-security record kinds',
}

export function formatLinuxExclusions(excluded) {
  if (!excluded || typeof excluded !== 'object') return []
  return Object.entries(excluded)
    .filter(([, count]) => Number(count) > 0)
    .map(([reason, count]) => ({
      label: EXCLUSION_LABELS[reason] || String(reason).replaceAll('_', ' '),
      value: Number(count),
    }))
}

export function predictionsEmptyGuidance(linux, { refreshPending = false } = {}) {
  if (refreshPending) {
    return 'No stored predictions yet. Status was refreshed after collection queued background detection; timer refreshes do not confirm that detection finished. Zero predictions does not mean there are no threats.'
  }
  if (!linux) {
    return 'No stored predictions for this Linux scope yet. Zero predictions does not mean there are no threats — collect Linux events from Servers; detection runs automatically after a successful collection.'
  }
  if (!isLinuxModelTrained(linux)) {
    const eligible = linux.eligible_count ?? 0
    const minimum = linux.minimum_required ?? 0
    const needed = additionalEligibleEventsNeeded(linux) ?? 0
    const excludedTotal = formatLinuxExclusions(linux.excluded).reduce((sum, row) => sum + row.value, 0)
    const exclusionNote = excludedTotal > 0
      ? ` ${excludedTotal} in-scope Linux rows were excluded from the ML baseline (snapshots, system events, collector logins, non-LIVE_LINUX origins, or missing source event times).`
      : ''
    return `No stored predictions. Linux Isolation Forest is not trained: ${eligible} of ${minimum} eligible events (${needed} more needed).${exclusionNote} Global research corpora and synthetic demos are not private LIVE_LINUX telemetry and do not count toward this baseline. Zero predictions does not mean there are no threats.`
  }
  return 'No stored anomaly predictions for this Linux scope. Detection runs automatically after a successful collection; a status refresh alone does not confirm detection finished. Zero predictions does not mean there are no threats.'
}

export function linuxModelView(linux) {
  if (!linux) return null
  const trained = isLinuxModelTrained(linux)
  const metadata = linux.training_metadata || {}
  const eligible = linux.eligible_count ?? 0
  const minimum = linux.minimum_required ?? 0
  const needed = additionalEligibleEventsNeeded(linux)
  const labelCount = linux.valid_label_count ?? 0
  const details = [
    { label: 'Eligible events', value: eligible },
    { label: 'Minimum required', value: minimum },
  ]
  if (!trained && needed !== null) {
    details.push({ label: 'Additional events needed', value: needed })
  }
  const exclusions = formatLinuxExclusions(linux.excluded)
  const excludedTotal = exclusions.reduce((sum, row) => sum + row.value, 0)
  if (excludedTotal > 0) {
    details.push({ label: 'Excluded from ML baseline', value: excludedTotal })
  }
  details.push({ label: 'Feature version', value: linux.feature_version || '-' })
  if (trained && typeof linux.threshold === 'number') {
    details.push({
      label: 'Threshold',
      value: `${linux.threshold.toFixed(4)} (${metadata.threshold_percentile ?? 99}th percentile of baseline)`,
    })
    details.push({ label: 'Training events', value: metadata.training_count ?? '-' })
  }
  return {
    isolationForest: {
      title: 'Linux Isolation Forest',
      status: label(linux.isolation_forest_status, ISOLATION_FOREST_STATUS),
      trained,
      details,
      exclusions,
      note: trained
        ? 'Scores eligible Linux security events only; snapshots, system events and collector logins are never scored. Global research corpora do not count.'
        : `${eligible} eligible LIVE_LINUX security events are below the ${minimum}-event minimum (${needed ?? 0} more needed). Account/server totals include ineligible rows (snapshots, system events, collector logins, missing source times). Public BGL/HDFS/OpenStack and synthetic demos are not private LIVE_LINUX telemetry. The model is not trained or ready until the backend confirms training.`,
    },
    randomForest: {
      title: 'Linux Random Forest',
      status: label(linux.random_forest_status, RANDOM_FOREST_STATUS),
      trained: false,
      details: [{ label: 'Valid Linux labels', value: labelCount }],
      note: `Supervised detection is unavailable: ${labelCount} valid analyst-verified Linux labels. Random Forest stays disabled until required labels exist.`,
    },
  }
}

export function linuxRunSummary(linux) {
  if (!linux) return ''
  const isolationForest = label(linux.isolation_forest_status, ISOLATION_FOREST_STATUS)
  const randomForest = label(linux.random_forest_status, RANDOM_FOREST_STATUS)
  const counts = isLinuxModelTrained(linux)
    ? `${linux.anomaly_count ?? 0} of ${linux.scored_count ?? 0} eligible events above threshold`
    : `${linux.eligible_count ?? 0}/${linux.minimum_required ?? 0} eligible events`
  return `Linux Isolation Forest: ${isolationForest} (${counts}). Linux Random Forest: ${randomForest}.`
}

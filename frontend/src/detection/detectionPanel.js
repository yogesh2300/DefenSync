// Pure helpers for the Detection panel embedded in DefenSync Intelligence.

export const ADMIN_SELECT_SERVER_MESSAGE =
  'Select a server before running detection as an administrator.'

export function adminRunDetectionBlocked(isAdmin, selectedServerId) {
  return Boolean(isAdmin) && !selectedServerId
}

export function hybridRunMessage(runResult) {
  if (!runResult || typeof runResult !== 'object') return null
  const analyzed = (runResult.events_analyzed ?? 0) - (runResult.linux?.scored_count ?? 0)
  if (runResult.isolation_forest === 'insufficient_events') {
    return `Cloud/HPC/behavioral: ML scoring was skipped because only ${analyzed} eligible ${analyzed === 1 ? 'event was' : 'events were'} available, which is below the minimum required. No Isolation Forest or Random Forest predictions were produced.`
  }
  const linux = runResult.linux
  const parts = [
    `Analyzed ${runResult.events_analyzed ?? 0} event(s).`,
    `Isolation Forest: ${runResult.isolation_forest || 'n/a'}.`,
    `Random Forest: ${runResult.random_forest || 'n/a'}.`,
  ]
  if (linux) {
    parts.push(`Linux eligible ${linux.eligible_count ?? 0}/${linux.minimum_required ?? 0}; anomalies ${linux.anomaly_count ?? 0}.`)
  }
  return parts.join(' ')
}

/** Prefer the backend message; never treat HTTP 200 alone as success. */
export function detectionRunFeedback(runResult) {
  if (!runResult || typeof runResult !== 'object') {
    return { message: 'Detection run completed.', type: 'info' }
  }
  const backendMessage = typeof runResult.message === 'string' ? runResult.message.trim() : ''
  const message = backendMessage || hybridRunMessage(runResult) || 'Detection run completed.'
  if (runResult.success === false) {
    return { message, type: 'warning' }
  }
  return { message, type: 'info' }
}

export function detectionReadyLabel(status) {
  if (!status) return { value: 'Unknown', caption: 'Status has not been loaded.' }

  // Linux panel: prefer Linux Isolation Forest readiness over hybrid Cloud/HPC bundles.
  const linux = status.linux
  if (linux && typeof linux === 'object') {
    const eligible = Number(linux.eligible_count ?? 0)
    const minimum = Number(linux.minimum_required ?? 0)
    const trained = linux.training_status === 'trained' && linux.model_present === true
    if (trained) {
      return {
        value: 'Ready',
        caption: 'Linux Isolation Forest is trained for eligible LIVE_LINUX security events.',
      }
    }
    if (Number.isFinite(eligible) && Number.isFinite(minimum) && minimum > 0) {
      const needed = Math.max(0, minimum - eligible)
      return {
        value: 'Not ready',
        caption: `Linux Isolation Forest needs ${needed} more eligible LIVE_LINUX security event${needed === 1 ? '' : 's'} (${eligible}/${minimum}). Snapshots and collector SSH logins do not count.`,
      }
    }
    return { value: 'Not ready', caption: 'Linux Isolation Forest is not trained for this scope.' }
  }

  if (status.ready) {
    const rf = status.random_forest === 'trained'
      ? 'Isolation Forest ready; Random Forest trained where labels exist'
      : 'Isolation Forest ready; Random Forest needs labeled data where applicable'
    return { value: 'Ready', caption: rf }
  }
  return { value: 'Not ready', caption: 'Need enough eligible events before models can score.' }
}

export function cloudDetectionUnsupportedMessage() {
  return 'Linux detection status and predictions are available in the Linux workspace after a successful server collection. Cloud uses Events, Alerts, and correlation on this page — not the Linux detection endpoints.'
}

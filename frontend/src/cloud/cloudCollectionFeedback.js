/** Format Cloud collect result: collection vs DEMO incident vs n8n webhook (not mailbox). */

export function formatCloudDemoFeedback(result) {
  const demo = result?.demo_feedback || {}
  if (!demo.presentation_enabled) {
    return 'DEMO incident: not created (add your login email to PRESENTATION_TELEMETRY_EMAILS).'
  }
  if (demo.demo_incident_created) {
    const risk = demo.trigger_risk_score != null ? ` risk ${demo.trigger_risk_score}/100` : ''
    return `DEMO incident created${risk}.`
  }
  return 'DEMO incident: not created this run.'
}

export function formatCloudN8nFeedback(n8n) {
  if (!n8n || typeof n8n !== 'object') return null
  const status = String(n8n.dispatch_status || n8n.status || '').toUpperCase()
  const policy = n8n.policy || (n8n.trigger_every === 1 ? 'cloud_demo_every_success' : 'alternate_success')
  const seq = n8n.sequence_number
  if (status === 'SKIPPED') {
    return policy === 'cloud_demo_every_success'
      ? 'n8n webhook: skipped.'
      : `n8n webhook: skipped (collection #${seq}; alternate every 2nd success).`
  }
  if (status === 'SENT') {
    return `n8n webhook accepted (HTTP ${n8n.last_http_status || 2}xx) for collection #${seq} — email delivery not confirmed by DefenSync.`
  }
  if (status === 'PENDING') return 'n8n webhook: PENDING.'
  if (status === 'FAILED') return 'n8n webhook: FAILED (collection still succeeded).'
  if (status === 'NOT_CONFIGURED') return 'n8n webhook: not configured.'
  return status ? `n8n webhook: ${status}` : null
}

export function formatCloudCollectMessage(result) {
  if (!result || result.status !== 'COLLECTION_OK') {
    return result?.error?.message || result?.status || 'Collection failed'
  }
  const collection = `Collection completed (${result.outcome || 'SUCCESS'}): retrieved ${result.records_retrieved ?? 0}, inserted ${result.records_inserted ?? 0}, deduplicated ${result.records_deduplicated ?? 0}.`
  const demo = formatCloudDemoFeedback(result)
  const n8n = formatCloudN8nFeedback(result.collection_n8n)
  return [collection, demo, n8n].filter(Boolean).join(' ')
}

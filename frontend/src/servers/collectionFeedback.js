// Pure helpers for Linux collection + post-collection detection messaging.

export function formatCollectionN8nNote(n8n) {
  if (!n8n || typeof n8n !== 'object') return null
  const status = String(n8n.dispatch_status || n8n.status || '').toUpperCase()
  const seq = n8n.sequence_number
  if (status === 'SKIPPED') {
    return seq != null ? `n8n: skipped (collection #${seq}; triggers on every 2nd success)` : 'n8n: skipped (odd success)'
  }
  if (status === 'SENT') {
    return seq != null ? `n8n: sent for collection #${seq}` : 'n8n: sent'
  }
  if (status === 'PENDING') return 'n8n: dispatch pending'
  if (status === 'FAILED') return 'n8n: dispatch failed (collection still succeeded)'
  if (status === 'NOT_CONFIGURED') return 'n8n: webhook not configured (collection still succeeded)'
  return status ? `n8n: ${status}` : null
}

export function formatLinuxCollectionFeedback(serverName, result) {
  const name = serverName || 'Server'
  if (!result || result.success === false) {
    const detail = result?.message || result?.error || 'collection failed'
    return { collection: `${name}: ${detail}`, detection: null, n8n: null }
  }
  const collected = result.collected_events ?? result.inserted ?? 0
  const collection = `${name}: collected ${collected} event${collected === 1 ? '' : 's'}`
  const detectionMessage = typeof result.detection?.message === 'string' ? result.detection.message.trim() : ''
  return {
    collection,
    detection: detectionMessage || null,
    n8n: formatCollectionN8nNote(result.collection_n8n),
  }
}

export function combinedLinuxCollectionMessage(serverName, result) {
  const parts = formatLinuxCollectionFeedback(serverName, result)
  return [parts.collection, parts.detection ? `Detection: ${parts.detection}` : null, parts.n8n].filter(Boolean).join('. ')
}

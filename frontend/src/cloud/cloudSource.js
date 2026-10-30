// Cloud source onboarding rules. Pure functions only, so the form logic is testable without a browser.
// The client secret lives only in the form's React state: never in storage, URLs, or logs.

export const PROVIDERS = [{ value: 'AZURE', label: 'Microsoft Azure' }]
export const SOURCE_TYPES = { AZURE: [{ value: 'AZURE_LOG_ANALYTICS', label: 'Azure Log Analytics' }] }

export const EMPTY_SOURCE_FORM = Object.freeze({
  provider: 'AZURE',
  source_type: 'AZURE_LOG_ANALYTICS',
  tenant_id: '',
  client_id: '',
  client_secret: '',
  workspace_id: '',
})

export const CREDENTIAL_FIELDS = [
  { name: 'tenant_id', label: 'Tenant ID', placeholder: '00000000-0000-0000-0000-000000000000' },
  { name: 'client_id', label: 'Client ID', placeholder: 'Application (client) ID' },
  { name: 'client_secret', label: 'Client Secret', placeholder: 'Client secret value', secret: true },
  { name: 'workspace_id', label: 'Workspace ID', placeholder: 'Log Analytics workspace ID' },
]

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const TENANT_DOMAIN = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i

export function sourceFormProblems(form) {
  const value = (name) => String(form?.[name] ?? '').trim()
  const problems = {}
  for (const { name, label } of CREDENTIAL_FIELDS) {
    if (!value(name)) problems[name] = `${label} is required.`
  }
  if (value('tenant_id') && !GUID.test(value('tenant_id')) && !TENANT_DOMAIN.test(value('tenant_id'))) {
    problems.tenant_id = 'Tenant ID must be a GUID or a tenant domain.'
  }
  if (value('client_id') && !GUID.test(value('client_id'))) problems.client_id = 'Client ID must be a GUID.'
  if (value('workspace_id') && !GUID.test(value('workspace_id'))) problems.workspace_id = 'Workspace ID must be the workspace GUID.'
  return problems
}

export function toSourcePayload(form, { accountId = null } = {}) {
  const payload = {
    provider: form.provider,
    source_type: form.source_type,
    tenant_id: form.tenant_id.trim(),
    client_id: form.client_id.trim(),
    client_secret: form.client_secret.trim(),
    workspace_id: form.workspace_id.trim(),
  }
  return accountId ? { ...payload, account_id: accountId } : payload
}

// "Add Cloud Source" stays disabled until Test Connection succeeds for the values currently in the form.
export function canAddSource(form, testResult, { busy = false } = {}) {
  return !busy && Object.keys(sourceFormProblems(form)).length === 0 && testResult?.success === true
}

const CONNECTION_LABELS = { CONNECTED: 'Connected', FAILED: 'Connection failed', UNTESTED: 'Not tested' }
const CONNECTION_VARIANTS = { CONNECTED: 'online', FAILED: 'error', UNTESTED: 'inactive' }

export function connectionLabel(status) {
  return CONNECTION_LABELS[status] || CONNECTION_LABELS.UNTESTED
}

export function connectionVariant(status) {
  return CONNECTION_VARIANTS[status] || CONNECTION_VARIANTS.UNTESTED
}

// Header status for the Cloud workspace; null means the source list has not loaded (or failed to load).
export function azureStatusLabel(listing) {
  if (!listing) return 'Azure'
  const sources = Array.isArray(listing) ? listing : listing.sources || []
  return sources.some((source) => source.connection_status === 'CONNECTED') ? 'Azure · Connected' : 'Azure · Not connected'
}

export function lastCollectionLabel(source, format = (value) => new Date(value).toLocaleString()) {
  return source?.last_successful_collection ? format(source.last_successful_collection) : 'Never'
}

// Latest persisted collection run: SUCCESS / PARTIAL / FAILED with row counts.
export function collectionRunSummary(run) {
  if (!run) return 'No collection runs yet'
  return `${run.status} · retrieved ${run.rows_retrieved ?? 0} · stored ${run.rows_stored ?? 0} · duplicates ${run.rows_duplicate ?? 0}`
}

export function collectionRunAlert(run) {
  if (!run?.error || run.status === 'SUCCESS') return null
  return { type: run.status === 'FAILED' ? 'error' : 'warning', message: run.error.message || run.error.code }
}

export function testResultMessage(result) {
  if (!result) return ''
  if (result.success) return 'Connection successful. DefenSync can read this Log Analytics workspace.'
  return result.error?.message || 'Connection failed.'
}

export function cloudErrorMessage(err, fallback = 'The request failed.') {
  const data = err?.response?.data
  if (data?.azure_error?.message) return data.azure_error.message
  if (typeof data?.error === 'string') return data.error
  if (Array.isArray(data?.error)) return 'Some fields are invalid. Check the values and try again.'
  return fallback
}

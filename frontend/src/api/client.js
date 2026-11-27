import axios from 'axios'

const TOKEN_KEY = 'defensync_token'
const LEGACY_TOKEN_KEY = 'cloudsync_token'

const api = axios.create({
  baseURL: '',
  headers: { 'Content-Type': 'application/json' },
})

function getToken() {
  return localStorage.getItem(TOKEN_KEY) || localStorage.getItem(LEGACY_TOKEN_KEY)
}

api.interceptors.request.use((config) => {
  const token = getToken()
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Email + password step: returns an OTP challenge. No access token exists until verifyOtp succeeds.
export async function login(email, password) {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(LEGACY_TOKEN_KEY)
  const params = new URLSearchParams()
  params.append('email', email)
  params.append('password', password)
  const { data } = await api.post('/api/v1/auth/token', params, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  return data
}

export async function sendOtp(challengeId, channel = null) {
  const { data } = await api.post('/api/v1/auth/otp/send', { challenge_id: challengeId, ...(channel ? { channel } : {}) })
  return data
}

function storeVerifiedToken(data) {
  localStorage.setItem(TOKEN_KEY, data.access_token)
  localStorage.removeItem(LEGACY_TOKEN_KEY)
  window.dispatchEvent(new CustomEvent('defensync:authenticated'))
  return { token_type: data.token_type }
}

export async function verifyOtp(challengeId, otp) {
  const { data } = await api.post('/api/v1/auth/otp/verify', { challenge_id: challengeId, otp })
  return storeVerifiedToken(data)
}

// Starts registration: returns a verification challenge. No account exists until verifyRegistration succeeds.
export async function register(username, email, password) {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(LEGACY_TOKEN_KEY)
  const { data } = await api.post('/api/v1/auth/register', { username, email, password })
  return data
}

export async function verifyRegistration(challengeId, otp) {
  const { data } = await api.post('/api/v1/auth/register/verify', { challenge_id: challengeId, otp })
  return storeVerifiedToken(data)
}

// Password reset never creates a session: nothing here touches stored tokens, and the reset token
// returned by verifyPasswordReset stays in the caller's memory only.
export async function requestPasswordReset(email) {
  const { data } = await api.post('/api/v1/auth/password-reset/request', { email })
  return data
}

export async function resendPasswordReset(challengeId) {
  const { data } = await api.post('/api/v1/auth/password-reset/resend', { challenge_id: challengeId })
  return data
}

export async function verifyPasswordReset(challengeId, otp) {
  const { data } = await api.post('/api/v1/auth/password-reset/verify', { challenge_id: challengeId, otp })
  return data
}

export async function completePasswordReset(resetToken, newPassword, confirmPassword) {
  const { data } = await api.post('/api/v1/auth/password-reset/complete', {
    reset_token: resetToken,
    new_password: newPassword,
    confirm_password: confirmPassword,
  })
  return data
}

export async function getMe() {
  const { data } = await api.get('/api/v1/auth/me')
  return data
}

export async function listTrustedDevices() {
  const { data } = await api.get('/api/v1/auth/trusted-devices')
  return data
}

export async function beginTrustedDeviceEnroll(publicKeyJwk, displayName = null) {
  const { data } = await api.post('/api/v1/auth/trusted-devices/enroll/begin', {
    public_key_jwk: publicKeyJwk,
    ...(displayName ? { display_name: displayName } : {}),
  })
  return data
}

export async function completeTrustedDeviceEnroll({ deviceId, challengeId, nonce, signature }) {
  const { data } = await api.post('/api/v1/auth/trusted-devices/enroll/complete', {
    device_id: deviceId,
    challenge_id: challengeId,
    nonce,
    signature,
  })
  if (data?.access_token) storeVerifiedToken(data)
  return data
}

export async function beginTrustedDeviceVerify(deviceId) {
  const { data } = await api.post('/api/v1/auth/trusted-devices/verify/begin', { device_id: deviceId })
  return data
}

export async function completeTrustedDeviceVerify({ deviceId, challengeId, nonce, signature }) {
  const { data } = await api.post('/api/v1/auth/trusted-devices/verify/complete', {
    device_id: deviceId,
    challenge_id: challengeId,
    nonce,
    signature,
  })
  if (data?.access_token) storeVerifiedToken(data)
  return data
}

export async function renameTrustedDevice(deviceId, displayName) {
  const { data } = await api.patch(`/api/v1/auth/trusted-devices/${deviceId}`, { display_name: displayName })
  return data
}

export async function revokeTrustedDevice(deviceId) {
  const { data } = await api.delete(`/api/v1/auth/trusted-devices/${deviceId}`)
  return data
}

export async function getHealth() {
  const { data } = await api.get('/health')
  return data
}

function withServerId(params = {}, serverId = null) {
  if (serverId) return { ...params, server_id: serverId }
  return params
}

function withEnvironment(params = {}, environment = null) {
  return environment ? { ...params, environment } : params
}

export async function getDashboardSummary(serverId = null, environment = null) {
  const { data } = await api.get('/api/v1/dashboard', { params: withEnvironment(withServerId({}, serverId), environment) })
  return data
}

export async function getEventStats(serverId = null, environment = null) {
  const { data } = await api.get('/api/v1/events/stats', { params: withEnvironment(withServerId({}, serverId), environment) })
  return data
}

export async function getEvents(params = {}) {
  const { data } = await api.get('/api/v1/events', { params })
  return data
}

export async function getOpenStackDatasetStatus() {
  const { data } = await api.get('/api/v1/datasets/openstack/status')
  return data
}

export async function getDatasetHubStatus() {
  const { data } = await api.get('/api/v1/datasets/status')
  return data
}

export async function getBglDatasetStatus() {
  const { data } = await api.get('/api/v1/datasets/bgl/status')
  return data
}

export async function getHdfsDatasetStatus() {
  const { data } = await api.get('/api/v1/datasets/hdfs/status')
  return data
}

export async function getBehavioralSummary() {
  const { data } = await api.get('/api/v1/behavioral/summary')
  return data
}

export async function getBehavioralProfiles() {
  const { data } = await api.get('/api/v1/behavioral/profiles')
  return data
}

export async function getBehavioralAnomalies(limit = 50) {
  const { data } = await api.get('/api/v1/behavioral/anomalies', { params: { limit } })
  return data
}

export async function loadBehavioralDemo() {
  const { data } = await api.post('/api/v1/behavioral/demo')
  return data
}

export async function loadOpenStackDemo() {
  const { data } = await api.post('/api/v1/datasets/openstack/demo')
  return data
}

export async function getHighRiskEvents(limit = 20, serverId = null, environment = null) {
  const params = withEnvironment({ limit }, environment)
  if (serverId) params.server_id = serverId
  const { data } = await api.get('/api/v1/events/high-risk', { params })
  if (Array.isArray(data)) return { total: data.length, items: data }
  return { total: data?.total ?? (data?.items || []).length, items: data?.items || [] }
}

export async function getRecentEvents(limit = 10, serverId = null, environment = null) {
  const { data } = await api.get('/api/v1/events/recent', { params: withEnvironment(withServerId({ limit }, serverId), environment) })
  return data
}

export async function getAlerts(params = {}) {
  const { data } = await api.get('/api/v1/alerts', { params })
  return data
}

export async function getAlertSummary(serverId = null, environment = null) {
  const { data } = await api.get('/api/v1/alerts/summary', { params: withEnvironment(withServerId({}, serverId), environment) })
  return data
}

export async function acknowledgeAlert(alertId) {
  const { data } = await api.post(`/api/v1/alerts/${alertId}/ack`)
  return data
}

export async function getDetectionStatus(serverId = null) {
  const { data } = await api.get('/api/v1/detection/status', { params: withServerId({}, serverId) })
  return data
}

export async function runDetection(serverId = null) {
  const { data } = await api.post('/api/v1/detection/run', null, { params: withServerId({}, serverId) })
  return data
}

export async function getIncidents(limit = 20, environment = null) {
  const { data } = await api.get('/api/v1/intelligence/incidents', { params: withEnvironment({ limit }, environment) })
  return data
}

export async function getN8nStatus() {
  const { data } = await api.get('/api/v1/intelligence/n8n/status')
  return data
}

export async function getCollectionN8nStatus() {
  const { data } = await api.get('/api/v1/account/collection-n8n')
  return data
}

export async function runCorrelation() {
  const { data } = await api.post('/api/v1/intelligence/correlate')
  return data
}

export async function getBehaviorHistory(actor = null, environment = 'LINUX') {
  const { data } = await api.get('/api/v1/intelligence/behavior-history', { params: withEnvironment(actor ? { actor } : {}, environment) })
  return data
}

export async function exportInvestigation(fmt = 'json') {
  const { data } = await api.get('/api/v1/intelligence/export', { params: { fmt }, responseType: fmt === 'csv' ? 'blob' : 'json' })
  return data
}

export async function getAnomalies(limit = 20, serverId = null) {
  const { data } = await api.get('/api/v1/detection/anomalies', { params: withServerId({ limit }, serverId) })
  if (Array.isArray(data)) return data
  return data?.items || []
}

export async function getOpenStackMlDemo() {
  const { data } = await api.get('/api/v1/ml-demo/openstack')
  return data
}

export async function trainOpenStackMlDemo() {
  const { data } = await api.post('/api/v1/ml-demo/openstack/train')
  return data
}

export async function getBehavioralRfDemo() {
  const { data } = await api.get('/api/v1/ml-demo/behavioral')
  return data
}

export async function trainBehavioralRfDemo() {
  const { data } = await api.post('/api/v1/ml-demo/behavioral/train')
  return data
}

export async function predictBehavioralPattern(session) {
  const { data } = await api.post('/api/v1/ml-demo/behavioral/predict', session)
  return data
}

export async function getAccountSummary(serverId = null, accountId = null, environment = null) {
  const params = withEnvironment(withServerId({}, serverId), environment)
  if (accountId) params.account_id = accountId
  const { data } = await api.get('/api/v1/account/summary', { params })
  return data
}

export async function getAccountList() {
  const { data } = await api.get('/api/v1/account/list')
  return data
}

export async function getGlobalIntelligenceSummary() {
  const { data } = await api.get('/api/v1/intelligence/global/summary')
  return data
}

export async function getAzureCollectorStatus() {
  const { data } = await api.get('/api/v1/cloud/azure/status')
  return data
}

export async function collectAzureTelemetry(payload) {
  const { data } = await api.post('/api/v1/cloud/azure/collect', payload)
  window.dispatchEvent(new CustomEvent('defensync:data-refresh', { detail: { result: data } }))
  return data
}

// Cloud sources (CLOUD environment). The client secret is sent only in request bodies and is never
// returned, stored in the browser, or placed in a URL.
export async function getCloudSources() {
  const { data } = await api.get('/api/v1/cloud/sources')
  return data
}

export async function getCloudSource(sourceId) {
  const { data } = await api.get(`/api/v1/cloud/sources/${encodeURIComponent(sourceId)}`)
  return data
}

export async function testCloudConnection(credentials) {
  const { data } = await api.post('/api/v1/cloud/sources/test-connection', credentials)
  return data
}

export async function createCloudSource(credentials) {
  const { data } = await api.post('/api/v1/cloud/sources', credentials)
  return data
}

export async function testCloudSource(sourceId) {
  const { data } = await api.post(`/api/v1/cloud/sources/${encodeURIComponent(sourceId)}/test-connection`)
  return data
}

export async function collectCloudSource(sourceId, payload = {}) {
  const { data } = await api.post(`/api/v1/cloud/sources/${encodeURIComponent(sourceId)}/collect`, payload)
  window.dispatchEvent(new CustomEvent('defensync:data-refresh', { detail: { result: data } }))
  return data
}

export async function deleteCloudSource(sourceId) {
  const { data } = await api.delete(`/api/v1/cloud/sources/${encodeURIComponent(sourceId)}`)
  return data
}

// Cloud investigation (read-only). Uses the authenticated axios client; visibility is enforced server-side.
export async function getCloudIdentityBaselines(params) {
  const { data } = await api.get('/api/v1/cloud/identity-baselines', { params })
  return data
}

export async function getCloudSequenceFindings(params) {
  const { data } = await api.get('/api/v1/cloud/sequence-findings', { params })
  return data
}

export async function runCollection(payload = {}) {
  const { data } = await api.post('/api/v1/collection/run', payload)
  window.dispatchEvent(new CustomEvent('defensync:data-refresh', { detail: { serverId: payload.server_id, result: data } }))
  return data
}

// Server Management
export async function getServers(activeOnly = false) {
  const { data } = await api.get('/api/v1/servers', { params: { active_only: activeOnly } })
  return data
}

export async function refreshServerStatus(serverId = null) {
  const { data } = await api.post('/api/v1/servers/refresh-status', null, {
    params: withServerId({}, serverId),
  })
  window.dispatchEvent(new CustomEvent('defensync:status-refreshed', { detail: { serverId, result: data } }))
  return data
}

export async function getFleetHealth(serverId = null) {
  const { data } = await api.get('/api/v1/health/servers', { params: withServerId({}, serverId) })
  return data
}

export async function getServer(serverId) {
  const { data } = await api.get(`/api/v1/servers/${serverId}`)
  return data
}

export async function testServerCredentials(payload) {
  const { data } = await api.post('/api/v1/servers/test', payload)
  return data
}

export async function createServer(payload) {
  const { data } = await api.post('/api/v1/servers', payload)
  return data
}

export async function updateServer(serverId, payload) {
  const { data } = await api.put(`/api/v1/servers/${serverId}`, payload)
  return data
}

export async function deleteServer(serverId) {
  const { data } = await api.delete(`/api/v1/servers/${serverId}`)
  return data
}

export async function testServerConnection(serverId) {
  const { data } = await api.post(`/api/v1/servers/${serverId}/test`)
  return data
}

export async function collectServer(serverId, payload = {}) {
  const { data } = await api.post(`/api/v1/servers/${serverId}/collect`, payload)
  window.dispatchEvent(new CustomEvent('defensync:data-refresh', { detail: { serverId, result: data } }))
  return data
}

export async function getServerLogs(serverId, limit = 100) {
  const { data } = await api.get(`/api/v1/servers/${serverId}/logs`, { params: { limit } })
  return data
}

export async function getServerStats(serverId) {
  const { data } = await api.get(`/api/v1/servers/${serverId}/stats`)
  return data
}

export async function getServerRisk(serverId) {
  const { data } = await api.get(`/api/v1/servers/${serverId}/risk`)
  return data
}

export async function getLogSources() {
  const { data } = await api.get('/api/v1/servers/sources')
  return data
}

export function logout() {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(LEGACY_TOKEN_KEY)
  try {
    sessionStorage.clear()
  } catch {
    // ignore storage errors in restricted environments
  }
  window.dispatchEvent(new CustomEvent('defensync:logout'))
}

export default api

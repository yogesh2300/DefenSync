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

export async function login(username, password) {
  const params = new URLSearchParams()
  params.append('username', username)
  params.append('password', password)
  const { data } = await api.post('/api/v1/auth/token', params, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  localStorage.setItem(TOKEN_KEY, data.access_token)
  localStorage.removeItem(LEGACY_TOKEN_KEY)
  return data
}

export async function register(username, email, password) {
  const { data } = await api.post('/api/v1/auth/register', { username, email, password })
  return data
}

export async function getMe() {
  const { data } = await api.get('/api/v1/auth/me')
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

export async function getDashboardSummary(serverId = null) {
  const { data } = await api.get('/api/v1/dashboard', { params: withServerId({}, serverId) })
  return data
}

export async function getEventStats(serverId = null) {
  const { data } = await api.get('/api/v1/events/stats', { params: withServerId({}, serverId) })
  return data
}

export async function getEvents(params = {}) {
  const { data } = await api.get('/api/v1/events', { params })
  return data
}

export async function getHighRiskEvents(limit = 20, serverId = null) {
  const params = { limit }
  if (serverId) params.server_id = serverId
  const { data } = await api.get('/api/v1/events/high-risk', { params })
  return data
}

export async function getRecentEvents(limit = 10, serverId = null) {
  const { data } = await api.get('/api/v1/events/recent', { params: withServerId({ limit }, serverId) })
  return data
}

export async function getAlerts(params = {}) {
  const { data } = await api.get('/api/v1/alerts', { params })
  return data
}

export async function getAlertSummary(serverId = null) {
  const { data } = await api.get('/api/v1/alerts/summary', { params: withServerId({}, serverId) })
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

export async function getAnomalies(limit = 20, serverId = null) {
  const { data } = await api.get('/api/v1/detection/anomalies', { params: withServerId({ limit }, serverId) })
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

import api from './client'

export async function getAdminDashboard() {
  const { data } = await api.get('/api/v1/admin/dashboard')
  return data
}

export async function getAdminUsers(params = {}) {
  const { data } = await api.get('/api/v1/admin/users', { params })
  return data
}

export async function getAdminUser(userId) {
  const { data } = await api.get(`/api/v1/admin/users/${userId}`)
  return data
}

export async function deleteAdminUser(userId) {
  const { data } = await api.delete(`/api/v1/admin/users/${userId}`)
  return data
}

export async function getAdminUserTrustedDevices(userId) {
  const { data } = await api.get(`/api/v1/auth/trusted-devices/admin/users/${userId}`)
  return data
}

export async function setAdminUserDeviceLimit(userId, deviceLimit) {
  const { data } = await api.put(`/api/v1/auth/trusted-devices/admin/users/${userId}/limit`, {
    device_limit: deviceLimit,
  })
  return data
}

export async function getAdminServers() {
  const { data } = await api.get('/api/v1/admin/servers')
  return data
}

export async function getAdminEvents(params = {}) {
  const { data } = await api.get('/api/v1/admin/events', { params })
  return data
}

export async function getAdminAlerts(params = {}) {
  const { data } = await api.get('/api/v1/admin/alerts', { params })
  return data
}

export async function getAdminAlertSummary() {
  const { data } = await api.get('/api/v1/admin/alerts/summary')
  return data
}

export async function getAdminDetections(limit = 100) {
  const { data } = await api.get('/api/v1/admin/detections', { params: { limit } })
  return data
}

export async function getAdminDetectionStatus() {
  const { data } = await api.get('/api/v1/admin/detections/status')
  return data
}

export async function getAdminCollections(limit = 200) {
  const { data } = await api.get('/api/v1/admin/collections', { params: { limit } })
  return data
}

export async function getAdminAnalytics() {
  const { data } = await api.get('/api/v1/admin/analytics')
  return data
}

export async function getAdminSystemHealth() {
  const { data } = await api.get('/api/v1/admin/system-health')
  return data
}

export async function getAdminML() {
  const { data } = await api.get('/api/v1/admin/ml')
  return data
}

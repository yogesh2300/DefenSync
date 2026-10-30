import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { getAdminUser, getAdminUserTrustedDevices, setAdminUserDeviceLimit } from '../../api/adminClient'
import Button from '../../components/ui/Button'
import LoadingSpinner from '../../components/ui/LoadingSpinner'
import { AdminCard, AdminMetric } from '../../components/admin/AdminLayout'

export default function AdminUserDetail() {
  const { userId } = useParams()
  const [user, setUser] = useState(null)
  const [devices, setDevices] = useState(null)
  const [deviceLimitDraft, setDeviceLimitDraft] = useState('3')
  const [deviceMessage, setDeviceMessage] = useState('')
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const profile = await getAdminUser(userId)
      setUser(profile)
      try {
        const summary = await getAdminUserTrustedDevices(userId)
        setDevices(summary)
        setDeviceLimitDraft(String(summary.device_limit ?? 3))
      } catch {
        setDevices(null)
      }
    } catch {
      setUser(null)
      setDevices(null)
    } finally {
      setLoading(false)
    }
  }, [userId])

  useEffect(() => { load() }, [load])

  const saveLimit = async () => {
    setDeviceMessage('')
    try {
      const result = await setAdminUserDeviceLimit(userId, Number(deviceLimitDraft))
      setDeviceMessage(`Device limit set to ${result.device_limit}.`)
      const summary = await getAdminUserTrustedDevices(userId)
      setDevices(summary)
      setDeviceLimitDraft(String(summary.device_limit ?? 3))
    } catch (err) {
      setDeviceMessage(err.response?.data?.error || err.message || 'Failed to update device limit.')
    }
  }

  if (loading) return <LoadingSpinner label="Loading user profile..." />
  if (!user) return <p className="text-zinc-400">User not found.</p>

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Link to="/admin/users"><Button variant="secondary">Back</Button></Link>
        <div>
          <h2 className="text-xl font-semibold text-white">{user.username}</h2>
          <p className="text-sm text-zinc-500">{user.email} · {user.role}</p>
        </div>
      </div>

      <section className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <AdminMetric label="Servers" value={user.servers?.length ?? 0} />
        <AdminMetric label="Events" value={user.events_count ?? 0} />
        <AdminMetric label="Alerts" value={user.alerts_count ?? 0} />
        <AdminMetric label="Risk Score" value={user.average_risk_score ?? 0} />
      </section>

      <AdminCard title="Trusted devices" subtitle="Admin-only per-user limit and device inventory (not Linux servers)">
        <div className="mb-4 flex flex-wrap items-end gap-3">
          <label className="text-xs text-zinc-400">
            Device limit
            <input
              type="number"
              min={0}
              max={50}
              className="mt-1 block w-28 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-white"
              value={deviceLimitDraft}
              onChange={(event) => setDeviceLimitDraft(event.target.value)}
              data-admin-device-limit
            />
          </label>
          <Button variant="secondary" onClick={saveLimit}>Save limit</Button>
          {deviceMessage && <p className="text-sm text-zinc-400">{deviceMessage}</p>}
        </div>
        <p className="mb-2 text-sm text-zinc-400" data-admin-trusted-device-slots>
          {devices
            ? `Trusted devices: ${devices.active_count} / ${devices.device_limit}`
            : 'Trusted device summary unavailable.'}
        </p>
        <p className="mb-3 text-xs text-zinc-500">
          Revoking device-bound sessions is performed by the user on Trusted Devices. Changing the limit here does not end existing MFA-only tokens.
        </p>
        <div className="space-y-2">
          {(devices?.devices || []).map((device) => (
            <div key={device.id} className="rounded-lg border border-zinc-800 px-3 py-2 text-sm">
              <div className="flex items-center justify-between gap-2">
                <span className="text-white">{device.display_name}</span>
                <span className="text-xs uppercase text-zinc-500">{device.status}</span>
              </div>
              <p className="mt-1 text-xs text-zinc-500">
                Created {device.created_at ? new Date(device.created_at).toLocaleString() : '—'}
                {' · '}
                Last seen {device.last_seen_at ? new Date(device.last_seen_at).toLocaleString() : 'Never'}
              </p>
            </div>
          ))}
          {devices && !devices.devices?.length && <p className="text-sm text-zinc-500">No trusted devices.</p>}
        </div>
      </AdminCard>

      <AdminCard title="Owned Servers">
        <div className="space-y-2">
          {(user.servers || []).map((s) => (
            <div key={s.id} className="flex items-center justify-between rounded-lg border border-zinc-800 px-3 py-2">
              <span className="text-white">{s.server_name}</span>
              <span className="text-xs text-zinc-500">{s.host} · {s.health_status}</span>
            </div>
          ))}
          {!user.servers?.length && <p className="text-sm text-zinc-500">No servers.</p>}
        </div>
      </AdminCard>

      <AdminCard title="Activity Timeline" subtitle="Recent events">
        <div className="max-h-80 space-y-2 overflow-y-auto">
          {(user.recent_events || []).map((e) => (
            <div key={e.event_id} className="rounded-lg border border-zinc-800 px-3 py-2 text-sm">
              <div className="flex justify-between gap-2">
                <span className="text-white">{e.event_type}</span>
                <span className="text-xs text-zinc-500">{e.timestamp ? new Date(e.timestamp).toLocaleString() : ''}</span>
              </div>
              <p className="mt-1 truncate text-zinc-400">{e.message}</p>
            </div>
          ))}
        </div>
      </AdminCard>

      <AdminCard title="Collection History">
        <div className="overflow-x-auto">
          <table className="admin-table w-full text-sm">
            <thead>
              <tr>
                <th className="px-3 py-2 text-left">Started</th>
                <th className="px-3 py-2 text-left">Status</th>
                <th className="px-3 py-2 text-left">Inserted</th>
                <th className="px-3 py-2 text-left">Duration</th>
              </tr>
            </thead>
            <tbody>
              {(user.collection_history || []).map((c) => (
                <tr key={c.id}>
                  <td className="px-3 py-3">{c.started_at ? new Date(c.started_at).toLocaleString() : '—'}</td>
                  <td className="px-3 py-3">{c.status}</td>
                  <td className="px-3 py-3">{c.inserted}</td>
                  <td className="px-3 py-3">{c.duration_ms ? `${c.duration_ms}ms` : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </AdminCard>
    </div>
  )
}

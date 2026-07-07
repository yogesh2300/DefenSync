import { useCallback, useEffect, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { Activity, HardDrive, Loader2, RadioTower, Server as ServerIcon } from 'lucide-react'
import {
  collectServer, createServer, deleteServer, getServers,
  testServerConnection, testServerCredentials,
} from '../api/client'
import { useAuth } from '../context/AuthContext'
import PageHeader from '../components/ui/PageHeader'
import Card from '../components/ui/Card'
import Button from '../components/ui/Button'
import AlertBanner from '../components/ui/AlertBanner'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import DataTable from '../components/ui/DataTable'
import { Input, Select, Textarea } from '../components/ui/Input'
import { StatusBadge } from '../components/ui/Badge'
import ServerCard from '../components/ui/ServerCard'

const emptyForm = {
  server_name: '',
  host: '',
  port: 22,
  username: '',
  authentication_type: 'password',
  password: '',
  private_key: '',
  operating_system: 'Ubuntu',
  environment: 'production',
  description: '',
}

const FULL_LOG_SOURCES = [
  'journalctl', 'last', 'lastb', 'who', 'w', 'uptime', 'free', 'df', 'ps', 'ss', 'hostnamectl', 'uname',
]

function apiError(err) {
  const data = err.response?.data
  if (!data) return err.message || 'Request failed'
  if (typeof data.detail === 'string') return data.detail
  if (typeof data.error === 'string') return data.error
  if (Array.isArray(data.detail)) return data.detail.map((d) => d.msg).join(', ')
  return JSON.stringify(data.detail || data.error || data)
}

function connectionLabel(server) {
  return server.connection_state || (server.status === 'online' ? 'Online' : 'Offline')
}

function StatTile({ label, value, icon: Icon, tone }) {
  return (
    <div className="rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-4">
      <div className="flex items-center justify-between gap-2">
        <p className="text-[11px] font-semibold uppercase tracking-wide muted-text">{label}</p>
        <Icon className={`h-4 w-4 ${tone || 'text-[#A5A5A5]'}`} />
      </div>
      <p className={`mt-2 text-3xl font-bold ${tone || 'cyber-text'}`}>{value}</p>
    </div>
  )
}

export default function Servers() {
  const { isAdmin } = useAuth()
  const location = useLocation()
  const navigate = useNavigate()
  const [servers, setServers] = useState([])
  const [form, setForm] = useState(emptyForm)
  const [showRegister, setShowRegister] = useState(location.pathname.endsWith('/new'))
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState('')
  const [message, setMessage] = useState('')
  const [testPassed, setTestPassed] = useState(false)
  const [testing, setTesting] = useState(false)
  const [saving, setSaving] = useState(false)
  const [actionId, setActionId] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setLoadError('')
    try {
      setServers(await getServers())
    } catch (err) {
      setLoadError(apiError(err))
      setServers([])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const buildTestPayload = () => {
    const payload = {
      host: form.host.trim(),
      port: Number(form.port) || 22,
      username: form.username.trim(),
      authentication_type: form.authentication_type,
    }
    if (form.authentication_type === 'password') payload.password = form.password
    else payload.private_key = form.private_key
    return payload
  }

  const buildCreatePayload = () => {
    const payload = {
      server_name: form.server_name.trim(),
      host: form.host.trim(),
      port: Number(form.port) || 22,
      username: form.username.trim(),
      authentication_type: form.authentication_type,
      operating_system: form.operating_system.trim() || 'linux',
      environment: form.environment || 'production',
      description: form.description.trim() || null,
    }
    if (form.authentication_type === 'password') payload.password = form.password
    else payload.private_key = form.private_key
    return payload
  }

  const invalidateTest = (updates) => {
    setForm((f) => ({ ...f, ...updates }))
    setTestPassed(false)
  }

  const handleTest = async () => {
    setTesting(true)
    setMessage('')
    setTestPassed(false)
    try {
      const result = await testServerCredentials(buildTestPayload())
      if (result.success) {
        setTestPassed(true)
        if (result.operating_system) {
          setForm((f) => ({ ...f, operating_system: result.operating_system }))
        }
        setMessage(`SSH connected to ${result.hostname || form.host} (${result.latency_ms}ms)${result.operating_system ? ` - OS: ${result.operating_system}` : ''}. You can save the server.`)
      } else {
        setMessage(result.message || 'SSH connection failed.')
      }
    } catch (err) {
      setMessage(apiError(err))
    } finally {
      setTesting(false)
    }
  }

  const handleCreate = async (e) => {
    e.preventDefault()
    if (!testPassed) {
      setMessage('Click Test Connection and verify SSH access before saving.')
      return
    }
    setSaving(true)
    setMessage('')
    try {
      const created = await createServer(buildCreatePayload())
      await testServerConnection(created.id)
      setForm(emptyForm)
      setTestPassed(false)
      setShowRegister(false)
      if (location.pathname.endsWith('/new')) navigate('/servers', { replace: true })
      setMessage(`Server "${created.server_name}" saved and registered.`)
      await load()
    } catch (err) {
      setMessage(apiError(err))
    } finally {
      setSaving(false)
    }
  }

  const runAction = async (id, fn) => {
    setActionId(id)
    try {
      await fn()
      await load()
    } catch (err) {
      setMessage(apiError(err))
    } finally {
      setActionId(null)
    }
  }

  const filteredServers = servers.filter((server) => {
    const term = search.trim().toLowerCase()
    const matchesSearch = !term || [
      server.server_name,
      server.host,
      server.username,
      server.operating_system,
      server.environment,
    ].some((value) => String(value || '').toLowerCase().includes(term))
    const state = connectionLabel(server).toLowerCase()
    const matchesStatus = !statusFilter || state === statusFilter
    return matchesSearch && matchesStatus
  })

  const onlineCount = servers.filter((server) => connectionLabel(server) === 'Online').length
  const offlineCount = servers.filter((server) => connectionLabel(server) === 'Offline').length
  const availability = servers.length ? Math.round((onlineCount / servers.length) * 100) : 0

  const testServer = async (server) => {
    const r = await testServerConnection(server.id)
    setMessage(r.success ? `${server.server_name}: Online (${r.latency_ms}ms)` : `${server.server_name}: ${r.message}`)
  }

  const collectFromServer = async (server) => {
    setMessage(`Collecting logs from ${server.server_name}...`)
    const r = await collectServer(server.id, { tail_lines: 500, log_sources: FULL_LOG_SOURCES })
    const detectionNote = r.detection?.message ? ` — ${r.detection.message}` : ''
    setMessage(`${server.server_name}: ${r.collected_events ?? r.inserted} events collected${detectionNote}`)
  }

  const deleteServerById = async (server) => {
    if (!window.confirm(`Delete server "${server.server_name}"?`)) return
    await deleteServer(server.id)
    setMessage(`Server "${server.server_name}" deleted.`)
  }

  const tableColumns = [
    {
      key: 'server_name',
      label: 'Server Name',
      render: (s) => (
        <div>
          <p className="font-medium cyber-text">{s.server_name}</p>
          <p className="font-mono text-xs text-slate-500">{s.host}:{s.port}</p>
        </div>
      ),
    },
    {
      key: 'connection_state',
      label: 'Status',
      render: (s) => {
        const label = connectionLabel(s)
        const variant = label === 'Online' ? 'online' : label === 'Inactive' ? 'inactive' : 'offline'
        return <StatusBadge status={variant}>{label}</StatusBadge>
      },
    },
    { key: 'operating_system', label: 'OS', render: (s) => s.operating_system || 'linux' },
    { key: 'environment', label: 'Environment', render: (s) => <span className="capitalize">{s.environment || 'production'}</span> },
    {
      key: 'risk_score',
      label: 'Risk',
      render: (s) => (
        <span className={s.risk_score >= 70 ? 'font-semibold text-red-400' : s.risk_score >= 40 ? 'font-semibold text-amber-400' : 'font-semibold text-emerald-400'}>
          {s.risk_score ?? 0}
        </span>
      ),
    },
    {
      key: 'last_collection',
      label: 'Last Collection',
      render: (s) => (
        <span className="font-mono text-xs text-slate-400">
          {s.last_collection ? new Date(s.last_collection).toLocaleString() : 'Never'}
        </span>
      ),
    },
    {
      key: 'actions',
      label: 'Actions',
      render: (s) => (
        <div className="flex flex-wrap gap-1.5">
          <Button variant="ghost" size="sm" onClick={() => navigate(`/servers/${s.id}`)}>View</Button>
          {isAdmin && (
            <Button variant="ghost" size="sm" onClick={() => navigate(`/servers/${s.id}/edit`)}>Edit</Button>
          )}
          <Button
            variant="secondary"
            size="sm"
            disabled={actionId === s.id}
            onClick={() => runAction(s.id, async () => {
              const r = await testServerConnection(s.id)
              setMessage(r.success ? `${s.server_name}: Online (${r.latency_ms}ms)` : `${s.server_name}: ${r.message}`)
            })}
          >
            {actionId === s.id ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
            Test
          </Button>
          <Button
            variant="primary"
            size="sm"
            disabled={actionId === s.id}
            onClick={() => runAction(s.id, async () => {
              setMessage(`Collecting logs from ${s.server_name}...`)
              const r = await collectServer(s.id, { tail_lines: 500, log_sources: FULL_LOG_SOURCES })
              const detectionNote = r.detection?.message ? ` — ${r.detection.message}` : ''
              setMessage(`${s.server_name}: ${r.collected_events ?? r.inserted} events collected${detectionNote}`)
            })}
          >
            {actionId === s.id ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
            Collect Logs
          </Button>
          {isAdmin && (
            <Button
              variant="danger"
              size="sm"
              disabled={actionId === s.id}
              onClick={() => {
                if (!window.confirm(`Delete server "${s.server_name}"?`)) return
                runAction(s.id, async () => {
                  await deleteServer(s.id)
                  setMessage(`Server "${s.server_name}" deleted.`)
                })
              }}
            >
              Delete
            </Button>
          )}
        </div>
      ),
    },
  ]

  return (
    <div className="page-shell">
      <PageHeader
        title="Servers"
        subtitle="Security Monitoring"
        actions={
          <Button onClick={() => { setShowRegister(true); setMessage('') }}>
            Register Server
          </Button>
        }
      />

      <AlertBanner message={loadError} type="error" />
      <AlertBanner message={message} />

      <section className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile label="Total Servers" value={servers.length} icon={ServerIcon} />
        <StatTile label="Online" value={onlineCount} icon={Activity} tone="text-emerald-600" />
        <StatTile label="Offline" value={offlineCount} icon={RadioTower} tone="text-red-500" />
        <StatTile label="Availability" value={`${availability}%`} icon={HardDrive} />
      </section>

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
        {filteredServers.map((server) => (
          <ServerCard
            key={server.id}
            server={server}
            isAdmin={isAdmin}
            busy={actionId === server.id}
            onOpen={() => navigate(`/servers/${server.id}`)}
            onTest={() => runAction(server.id, () => testServer(server))}
            onCollect={() => runAction(server.id, () => collectFromServer(server))}
            onDelete={() => runAction(server.id, () => deleteServerById(server))}
          />
        ))}
        {!filteredServers.length && !loading && (
          <Card className="col-span-full flex items-center justify-center py-12 text-center">
            <div>
              <ServerIcon className="mx-auto mb-3 h-10 w-10 muted-text" />
              <p className="text-lg font-semibold cyber-text">No servers found</p>
              <p className="mt-1 text-sm muted-text">Register a Linux server or adjust your filters.</p>
            </div>
          </Card>
        )}
      </section>

      {showRegister && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <Card title="Register Linux Server" subtitle="Security Monitoring" className="w-full max-w-4xl max-h-[90vh] overflow-y-auto">
          <form onSubmit={handleCreate} className="space-y-5">
            <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
              <Input
                label="Server Name"
                placeholder="Production Web Node"
                value={form.server_name}
                onChange={(e) => invalidateTest({ server_name: e.target.value })}
                required
              />
              <Input
                label="Host / IP"
                placeholder="192.168.1.50"
                value={form.host}
                onChange={(e) => invalidateTest({ host: e.target.value })}
                required
              />
              <Input
                label="SSH Port"
                type="number"
                min={1}
                max={65535}
                value={form.port}
                onChange={(e) => invalidateTest({ port: Number(e.target.value) })}
                required
              />
              <Input
                label="Username"
                placeholder="centos"
                value={form.username}
                onChange={(e) => invalidateTest({ username: e.target.value })}
                required
              />
              <Select
                label="Authentication Method"
                value={form.authentication_type}
                onChange={(e) => invalidateTest({ authentication_type: e.target.value, password: '', private_key: '' })}
              >
                <option value="password">Password</option>
                <option value="ssh_key">SSH Private Key</option>
              </Select>
              <Select
                label="Operating System"
                value={form.operating_system}
                onChange={(e) => setForm({ ...form, operating_system: e.target.value })}
              >
                <option value="Ubuntu">Ubuntu</option>
                <option value="CentOS">CentOS</option>
                <option value="Debian">Debian</option>
                <option value="Rocky">Rocky</option>
              </Select>
              <Select
                label="Environment"
                value={form.environment || 'production'}
                onChange={(e) => setForm({ ...form, environment: e.target.value })}
              >
                <option value="production">Production</option>
                <option value="development">Development</option>
                <option value="testing">Testing</option>
              </Select>
            </div>

            {form.authentication_type === 'password' ? (
              <Input
                label="Password"
                type="password"
                placeholder="SSH password"
                value={form.password}
                onChange={(e) => invalidateTest({ password: e.target.value })}
                required
                autoComplete="new-password"
              />
            ) : (
              <Textarea
                label="Private Key (PEM)"
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                value={form.private_key}
                onChange={(e) => invalidateTest({ private_key: e.target.value })}
                required
                rows={6}
              />
            )}

            <Input
              label="Description (optional)"
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
            />

            <div className="flex flex-wrap gap-3 pt-1 border-t border-[var(--panel-border)]">
              <Button type="button" variant="secondary" onClick={handleTest} disabled={testing}>
                {testing ? 'Testing SSH...' : 'Test Connection'}
              </Button>
              <Button type="submit" disabled={!testPassed || saving}>
                {saving ? 'Saving...' : 'Save Server'}
              </Button>
          <Button type="button" variant="ghost" onClick={() => { setShowRegister(false); setForm(emptyForm); setTestPassed(false); if (location.pathname.endsWith('/new')) navigate('/servers') }}>
                Cancel
              </Button>
              {testPassed && (
                <span className="self-center text-xs text-emerald-600">Connection verified</span>
              )}
            </div>
          </form>
        </Card>
        </div>
      )}

      <Card title="Server Directory" subtitle="Detailed list, actions and filters">
        <div className="mb-4 flex flex-col sm:flex-row gap-3">
          <Input
            placeholder="Search server name, host, user, OS, environment..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="sm:max-w-md"
          />
          <Select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className="sm:w-44">
            <option value="">All Statuses</option>
            <option value="online">Online</option>
            <option value="offline">Offline</option>
            <option value="inactive">Inactive</option>
          </Select>
        </div>
        {loading ? (
          <LoadingSpinner label="Loading registered servers..." />
        ) : (
          <DataTable
            columns={tableColumns}
            rows={filteredServers}
            emptyMessage={isAdmin
              ? 'No servers registered yet. Use the form above to add your first Linux server.'
              : 'No servers registered. Ask an admin to add Linux servers.'}
            keyField="id"
          />
        )}
      </Card>
    </div>
  )
}

import { useCallback, useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { getServer, testServerConnection, testServerCredentials, updateServer } from '../api/client'
import { apiErrorMessage, buildUpdatePayload, planConnectionTest } from '../servers/editServer'
import PageHeader from '../components/ui/PageHeader'
import Card from '../components/ui/Card'
import Button from '../components/ui/Button'
import AlertBanner from '../components/ui/AlertBanner'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import { Input, Select, Textarea } from '../components/ui/Input'

export default function EditServer() {
  const { serverId } = useParams()
  const navigate = useNavigate()
  const [form, setForm] = useState(null)
  const [original, setOriginal] = useState(null)
  const [password, setPassword] = useState('')
  const [privateKey, setPrivateKey] = useState('')
  const [message, setMessage] = useState('')
  const [testing, setTesting] = useState(false)

  const load = useCallback(async () => {
    const srv = await getServer(serverId)
    const loaded = {
      server_name: srv.server_name,
      host: srv.host,
      port: srv.port,
      username: srv.username,
      authentication_type: srv.authentication_type,
      operating_system: srv.operating_system || 'linux',
      environment: srv.environment || 'production',
      description: srv.description || '',
      status: srv.status === 'inactive' ? 'inactive' : 'active',
    }
    setForm(loaded)
    setOriginal(loaded)
  }, [serverId])

  useEffect(() => { load() }, [load])

  if (!form) return <LoadingSpinner label="Loading server..." />

  const handleTest = async () => {
    setTesting(true)
    setMessage('')
    try {
      const plan = planConnectionTest(original, form, { password, privateKey })
      if (plan.mode === 'blocked') {
        setMessage(plan.reason)
        return
      }
      const r = plan.mode === 'preview'
        ? await testServerCredentials(plan.request)
        : await testServerConnection(serverId)
      const unsaved = plan.mode === 'preview' ? ' Not saved yet.' : ''
      setMessage(r.success ? `Connection OK (${r.latency_ms}ms).${unsaved}` : r.message)
    } catch (err) {
      setMessage(apiErrorMessage(err, 'Test failed'))
    } finally {
      setTesting(false)
    }
  }

  const handleSave = async (e) => {
    e.preventDefault()
    setMessage('')
    const { payload, error } = buildUpdatePayload(original, form, { password, privateKey })
    if (error) {
      setMessage(error)
      return
    }
    try {
      await updateServer(serverId, payload)
      setMessage('Server updated successfully.')
      setTimeout(() => navigate(`/servers/${serverId}`), 800)
    } catch (err) {
      setMessage(apiErrorMessage(err, 'Update failed'))
    }
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title="Edit Server"
        subtitle="Security Monitoring"
        actions={<Link to={`/servers/${serverId}`}><Button variant="secondary">Cancel</Button></Link>}
      />

      <AlertBanner message={message} />

      <section className="grid gap-6 xl:grid-cols-[0.7fr_1.3fr]">
        <Card title="Connection Profile" subtitle="Current target">
          <div className="space-y-4">
            {[
              ['Server', form.server_name],
              ['Host', `${form.host}:${form.port}`],
              ['User', form.username],
              ['Environment', form.environment],
            ].map(([label, value]) => (
              <div key={label} className="rounded-3xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-4">
                <p className="text-xs muted-text">{label}</p>
                <p className="mt-2 truncate font-semibold cyber-text">{value || '-'}</p>
              </div>
            ))}
          </div>
        </Card>

        <Card title="Server Settings" subtitle="Security Monitoring">
          <form onSubmit={handleSave} className="space-y-5">
            <div className="grid gap-4 lg:grid-cols-3">
              <Input label="Server Name" value={form.server_name} onChange={(e) => setForm({ ...form, server_name: e.target.value })} required />
              <Input label="Host / IP" value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} required />
              <Input label="Port" type="number" value={form.port} onChange={(e) => setForm({ ...form, port: Number(e.target.value) })} />
              <Input label="Username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required />
              <Select label="Authentication Type" value={form.authentication_type} onChange={(e) => setForm({ ...form, authentication_type: e.target.value })}>
                <option value="password">Password</option>
                <option value="ssh_key">SSH Private Key</option>
              </Select>
              <Select label="Scheduler Status" value={form.status} onChange={(e) => setForm({ ...form, status: e.target.value })}>
                <option value="active">Active (included in scheduler)</option>
                <option value="inactive">Inactive (excluded)</option>
              </Select>
            </div>
            {form.authentication_type === 'password' ? (
              <Input label="New Password (optional)" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Leave blank to keep existing" />
            ) : (
              <Textarea label="New Private Key (optional)" value={privateKey} onChange={(e) => setPrivateKey(e.target.value)} placeholder="Leave blank to keep existing key" rows={5} />
            )}
            <div className="grid gap-4 lg:grid-cols-2">
              <Select label="Operating System" value={form.operating_system} onChange={(e) => setForm({ ...form, operating_system: e.target.value })}>
                <option value="Ubuntu">Ubuntu</option>
                <option value="CentOS">CentOS</option>
                <option value="Debian">Debian</option>
                <option value="Rocky">Rocky</option>
              </Select>
              <Select label="Environment" value={form.environment || 'production'} onChange={(e) => setForm({ ...form, environment: e.target.value })}>
                <option value="development">Development</option>
                <option value="testing">Testing</option>
                <option value="production">Production</option>
              </Select>
            </div>
            <Input label="Description" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
            <div className="flex flex-wrap gap-3 border-t border-[var(--panel-border)] pt-4">
              <Button type="button" variant="secondary" onClick={handleTest} disabled={testing}>{testing ? 'Testing...' : 'Test Connection'}</Button>
              <Button type="submit">Save Server</Button>
            </div>
          </form>
        </Card>
      </section>
    </div>
  )
}

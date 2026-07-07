import { useEffect, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { CheckCircle2, DatabaseZap, ListChecks, Server, TerminalSquare } from 'lucide-react'
import { getServers, runCollection } from '../api/client'
import AlertBanner from '../components/ui/AlertBanner'
import Button from '../components/ui/Button'
import Card from '../components/ui/Card'
import PageHeader from '../components/ui/PageHeader'
import { Input, Select } from '../components/ui/Input'
import { useAuth } from '../context/AuthContext'
import { useSelectedServer } from '../context/SelectedServerContext'

const LOG_SOURCE_OPTIONS = ['journalctl', 'last', 'lastb', 'who', 'w', 'uptime', 'free', 'df', 'ps', 'ss', 'hostnamectl', 'uname']

function StepBlock({ number, title, text, active }) {
  return (
    <div className={`rounded-3xl border p-4 ${active ? 'border-neutral-300 bg-[var(--panel-strong)]' : 'border-[var(--panel-border)] bg-[var(--panel)]'}`}>
      <div className="flex gap-3">
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-[var(--panel-border)] font-mono text-xs cyber-text">
          {number}
        </div>
        <div>
          <p className="font-semibold cyber-text">{title}</p>
          <p className="mt-1 text-sm muted-text">{text}</p>
        </div>
      </div>
    </div>
  )
}

export default function Collection() {
  const { isAdmin } = useAuth()
  const { selectedServerId } = useSelectedServer()
  const [servers, setServers] = useState([])
  const [serverId, setServerId] = useState('')
  const [tailLines, setTailLines] = useState(500)
  const [logSources, setLogSources] = useState(LOG_SOURCE_OPTIONS)
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    getServers(true).then(setServers).catch(() => {})
  }, [])

  useEffect(() => {
    if (selectedServerId) setServerId(selectedServerId)
  }, [selectedServerId])

  if (!isAdmin) return <Navigate to="/" replace />

  const selectedServer = servers.find((server) => server.id === serverId)

  const toggleSource = (src) => {
    setLogSources((prev) => prev.includes(src) ? prev.filter((s) => s !== src) : [...prev, src])
  }

  const handleRun = async (event) => {
    event.preventDefault()
    if (!serverId) return
    setLoading(true)
    setResult(null)
    try {
      setResult(await runCollection({ server_id: serverId, tail_lines: tailLines, log_sources: logSources }))
    } catch (err) {
      setResult({ success: false, message: err.response?.data?.detail || err.message })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-8">
      <PageHeader title="Collection" subtitle="Security Monitoring" />

      <section className="grid gap-6 xl:grid-cols-[0.75fr_1.25fr]">
        <Card title="Run Plan" subtitle="A guided collection workflow">
          <div className="space-y-4">
            <StepBlock number="01" title="Choose server" text={selectedServer ? `${selectedServer.server_name} - ${selectedServer.host}` : 'Select a registered server'} active={Boolean(serverId)} />
            <StepBlock number="02" title="Set volume" text={`${tailLines} lines per source`} active={tailLines > 0} />
            <StepBlock number="03" title="Choose sources" text={`${logSources.length} Linux sources selected`} active={logSources.length > 0} />
            <StepBlock number="04" title="Run" text={loading ? 'Collection is running' : 'Ready when server and sources are selected'} active={Boolean(serverId && logSources.length)} />
          </div>
        </Card>

        <Card title="Collection Setup" subtitle="Security Monitoring">
          {servers.length === 0 ? (
            <div className="flex min-h-[340px] flex-col items-center justify-center text-center">
              <Server className="mb-4 h-10 w-10 muted-text" />
              <p className="text-lg font-semibold cyber-text">No active servers</p>
              <p className="mt-2 max-w-sm text-sm muted-text">Add a server before running collection.</p>
            </div>
          ) : (
            <form onSubmit={handleRun} className="space-y-6">
              <div className="grid gap-4 lg:grid-cols-[1fr_180px]">
                <Select label="Target Server" value={serverId} onChange={(event) => setServerId(event.target.value)} required>
                  <option value="">Select a server...</option>
                  {servers.map((server) => <option key={server.id} value={server.id}>{server.server_name} ({server.host})</option>)}
                </Select>
                <Input label="Tail Lines" type="number" min={1} max={10000} value={tailLines} onChange={(event) => setTailLines(Number(event.target.value))} />
              </div>

              <div>
                <div className="mb-3 flex items-center justify-between">
                  <p className="text-sm font-semibold cyber-text">Log Sources</p>
                  <span className="rounded-full border border-[var(--panel-border)] px-2.5 py-1 text-xs muted-text">{logSources.length} selected</span>
                </div>
                <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                  {LOG_SOURCE_OPTIONS.map((source) => (
                    <label
                      key={source}
                      className={`flex cursor-pointer items-center justify-between rounded-2xl border p-3 text-sm transition ${
                        logSources.includes(source)
                          ? 'border-neutral-300 bg-[var(--panel-strong)] cyber-text'
                          : 'border-[var(--panel-border)] bg-[var(--panel)] muted-text hover:bg-[var(--panel-strong)]'
                      }`}
                    >
                      <input type="checkbox" className="sr-only" checked={logSources.includes(source)} onChange={() => toggleSource(source)} />
                      <span>{source}</span>
                      {logSources.includes(source) && <CheckCircle2 className="h-4 w-4" />}
                    </label>
                  ))}
                </div>
              </div>

              <Button type="submit" disabled={loading || !serverId || !logSources.length} className="w-full sm:w-auto">
                <DatabaseZap className="h-4 w-4" />
                {loading ? 'Running Collection...' : 'Run Collection'}
              </Button>
            </form>
          )}
        </Card>
      </section>

      <section className="grid gap-6 xl:grid-cols-[0.8fr_1.2fr]">
        <Card title="Run Summary" subtitle="Selected configuration">
          <div className="grid gap-4 sm:grid-cols-3">
            <div className="rounded-3xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-5">
              <Server className="mb-5 h-5 w-5 text-neutral-300" />
              <p className="text-xs muted-text">Server</p>
              <p className="mt-2 truncate text-lg font-semibold cyber-text">{selectedServer?.server_name || 'Not selected'}</p>
            </div>
            <div className="rounded-3xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-5">
              <TerminalSquare className="mb-5 h-5 w-5 text-neutral-300" />
              <p className="text-xs muted-text">Tail Lines</p>
              <p className="mt-2 text-lg font-semibold cyber-text">{tailLines}</p>
            </div>
            <div className="rounded-3xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-5">
              <ListChecks className="mb-5 h-5 w-5 text-neutral-300" />
              <p className="text-xs muted-text">Sources</p>
              <p className="mt-2 text-lg font-semibold cyber-text">{logSources.length}</p>
            </div>
          </div>
        </Card>

        <Card title="Collection Output" subtitle="Security Monitoring">
          {!result ? (
            <div className="flex min-h-[240px] flex-col items-center justify-center rounded-3xl border border-dashed border-[var(--panel-border)] bg-[var(--panel-strong)] text-center">
              <DatabaseZap className="mb-4 h-10 w-10 muted-text" />
              <p className="text-sm muted-text">Results will appear after collection.</p>
            </div>
          ) : (
            <>
              <AlertBanner
                message={result.message || (result.success ? `Collected ${result.collected_events ?? result.inserted} events` : 'Collection failed')}
                type={result.success !== false ? 'success' : 'error'}
              />
              <pre className="max-h-[360px] overflow-auto rounded-3xl border border-[var(--panel-border)] bg-slate-950/80 p-4 text-xs text-slate-200">
                {JSON.stringify(result, null, 2)}
              </pre>
            </>
          )}
        </Card>
      </section>
    </div>
  )
}

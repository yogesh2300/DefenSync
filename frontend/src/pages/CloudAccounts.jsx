import { useCallback, useEffect, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { Cloud, PlugZap, Plus, RefreshCw, Trash2 } from 'lucide-react'
import {
  collectAzureTelemetry, collectCloudSource, deleteCloudSource, getAccountList, getAccountSummary,
  getAzureCollectorStatus, getCloudSources, testCloudSource,
} from '../api/client'
import { formatCloudCollectMessage } from '../cloud/cloudCollectionFeedback.js'
import {
  cloudErrorMessage, collectionRunAlert, collectionRunSummary, connectionLabel, connectionVariant, lastCollectionLabel,
} from '../cloud/cloudSource'
import AddCloudSourceForm from '../components/cloud/AddCloudSourceForm'
import AlertBanner from '../components/ui/AlertBanner'
import Badge from '../components/ui/Badge'
import Button from '../components/ui/Button'
import Card from '../components/ui/Card'
import { Select } from '../components/ui/Input'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import PageHeader from '../components/ui/PageHeader'
import { useAuth } from '../context/AuthContext'
import { ADD_CLOUD_SOURCE_PATH, addScreenExitPath } from '../environment'

function Metric({ label, value }) {
  return (
    <div className="rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] px-3 py-2">
      <p className="text-[10px] font-semibold uppercase tracking-wide muted-text">{label}</p>
      <p className="mt-1 text-lg font-bold tabular-nums cyber-text">{value ?? 0}</p>
    </div>
  )
}

function Detail({ label, value, mono = false }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-[var(--panel-border)] py-1.5 last:border-b-0">
      <span className="text-xs muted-text">{label}</span>
      <span className={`truncate text-right text-xs cyber-text ${mono ? 'font-mono' : 'font-semibold'}`}>{value}</span>
    </div>
  )
}

// Azure can take several minutes to ingest sign-in and activity records into Log Analytics,
// so a longer window still reaches them; re-collected rows are deduplicated by record ID.
const LOOKBACK_OPTIONS = [15, 60, 240]

function CloudSourceCard({ source, accountName, busy, canDelete, onCollect, onTest, onDelete }) {
  const runAlert = collectionRunAlert(source.last_collection_run)
  const [lookback, setLookback] = useState(LOOKBACK_OPTIONS[0])
  return (
    <Card title="Cloud Source" subtitle={`${source.provider_label} · ${source.source_type_label}`}>
      <div className="space-y-3" data-cloud-source={source.id}>
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-3xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-4">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-[#111111] text-white"><Cloud className="h-5 w-5" /></div>
            <div>
              <p className="text-sm font-semibold cyber-text">Status: {connectionLabel(source.connection_status)}</p>
              <p className="mt-1 text-xs muted-text">Last collection: {lastCollectionLabel(source)}</p>
            </div>
          </div>
          <Badge variant={connectionVariant(source.connection_status)}>{connectionLabel(source.connection_status)}</Badge>
        </div>
        <div>
          <Detail label="Workspace ID" value={source.workspace_id} mono />
          <Detail label="Tenant ID" value={source.tenant_id} mono />
          <Detail label="Client ID" value={source.client_id} mono />
          <Detail label="Client secret" value={source.client_secret_configured ? 'Stored encrypted' : 'Not set'} />
          {accountName !== undefined && <Detail label="Account" value={accountName || 'Platform (no account)'} />}
          {source.last_collection_status && <Detail label="Last collection status" value={source.last_collection_status} />}
          <Detail label="Last collection run" value={collectionRunSummary(source.last_collection_run)} />
        </div>
        {source.connection_error && <AlertBanner type="error" message={source.connection_error.message} />}
        {source.last_collection_error && !source.connection_error && <AlertBanner type="error" message={source.last_collection_error} />}
        {runAlert && !source.connection_error && !source.last_collection_error && <AlertBanner type={runAlert.type} message={runAlert.message} />}
        <div className="flex flex-wrap items-end gap-2">
          <Select
            label="Collection window"
            value={lookback}
            onChange={(event) => setLookback(Number(event.target.value))}
            disabled={Boolean(busy)}
            className="w-40"
            data-collect-lookback={source.id}
          >
            {LOOKBACK_OPTIONS.map((minutes) => (
              <option key={minutes} value={minutes}>{minutes < 60 ? `Last ${minutes} min` : `Last ${minutes / 60} h`}</option>
            ))}
          </Select>
          <Button onClick={() => onCollect(lookback)} disabled={Boolean(busy)}>{busy === 'collect' ? 'Collecting...' : 'Collect Now'}</Button>
          <Button variant="secondary" onClick={onTest} disabled={Boolean(busy)}>
            <PlugZap className="h-4 w-4" /> {busy === 'test' ? 'Testing...' : 'Test Connection'}
          </Button>
          {canDelete && (
            <Button variant="ghost" onClick={onDelete} disabled={Boolean(busy)}>
              <Trash2 className="h-4 w-4" /> {busy === 'delete' ? 'Removing...' : 'Remove'}
            </Button>
          )}
        </div>
      </div>
    </Card>
  )
}

// Server .env collector from Step 2; kept for administrators and shown only when it is configured.
function LegacyCollectorCard({ status, accounts, onCollected }) {
  const [targetAccount, setTargetAccount] = useState('')
  const [collecting, setCollecting] = useState(false)
  const [result, setResult] = useState(null)

  const handleCollect = async () => {
    setCollecting(true)
    try {
      const data = await collectAzureTelemetry({ account_id: targetAccount, lookback_minutes: 15 })
      setResult(data.status === 'COLLECTION_OK'
        ? { type: 'success', message: `Retrieved ${data.records_retrieved}, inserted ${data.records_inserted}, deduplicated ${data.records_deduplicated}.` }
        : { type: 'error', message: data.error?.message || data.status })
      onCollected()
    } catch (err) {
      setResult({ type: 'error', message: cloudErrorMessage(err, 'Azure collection failed') })
    } finally {
      setCollecting(false)
    }
  }

  return (
    <Card title="Server-configured collector" subtitle={`Azure settings from the server .env · ${status.status}`}>
      {result && <AlertBanner type={result.type} message={result.message} />}
      <div className="mt-2 flex flex-wrap items-end gap-2" data-cloud-collect="AZURE">
        <Select label="Collect into account" value={targetAccount} onChange={(event) => setTargetAccount(event.target.value)} className="w-56">
          <option value="">Select account</option>
          {accounts.map((account) => <option key={account.id} value={account.id}>{account.name}</option>)}
        </Select>
        <Button onClick={handleCollect} disabled={collecting || !targetAccount}>
          {collecting ? 'Collecting...' : 'Collect now (last 15 min)'}
        </Button>
      </div>
    </Card>
  )
}

export default function CloudAccounts({ admin = false }) {
  const { isAdmin } = useAuth()
  const location = useLocation()
  const navigate = useNavigate()
  const onAddRoute = location.pathname.endsWith('/new')
  const [sources, setSources] = useState([])
  const [accounts, setAccounts] = useState([])
  const [summary, setSummary] = useState(null)
  const [legacy, setLegacy] = useState(null)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState('')
  const [formOpen, setFormOpen] = useState(false)
  const [busy, setBusy] = useState({})
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    const [sourceResult, summaryResult, accountResult, legacyResult] = await Promise.allSettled([
      getCloudSources(),
      admin ? Promise.resolve(null) : getAccountSummary(null, null, 'CLOUD'),
      isAdmin ? getAccountList() : Promise.resolve(null),
      admin ? getAzureCollectorStatus() : Promise.resolve(null),
    ])
    if (sourceResult.status === 'fulfilled') {
      setSources(sourceResult.value?.sources || [])
      setLoadError('')
    } else {
      setLoadError(cloudErrorMessage(sourceResult.reason, 'Cloud sources could not be loaded.'))
    }
    setSummary(summaryResult.status === 'fulfilled' ? summaryResult.value : null)
    setAccounts(accountResult.status === 'fulfilled' ? accountResult.value?.accounts || [] : [])
    setLegacy(legacyResult.status === 'fulfilled' ? legacyResult.value : null)
    setLoading(false)
  }, [admin, isAdmin])

  useEffect(() => {
    load()
  }, [load])

  const closeForm = () => {
    if (onAddRoute) navigate(addScreenExitPath('cancelled'), { replace: true })
    else setFormOpen(false)
  }

  const handleCreated = async (source) => {
    if (onAddRoute) {
      navigate(addScreenExitPath('created'), { replace: true })
      return
    }
    setError('')
    setMessage(`Cloud source added. Status: ${connectionLabel(source.connection_status)}. Last collection: Never.`)
    setFormOpen(false)
    await load()
  }

  const runAction = async (source, action, lookbackMinutes = 15) => {
    setBusy((current) => ({ ...current, [source.id]: action }))
    setMessage('')
    setError('')
    try {
      if (action === 'collect') {
        const result = await collectCloudSource(source.id, { lookback_minutes: lookbackMinutes })
        if (result.status === 'COLLECTION_OK') {
          setMessage(formatCloudCollectMessage(result))
        }
        else setError(result.error?.message || result.status)
      } else if (action === 'test') {
        const result = await testCloudSource(source.id)
        if (result.success) setMessage('Connection successful.')
        else setError(result.error?.message || 'Connection failed.')
      } else if (action === 'delete') {
        if (!window.confirm('Remove this cloud source? Collected events are kept.')) return
        await deleteCloudSource(source.id)
        setMessage('Cloud source removed.')
      }
      await load()
    } catch (err) {
      setError(cloudErrorMessage(err))
    } finally {
      setBusy((current) => ({ ...current, [source.id]: undefined }))
    }
  }

  if (onAddRoute) {
    return (
      <div className="page-shell">
        <PageHeader
          title="Add Cloud Account"
          subtitle="Connect a read-only Azure Log Analytics workspace. Cancel returns to environment selection."
        />
        <AddCloudSourceForm accounts={isAdmin ? accounts : null} onCreated={handleCreated} onCancel={closeForm} />
      </div>
    )
  }

  if (loading && !sources.length) return <LoadingSpinner label="Loading cloud sources..." />

  // The admin console has no /new route, so it opens the form in place.
  const showForm = admin && !loadError && (formOpen || sources.length === 0)
  const openAdd = () => (admin ? setFormOpen(true) : navigate(ADD_CLOUD_SOURCE_PATH))
  const accountNames = Object.fromEntries(accounts.map((account) => [account.id, account.name]))

  return (
    <div className="page-shell">
      <PageHeader
        title="Cloud Accounts"
        subtitle="Cloud sources connected to DefenSync. Collection is read-only; DefenSync never changes cloud resources."
        actions={(
          <>
            {!showForm && (
              <Button onClick={openAdd} data-add-resource="CLOUD"><Plus className="h-4 w-4" /> Add Cloud Account</Button>
            )}
            <Button variant="secondary" onClick={load}><RefreshCw className="h-4 w-4" /> Refresh</Button>
          </>
        )}
      />

      {message && <AlertBanner type="success" message={message} />}
      {(error || loadError) && <AlertBanner type="error" message={error || loadError} />}

      {showForm && (
        <AddCloudSourceForm
          accounts={isAdmin ? accounts : null}
          onCreated={handleCreated}
          onCancel={sources.length > 0 ? closeForm : null}
        />
      )}

      {!admin && !loadError && sources.length === 0 && (
        <Card className="py-10 text-center" data-workspace-empty="CLOUD">
          <Cloud className="mx-auto mb-3 h-10 w-10 muted-text" />
          <p className="text-lg font-semibold cyber-text">No Cloud Accounts configured</p>
          <p className="mt-1 text-sm muted-text">Connect an Azure Log Analytics workspace to start collecting cloud telemetry.</p>
          <Button className="mt-4" onClick={openAdd}><Plus className="h-4 w-4" /> Add Cloud Account</Button>
        </Card>
      )}

      {sources.length > 0 && (
        <section className="grid gap-4 lg:grid-cols-2">
          {sources.map((source) => (
            <CloudSourceCard
              key={source.id}
              source={source}
              accountName={isAdmin ? accountNames[source.account_id] || null : undefined}
              busy={busy[source.id]}
              canDelete={isAdmin}
              onCollect={(lookbackMinutes) => runAction(source, 'collect', lookbackMinutes)}
              onTest={() => runAction(source, 'test')}
              onDelete={() => runAction(source, 'delete')}
            />
          ))}
        </section>
      )}

      {!admin && sources.length > 0 && (
        <Card title="This account" subtitle="Private cloud telemetry for your account">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Metric label="Cloud events" value={summary?.events} />
            <Metric label="Failed sign-ins" value={summary?.failed_logins} />
            <Metric label="High risk" value={summary?.high_risk_events} />
            <Metric label="Incidents" value={summary?.incidents} />
          </div>
        </Card>
      )}

      {admin && legacy?.configured && <LegacyCollectorCard status={legacy} accounts={accounts} onCollected={load} />}
    </div>
  )
}

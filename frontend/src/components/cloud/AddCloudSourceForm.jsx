import { useState } from 'react'
import { CheckCircle2, PlugZap, XCircle } from 'lucide-react'
import { createCloudSource, testCloudConnection } from '../../api/client'
import {
  CREDENTIAL_FIELDS, EMPTY_SOURCE_FORM, PROVIDERS, SOURCE_TYPES, canAddSource, cloudErrorMessage,
  sourceFormProblems, testResultMessage, toSourcePayload,
} from '../../cloud/cloudSource'
import AlertBanner from '../ui/AlertBanner'
import Button from '../ui/Button'
import Card from '../ui/Card'
import { Input, Select } from '../ui/Input'

export default function AddCloudSourceForm({ accounts = null, onCreated, onCancel }) {
  const [form, setForm] = useState({ ...EMPTY_SOURCE_FORM })
  const [accountId, setAccountId] = useState('')
  const [problems, setProblems] = useState({})
  const [testResult, setTestResult] = useState(null)
  const [testing, setTesting] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const update = (name) => (event) => {
    const value = event.target.value
    setForm((current) => ({ ...current, [name]: value }))
    setProblems((current) => ({ ...current, [name]: undefined }))
    setTestResult(null)
    setError('')
  }

  const validate = () => {
    const found = sourceFormProblems(form)
    setProblems(found)
    return Object.keys(found).length === 0
  }

  const handleTest = async () => {
    if (!validate()) return
    setTesting(true)
    setError('')
    try {
      setTestResult(await testCloudConnection(toSourcePayload(form)))
    } catch (err) {
      setTestResult({ success: false, error: { message: cloudErrorMessage(err, 'Connection test failed.') } })
    } finally {
      setTesting(false)
    }
  }

  const handleAdd = async (event) => {
    event.preventDefault()
    if (!canAddSource(form, testResult) || !validate()) return
    setSaving(true)
    setError('')
    try {
      const source = await createCloudSource(toSourcePayload(form, { accountId: accounts ? accountId : null }))
      setForm({ ...EMPTY_SOURCE_FORM })
      setTestResult(null)
      onCreated?.(source)
    } catch (err) {
      setTestResult(null)
      setError(cloudErrorMessage(err, 'The cloud source could not be added.'))
    } finally {
      setSaving(false)
    }
  }

  const busy = testing || saving
  const sourceTypes = SOURCE_TYPES[form.provider] || []

  return (
    <Card title="Add Cloud Source" subtitle="Connect a read-only Azure Log Analytics workspace to this Cloud workspace">
      <form className="space-y-4" onSubmit={handleAdd} autoComplete="off" data-cloud-source-form="AZURE">
        {error && <AlertBanner type="error" message={error} />}
        <div className="grid gap-3 sm:grid-cols-2">
          <Select label="Cloud Provider" value={form.provider} onChange={update('provider')}>
            {PROVIDERS.map((provider) => <option key={provider.value} value={provider.value}>{provider.label}</option>)}
          </Select>
          <Select label="Source Type" value={form.source_type} onChange={update('source_type')}>
            {sourceTypes.map((type) => <option key={type.value} value={type.value}>{type.label}</option>)}
          </Select>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          {CREDENTIAL_FIELDS.map(({ name, label, placeholder, secret }) => (
            <div key={name}>
              <Input
                label={label}
                name={name}
                type={secret ? 'password' : 'text'}
                autoComplete={secret ? 'new-password' : 'off'}
                spellCheck={false}
                placeholder={placeholder}
                value={form[name]}
                onChange={update(name)}
                aria-invalid={Boolean(problems[name])}
              />
              {problems[name] && <p className="mt-1 px-2 text-xs text-[#B42318]">{problems[name]}</p>}
            </div>
          ))}
        </div>

        {accounts && (
          <Select label="Owner account" value={accountId} onChange={(event) => setAccountId(event.target.value)}>
            <option value="">Platform (no account)</option>
            {accounts.map((account) => <option key={account.id} value={account.id}>{account.name}</option>)}
          </Select>
        )}

        <p className="text-[11px] muted-text">
          Use an app registration with only the <strong>Log Analytics Reader</strong> role on the workspace. The client secret is encrypted on the server and is never shown again.
        </p>

        {testResult && (
          <div
            className={`flex items-start gap-2 rounded-2xl border px-3 py-2 text-sm ${testResult.success ? 'border-[#B7E0CF] bg-[#EEF8F3]' : 'border-[#F4C7C3] bg-[#FDF1F0]'}`}
            data-cloud-test-result={testResult.success ? 'success' : 'failed'}
          >
            {testResult.success ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" /> : <XCircle className="mt-0.5 h-4 w-4 shrink-0" />}
            <span>{testResultMessage(testResult)}</span>
          </div>
        )}

        <div className="flex flex-wrap gap-2">
          <Button type="button" variant="secondary" onClick={handleTest} disabled={busy}>
            <PlugZap className="h-4 w-4" /> {testing ? 'Testing...' : 'Test Connection'}
          </Button>
          <Button type="submit" disabled={!canAddSource(form, testResult, { busy })}>
            {saving ? 'Adding...' : 'Add Cloud Source'}
          </Button>
          {onCancel && <Button type="button" variant="ghost" onClick={onCancel} disabled={busy}>Cancel</Button>}
        </div>
        {!testResult?.success && <p className="text-[11px] muted-text">Run Test Connection successfully before adding the source.</p>}
      </form>
    </Card>
  )
}

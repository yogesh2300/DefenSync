import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Bar, BarChart, CartesianGrid, ComposedChart, Line, ReferenceLine, ResponsiveContainer, Scatter, Tooltip, XAxis, YAxis,
} from 'recharts'
import { BrainCircuit, Cloud, FlaskConical, GitBranch, RefreshCw } from 'lucide-react'
import {
  getBehavioralRfDemo, getOpenStackMlDemo, predictBehavioralPattern, trainBehavioralRfDemo, trainOpenStackMlDemo,
} from '../api/client'
import {
  BEHAVIORAL_FEATURES, DATA_SOURCES, DEFAULT_SESSION, LIVE_AZURE, behavioralView, openStackView, percent, sessionPayload,
} from '../mlDemo/mlDemo'
import AlertBanner from '../components/ui/AlertBanner'
import Button from '../components/ui/Button'
import Card from '../components/ui/Card'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import PageHeader from '../components/ui/PageHeader'

const TOOLTIP = {
  contentStyle: {
    background: 'var(--panel-strong)',
    border: '1px solid var(--panel-border)',
    borderRadius: 16,
    color: 'var(--text-main)',
    fontSize: 12,
  },
}

const SOURCE_ICONS = { LIVE_AZURE: Cloud, OPENSTACK_DEMO: GitBranch, SYNTHETIC_BEHAVIORAL: FlaskConical }

function errorText(err, fallback) {
  return err?.response?.data?.error || err?.response?.data?.detail || err?.message || fallback
}

function SourceTag({ sourceKey }) {
  const source = DATA_SOURCES.find((item) => item.key === sourceKey)
  if (!source) return null
  return (
    <span
      data-ml-source={source.key}
      className={`inline-flex items-center rounded-full border px-2.5 py-1 text-[10px] font-bold tracking-wide ${source.live ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-700' : 'border-amber-500/30 bg-amber-500/10 text-amber-700'}`}
    >
      {source.label}
    </span>
  )
}

function Disclaimer({ children }) {
  if (!children) return null
  return <p className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs font-medium text-amber-800">{children}</p>
}

function Stat({ label, value }) {
  return (
    <div className="rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-3">
      <p className="text-[11px] font-semibold uppercase tracking-wide muted-text">{label}</p>
      <p className="mt-1 text-lg font-bold cyber-text">{value}</p>
    </div>
  )
}

function OpenStackSection({ view, training, onTrain }) {
  if (!view) return null
  const threshold = view?.trained ? Number(view.stats.find((s) => s.label === 'Threshold')?.value) : null
  return (
    <Card
      title="Cloud API behaviour - Isolation Forest"
      subtitle="Is this cloud API behaviour unusual compared with the learned baseline?"
      action={<SourceTag sourceKey={view?.sourceKey} />}
    >
      <Disclaimer>{view?.disclaimer}</Disclaimer>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm cyber-text">
          Status: <span className="font-semibold">{view?.status}</span>
          {view?.modelVersion && <span className="muted-text"> · {view.modelVersion} · features {view.featureVersion} ({view.featureCount})</span>}
        </p>
        <Button size="sm" onClick={onTrain} disabled={training}>{training ? 'Training...' : view?.trained ? 'Retrain' : 'Train demonstration'}</Button>
      </div>
      {view?.message && !view.trained && <p className="mt-2 text-xs muted-text">{view.message}</p>}
      <p className="mt-2 text-xs muted-text">Aggregation: {view?.aggregation}</p>

      {view?.trained && (
        <>
          <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {view.stats.map((stat) => <Stat key={stat.label} {...stat} />)}
          </div>
          <div className="mt-4">
            <p className="mb-2 text-xs font-semibold muted-text">Anomaly score per window (higher is more unusual; dots are flagged windows)</p>
            <ResponsiveContainer width="100%" height={200}>
              <ComposedChart data={view.series}>
                <CartesianGrid stroke="rgba(148,163,184,0.12)" strokeDasharray="3 3" />
                <XAxis dataKey="index" tick={{ fill: '#A5A5A5', fontSize: 10 }} />
                <YAxis tick={{ fill: '#A5A5A5', fontSize: 10 }} width={40} domain={['auto', 'auto']} />
                <Tooltip {...TOOLTIP} labelFormatter={(index) => view.series[index]?.window || index} />
                {Number.isFinite(threshold) && <ReferenceLine y={threshold} stroke="#B76E79" strokeDasharray="4 4" />}
                <Line dataKey="score" stroke="#6F746F" dot={false} strokeWidth={1.5} isAnimationActive={false} />
                <Scatter dataKey="anomalous" fill="#B76E79" isAnimationActive={false} />
              </ComposedChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-4 overflow-x-auto">
            <p className="mb-2 text-xs font-semibold muted-text">Most anomalous windows and the features that deviate most from the baseline median</p>
            <table className="w-full text-left text-xs">
              <thead className="muted-text">
                <tr><th className="py-1 pr-3">Window start (dataset time)</th><th className="py-1 pr-3">Score</th><th className="py-1">Evidence</th></tr>
              </thead>
              <tbody>
                {view.topAnomalies.map((item) => (
                  <tr key={item.window} className="border-t border-[var(--panel-border)] align-top">
                    <td className="py-1.5 pr-3 font-mono">{item.window}</td>
                    <td className="py-1.5 pr-3 font-semibold cyber-text">{item.score.toFixed(3)}</td>
                    <td className="py-1.5 cyber-text">{item.evidence.join('; ') || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {view.evaluation && (
            <p className="mt-3 text-xs muted-text">{view.evaluation.text} {view.evaluation.note}</p>
          )}
          <p className="mt-2 text-[11px] muted-text">Never used as features: {view.excluded.join(', ')}.</p>
        </>
      )}
    </Card>
  )
}

function ConfusionTable({ confusion }) {
  if (!confusion) return null
  return (
    <div className="overflow-x-auto">
      <p className="mb-2 text-xs font-semibold muted-text">Confusion matrix (rows: true pattern, columns: predicted pattern)</p>
      <table className="text-xs">
        <thead className="muted-text">
          <tr>
            <th className="py-1 pr-2" />
            {confusion.labels.map((label) => <th key={label} className="px-2 py-1 font-semibold">{label.replace('_', ' ')}</th>)}
          </tr>
        </thead>
        <tbody>
          {confusion.matrix.map((row, i) => (
            <tr key={confusion.labels[i]} className="border-t border-[var(--panel-border)]">
              <th className="py-1 pr-2 text-left font-semibold muted-text">{confusion.labels[i].replace('_', ' ')}</th>
              {row.map((value, j) => (
                <td key={confusion.labels[j]} className={`px-2 py-1 text-center ${i === j ? 'font-bold cyber-text' : value ? 'font-semibold text-red-500' : 'muted-text'}`}>{value}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function BehavioralSection({ view, training, onTrain }) {
  const [form, setForm] = useState(DEFAULT_SESSION)
  const [prediction, setPrediction] = useState(null)
  const [predictError, setPredictError] = useState('')
  const [predicting, setPredicting] = useState(false)

  const handlePredict = async (event) => {
    event.preventDefault()
    const payload = sessionPayload(form)
    if (!payload) {
      setPredictError('Every session field must be a number.')
      return
    }
    setPredicting(true)
    setPredictError('')
    try {
      setPrediction(await predictBehavioralPattern(payload))
    } catch (err) {
      setPrediction(null)
      setPredictError(errorText(err, 'Prediction failed.'))
    } finally {
      setPredicting(false)
    }
  }

  if (!view) return null
  return (
    <Card
      title="Session behaviour - Random Forest"
      subtitle="What known behavioural pattern does this session most closely resemble?"
      action={<SourceTag sourceKey={view?.sourceKey} />}
    >
      <Disclaimer>{view && `${view.demonstration} ${view.disclaimer}`}</Disclaimer>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm cyber-text">
          Status: <span className="font-semibold">{view?.status}</span>
          {view?.modelVersion && <span className="muted-text"> · {view.modelVersion}</span>}
        </p>
        <Button size="sm" onClick={onTrain} disabled={training}>{training ? 'Training...' : view?.trained ? 'Retrain' : 'Train demonstration'}</Button>
      </div>
      {view?.message && !view.trained && <p className="mt-2 text-xs muted-text">{view.message}</p>}

      {view?.trained && (
        <>
          <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {view.stats.map((stat) => <Stat key={stat.label} {...stat} />)}
          </div>
          <div className="mt-4 grid gap-4 lg:grid-cols-2">
            <div className="overflow-x-auto">
              <p className="mb-2 text-xs font-semibold muted-text">Per-pattern hold-out metrics</p>
              <table className="w-full text-left text-xs">
                <thead className="muted-text">
                  <tr><th className="py-1 pr-2">Pattern</th><th className="py-1 pr-2">Sessions</th><th className="py-1 pr-2">Precision</th><th className="py-1 pr-2">Recall</th><th className="py-1 pr-2">F1</th><th className="py-1">Test n</th></tr>
                </thead>
                <tbody>
                  {view.classRows.map((row) => (
                    <tr key={row.name} className="border-t border-[var(--panel-border)]">
                      <td className="py-1 pr-2 font-semibold cyber-text">{row.name}</td>
                      <td className="py-1 pr-2">{row.total}</td>
                      <td className="py-1 pr-2">{row.precision}</td>
                      <td className="py-1 pr-2">{row.recall}</td>
                      <td className="py-1 pr-2">{row.f1}</td>
                      <td className="py-1">{row.support}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <ConfusionTable confusion={view.confusion} />
          </div>
          <div className="mt-4">
            <p className="mb-2 text-xs font-semibold muted-text">Feature importance (impurity-based)</p>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={view.importance} layout="vertical" margin={{ left: 40 }}>
                <CartesianGrid stroke="rgba(148,163,184,0.12)" strokeDasharray="3 3" />
                <XAxis type="number" tick={{ fill: '#A5A5A5', fontSize: 10 }} />
                <YAxis type="category" dataKey="feature" tick={{ fill: '#A5A5A5', fontSize: 10 }} width={150} />
                <Tooltip {...TOOLTIP} />
                <Bar dataKey="importance" fill="#A3A3A3" radius={[0, 8, 8, 0]} isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <form className="mt-4 rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-4" onSubmit={handlePredict}>
            <p className="mb-3 text-sm font-semibold cyber-text">Try a session (synthetic pattern match only)</p>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {BEHAVIORAL_FEATURES.map((feature) => (
                <label key={feature.key} className="text-xs muted-text">
                  {feature.label}
                  <input
                    type="number"
                    className="mt-1 w-full rounded-xl border border-[var(--panel-border)] bg-white px-3 py-1.5 text-sm text-[#111111]"
                    step={feature.step}
                    min={feature.min}
                    max={feature.max}
                    value={form[feature.key]}
                    onChange={(e) => setForm((prev) => ({ ...prev, [feature.key]: e.target.value }))}
                  />
                </label>
              ))}
            </div>
            <div className="mt-3 flex flex-wrap items-center gap-3">
              <Button size="sm" type="submit" disabled={predicting}>{predicting ? 'Classifying...' : 'Classify session'}</Button>
              {prediction && (
                <p className="text-sm cyber-text">
                  Closest synthetic pattern: <span className="font-bold">{prediction.predicted_pattern}</span> ({percent(prediction.confidence)})
                </p>
              )}
            </div>
            {predictError && <p className="mt-2 text-xs text-red-500">{predictError}</p>}
            {prediction && <p className="mt-2 text-[11px] muted-text">{prediction.disclaimer}</p>}
          </form>
          <p className="mt-2 text-[11px] muted-text">Never used as features: {view.excluded.join(', ')}.</p>
        </>
      )}
    </Card>
  )
}

export default function MlDemo() {
  const [openstack, setOpenstack] = useState(null)
  const [behavioral, setBehavioral] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [training, setTraining] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    const [os, rf] = await Promise.allSettled([getOpenStackMlDemo(), getBehavioralRfDemo()])
    if (os.status === 'fulfilled') setOpenstack(os.value)
    if (rf.status === 'fulfilled') setBehavioral(rf.value)
    const failed = [os, rf].find((item) => item.status === 'rejected')
    if (failed) setError(errorText(failed.reason, 'Failed to load ML demonstrations.'))
    setLoading(false)
  }, [])

  useEffect(() => { load() }, [load])

  const train = async (which) => {
    setTraining(which)
    setError('')
    try {
      if (which === 'openstack') setOpenstack(await trainOpenStackMlDemo())
      else setBehavioral(await trainBehavioralRfDemo())
    } catch (err) {
      setError(errorText(err, 'Training failed.'))
    } finally {
      setTraining('')
    }
  }

  const osView = useMemo(() => openStackView(openstack), [openstack])
  const rfView = useMemo(() => behavioralView(behavioral), [behavioral])

  return (
    <div className="page-shell">
      <PageHeader
        title="ML Demonstrations"
        subtitle="Dataset-only models, kept separate from live Azure telemetry and from the Linux detection models"
        actions={(
          <Button variant="secondary" onClick={load} disabled={loading || Boolean(training)}>
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        )}
      />

      {error && <AlertBanner type="error" message={error} />}

      <section className="grid gap-3 md:grid-cols-3">
        {DATA_SOURCES.map((source) => {
          const Icon = SOURCE_ICONS[source.key] || BrainCircuit
          return (
            <div key={source.key} className="rounded-2xl border border-[var(--panel-border)] bg-[var(--panel)] p-4">
              <div className="mb-2 flex items-center justify-between gap-2">
                <SourceTag sourceKey={source.key} />
                <Icon className="h-4 w-4 text-[#A5A5A5]" />
              </div>
              <p className="text-xs muted-text">{source.description}</p>
              {source.key === LIVE_AZURE && <p className="mt-2 text-[11px] font-semibold cyber-text">Shown on Dashboard, Events and Cloud Accounts - not on this page.</p>}
            </div>
          )
        })}
      </section>

      {loading ? (
        <LoadingSpinner label="Loading ML demonstrations..." />
      ) : (
        <>
          <OpenStackSection view={osView} training={training === 'openstack'} onTrain={() => train('openstack')} />
          <BehavioralSection view={rfView} training={training === 'behavioral'} onTrain={() => train('behavioral')} />
        </>
      )}
    </div>
  )
}

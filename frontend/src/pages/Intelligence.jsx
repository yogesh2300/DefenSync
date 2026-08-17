import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Tooltip, XAxis, YAxis, ResponsiveContainer,
} from 'recharts'
import { RefreshCw } from 'lucide-react'
import {
  getAlerts,
  getBehavioralAnomalies,
  getBehavioralProfiles,
  getBehavioralSummary,
  getEvents,
  getHighRiskEvents,
  getOpenStackDatasetStatus,
  getServers,
  loadBehavioralDemo,
  loadOpenStackDemo,
} from '../api/client'
import AlertBanner from '../components/ui/AlertBanner'
import Badge, { SeverityBadge } from '../components/ui/Badge'
import Button from '../components/ui/Button'
import Card from '../components/ui/Card'
import RiskWidget from '../components/ui/RiskWidget'
import { Select } from '../components/ui/Input'
import './Intelligence.css'

const TOOLTIP = {
  contentStyle: {
    background: 'var(--panel-strong)',
    border: '1px solid var(--panel-border)',
    borderRadius: 16,
    color: 'var(--text-main)',
    fontSize: 12,
  },
}

const FILTERS = ['All', 'Linux', 'OpenStack', 'Behavioral', 'Normal', 'Anomalous', 'High Risk', 'Critical']

function normalizeRows(value) {
  if (Array.isArray(value)) return value
  if (Array.isArray(value?.items)) return value.items
  return []
}

function parseJson(value, fallback = {}) {
  try {
    return typeof value === 'string' ? JSON.parse(value) : value || fallback
  } catch {
    return fallback
  }
}

function riskOf(event) {
  return Number(event?.behavioral_risk_score ?? event?.risk_score ?? 0) || 0
}

function sourceOf(event) {
  const source = (event?.source_type || 'LINUX').toUpperCase()
  if (source === 'CLOUD') return 'OpenStack'
  if (source === 'BEHAVIORAL') return 'Behavioral'
  return 'Linux'
}

function actorOf(event) {
  return event?.actor_id || event?.username || event?.user_id || event?.source_ip || 'unknown'
}

function labelOf(event) {
  return event?.behavioral_classification || event?.original_label || event?.classification || event?.severity || 'UNLABELLED'
}

function eventTime(event) {
  const parsed = event?.timestamp ? new Date(event.timestamp).getTime() : 0
  return Number.isFinite(parsed) ? parsed : 0
}

function eventId(event, index = 0) {
  return event?.event_id || event?.id || `${sourceOf(event)}-${eventTime(event)}-${index}`
}

function originOf(event) {
  return event?.data_origin || 'LIVE_LINUX'
}

function sourceBadge(event) {
  const source = sourceOf(event)
  const variant = source === 'OpenStack' ? 'medium' : source === 'Behavioral' ? 'normal' : 'info'
  return (
    <span title={originOf(event)}>
      <Badge variant={variant}>{source}</Badge>
    </span>
  )
}

function postureLevel(score) {
  if (score >= 85) return { label: 'Critical', variant: 'critical' }
  if (score >= 70) return { label: 'High', variant: 'high' }
  if (score >= 50) return { label: 'Medium', variant: 'medium' }
  if (score > 0) return { label: 'Low', variant: 'low' }
  return { label: 'Informational', variant: 'info' }
}

function CountUp({ value, className }) {
  const target = Number(value) || 0
  const [shown, setShown] = useState(target)
  useEffect(() => {
    const reduce = typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches
    if (reduce) {
      setShown(target)
      return undefined
    }
    let frame
    let origin = shown
    const startAt = performance.now()
    const tick = (now) => {
      const progress = Math.min(1, (now - startAt) / 800)
      setShown(Math.round(origin + (target - origin) * progress))
      if (progress < 1) frame = requestAnimationFrame(tick)
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [target])
  return <span className={className}>{shown}</span>
}

function StatusDot({ active }) {
  return (
    <span
      className={`inline-flex h-2 w-2 rounded-full ${active ? 'bg-[#6EA779] intel-pulse-dot' : 'bg-[#C9CCC7]'}`}
      aria-hidden="true"
    />
  )
}

function severityScore(event) {
  const severity = (event?.severity || '').toLowerCase()
  if (severity === 'critical') return 100
  if (severity === 'high' || severity === 'error') return 80
  if (severity === 'medium' || severity === 'warning') return 55
  if (severity === 'low') return 30
  return riskOf(event)
}

function recommendationFor(score, evidence = []) {
  if (score >= 85) {
    return {
      level: 'Critical',
      action: 'Escalate immediately, require identity verification, review related host and OpenStack activity, and prepare containment approval.',
      reason: 'Overall risk is critical based on event risk, behavioral signals, and correlated evidence.',
    }
  }
  if (score >= 70) {
    return {
      level: 'High',
      action: 'Prioritize analyst review and validate the identity, session, server, and cloud resource involved.',
      reason: 'Multiple high-risk indicators were observed.',
    }
  }
  if (score >= 50) {
    return {
      level: 'Medium',
      action: 'Investigate related events and monitor the identity for repeated behavior.',
      reason: 'Suspicious evidence exists but does not yet reach critical severity.',
    }
  }
  if (evidence.length) {
    return {
      level: 'Low',
      action: 'Monitor and retain evidence for trend review.',
      reason: 'Some related evidence exists, but the current risk remains low.',
    }
  }
  return {
    level: 'Informational',
    action: 'Continue monitoring through normal SOC workflow.',
    reason: 'No strong correlated threat pattern is visible for the selected record.',
  }
}

function computeCorrelation(events) {
  const groups = new Map()
  events.forEach((event) => {
    const actor = actorOf(event)
    if (!actor || actor === 'unknown') return
    if (!groups.has(actor)) groups.set(actor, [])
    groups.get(actor).push(event)
  })

  const incidents = []
  groups.forEach((rows, actor) => {
    const sorted = [...rows].sort((a, b) => eventTime(a) - eventTime(b))
    const hasLinuxLogin = sorted.some((event) => sourceOf(event) === 'Linux' && /login|ssh|auth/i.test(`${event.event_type} ${event.message}`))
    const hasPrivilege = sorted.some((event) => sourceOf(event) === 'Linux' && /sudo|privilege|root|escalat|admin/i.test(`${event.event_type} ${event.message}`))
    const hasCloud = sorted.some((event) => sourceOf(event) === 'OpenStack')
    const hasBehavior = sorted.some((event) => sourceOf(event) === 'Behavioral' && riskOf(event) >= 50)
    const highRisk = sorted.filter((event) => riskOf(event) >= 70 || ['critical', 'high', 'error'].includes((event.severity || '').toLowerCase()))
    const evidence = [
      hasLinuxLogin && 'Linux login/authentication activity',
      hasPrivilege && 'Privilege-related Linux activity',
      hasCloud && 'OpenStack cloud activity',
      hasBehavior && 'Behavioral anomaly or over-efficiency',
      highRisk.length > 0 && `${highRisk.length} high-risk record(s)`,
    ].filter(Boolean)
    if (evidence.length < 2) return
    const confidence = Math.min(100, Math.round((evidence.length / 5) * 80 + Math.min(highRisk.length, 4) * 5))
    const maxRisk = Math.max(...sorted.map(riskOf), 0)
    const lastEvent = sorted[sorted.length - 1]
    incidents.push({
      id: `${actor}-${eventTime(lastEvent)}`,
      actor,
      confidence,
      evidence,
      relatedEvents: sorted,
      latestEvent: lastEvent,
      score: Math.min(100, Math.round((confidence * 0.45) + (maxRisk * 0.55))),
      sources: [...new Set(sorted.map(sourceOf))],
    })
  })
  return incidents.sort((a, b) => b.score - a.score).slice(0, 12)
}

function relatedEventsFor(event, events) {
  if (!event) return []
  const actor = actorOf(event)
  const server = event.server_id || event.hostname || event.resource_id
  const time = eventTime(event)
  const windowMs = 15 * 60 * 1000
  return events
    .filter((candidate) => {
      if (eventId(candidate) === eventId(event)) return true
      const sameActor = actor !== 'unknown' && actorOf(candidate) === actor
      const sameServer = server && [candidate.server_id, candidate.hostname, candidate.resource_id].includes(server)
      const closeInTime = Math.abs(eventTime(candidate) - time) <= windowMs
      return closeInTime && (sameActor || sameServer)
    })
    .sort((a, b) => eventTime(a) - eventTime(b))
    .slice(0, 20)
}

function MiniRow({ label, value }) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] px-3 py-2">
      <span className="text-xs muted-text">{label}</span>
      <span className="text-sm font-semibold cyber-text">{value ?? '-'}</span>
    </div>
  )
}

function SecurityPosture({ score, incidents, linuxActive, cloudActive, behaviorActive }) {
  const level = postureLevel(score)
  const radius = 54
  const circ = 2 * Math.PI * radius
  const offset = circ - (Math.min(100, Math.max(0, score)) / 100) * circ
  return (
    <Card className="intel-enter h-full">
      <p className="text-[11px] font-semibold uppercase tracking-wide muted-text">Security Posture</p>
      <div className="mt-3 flex flex-col items-center gap-3 sm:flex-row sm:items-center sm:gap-6">
        <div className="relative h-[140px] w-[140px] shrink-0">
          <svg width="140" height="140" className="intel-ring" aria-hidden="true">
            <circle cx="70" cy="70" r={radius} fill="none" stroke="var(--panel-border)" strokeWidth="10" />
            <circle
              cx="70"
              cy="70"
              r={radius}
              fill="none"
              stroke="#111111"
              strokeWidth="10"
              strokeLinecap="round"
              strokeDasharray={circ}
              strokeDashoffset={offset}
              className="intel-ring-progress"
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <CountUp value={score} className="text-4xl font-bold tabular-nums cyber-text" />
            <Badge variant={level.variant}>{level.label}</Badge>
          </div>
        </div>
        <div className="w-full space-y-2">
          <MiniRow label="Correlated incidents" value={incidents} />
          <div className="grid grid-cols-3 gap-2 text-center">
            <div className="rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] px-2 py-2">
              <div className="flex items-center justify-center gap-1 text-[11px] muted-text"><StatusDot active={linuxActive} /> Linux</div>
              <p className="mt-1 text-xs font-semibold cyber-text">{linuxActive ? 'Available' : 'None loaded'}</p>
            </div>
            <div className="rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] px-2 py-2">
              <div className="flex items-center justify-center gap-1 text-[11px] muted-text"><StatusDot active={cloudActive} /> OpenStack</div>
              <p className="mt-1 text-xs font-semibold cyber-text">{cloudActive ? 'Available' : 'None loaded'}</p>
            </div>
            <div className="rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] px-2 py-2">
              <div className="flex items-center justify-center gap-1 text-[11px] muted-text"><StatusDot active={behaviorActive} /> Behavior</div>
              <p className="mt-1 text-xs font-semibold cyber-text">{behaviorActive ? 'Available' : 'None loaded'}</p>
            </div>
          </div>
        </div>
      </div>
    </Card>
  )
}

function IntelligenceFlow({ linuxCount, cloudCount, behaviorCount, risk }) {
  return (
    <Card className="intel-enter intel-enter-delay-1 h-full">
      <p className="text-[11px] font-semibold uppercase tracking-wide muted-text">Intelligence Flow</p>
      <p className="mt-1 text-sm muted-text">Evidence sources feed correlation, then risk.</p>
      <div className="mt-4 space-y-3">
        {[
          ['Linux', linuxCount],
          ['OpenStack', cloudCount],
          ['Behavior', behaviorCount],
        ].map(([label, count], index) => (
          <div key={label} className="flex items-center gap-3">
            <div className="w-24 shrink-0 text-sm font-semibold cyber-text">{label}</div>
            <div className="intel-flow-track flex-1">
              <span className={`intel-flow-dot delay-${index}`} />
            </div>
            <span className="w-16 text-right text-xs tabular-nums muted-text">{count}</span>
          </div>
        ))}
      </div>
      <div className="mt-4 flex flex-wrap items-center justify-between gap-2 rounded-2xl bg-[var(--mint)] px-4 py-3">
        <span className="text-sm font-semibold cyber-text">Correlation engine</span>
        <span className="text-xs muted-text">→ Risk <strong className="cyber-text">{risk}</strong></span>
      </div>
    </Card>
  )
}

function ActiveInvestigation({ incident, recommendation, classification }) {
  if (!incident) {
    return (
      <Card className="intel-enter intel-enter-delay-2 h-full">
        <p className="text-[11px] font-semibold uppercase tracking-wide muted-text">Active Investigation</p>
        <p className="mt-4 text-sm muted-text">No multi-evidence correlation is available in the currently loaded records.</p>
      </Card>
    )
  }
  const steps = [
    incident.sources.includes('OpenStack') && 'OpenStack activity',
    incident.sources.includes('Behavioral') && 'Behavioral deviation',
    classification && classification !== 'NORMAL' ? String(classification).replace(/_/g, ' ') : null,
    incident.evidence.find((item) => /high-risk/i.test(item)),
    recommendation?.level ? `${recommendation.level} recommendation` : 'Analyst recommendation',
  ].filter(Boolean)
  return (
    <Card className="intel-enter intel-enter-delay-2 h-full">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wide muted-text">Active Investigation</p>
          <h2 className="mt-1 text-2xl font-bold tracking-tight cyber-text">{incident.actor}</h2>
          <p className="mt-1 text-sm muted-text">Cross-source evidence · {incident.sources.join(' → ')}</p>
        </div>
        <div className="text-right">
          <p className="text-3xl font-bold tabular-nums cyber-text">{incident.score}</p>
          <p className="text-xs muted-text">{incident.confidence}% confidence</p>
        </div>
      </div>
      <div className="mt-4 space-y-2">
        {steps.map((step, index) => (
          <div key={`${step}-${index}`} className="flex gap-3">
            <div className="flex w-4 flex-col items-center">
              <span className="mt-1 h-2.5 w-2.5 rounded-full bg-[#111111]" />
              {index < steps.length - 1 && <span className="mt-1 w-px flex-1 bg-[var(--panel-border)]" />}
            </div>
            <p className="pb-3 text-sm cyber-text">{step}</p>
          </div>
        ))}
      </div>
      <div className="mt-1 flex flex-wrap gap-2">
        {incident.evidence.map((item) => <Badge key={item} variant="info">{item}</Badge>)}
      </div>
      <p className="mt-4 text-sm muted-text">{recommendation?.action}</p>
    </Card>
  )
}

function EvidenceTimeline({ events, recommendation }) {
  const items = (events || []).slice(0, 8)
  return (
    <div className="mt-4 max-h-80 overflow-auto pr-1">
      <p className="text-xs font-semibold uppercase tracking-wide muted-text">Evidence timeline</p>
      <div className="mt-3">
        {items.map((event, index) => (
          <div key={eventId(event, index)} className="intel-timeline-item flex gap-3" style={{ animationDelay: `${index * 60}ms` }}>
            <div className="flex w-4 flex-col items-center">
              <span className="mt-1 h-2.5 w-2.5 rounded-full bg-[#6EA779]" />
              <span className="mt-1 w-px flex-1 bg-[var(--panel-border)]" />
            </div>
            <div className="pb-4">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-[11px] muted-text">{event.timestamp ? new Date(event.timestamp).toLocaleString() : '-'}</span>
                {sourceBadge(event)}
                <SeverityBadge severity={event.severity || 'info'} />
              </div>
              <p className="mt-1 text-sm font-semibold cyber-text">{event.event_type || 'Event'}</p>
              <p className="line-clamp-2 text-xs muted-text">{event.message || event.raw_log}</p>
              <p className="mt-1 text-[11px] muted-text">{originOf(event)}</p>
            </div>
          </div>
        ))}
        {recommendation && (
          <div className="intel-timeline-item flex gap-3" style={{ animationDelay: `${items.length * 60}ms` }}>
            <div className="flex w-4 flex-col items-center">
              <span className="mt-1 h-2.5 w-2.5 rounded-full bg-[#111111]" />
            </div>
            <div className="pb-1">
              <p className="text-xs font-semibold uppercase tracking-wide muted-text">Recommendation</p>
              <p className="mt-1 text-sm font-semibold cyber-text">{recommendation.level}</p>
              <p className="text-xs muted-text">{recommendation.action}</p>
            </div>
          </div>
        )}
        {!items.length && <p className="text-sm muted-text">Select a record to inspect related evidence.</p>}
      </div>
    </div>
  )
}

function SourceCards({ linuxCount, cloudCount, behaviorCount, profileStatus }) {
  const cards = [
    { name: 'Linux', count: linuxCount, status: linuxCount > 0 ? 'Available' : 'None loaded' },
    { name: 'OpenStack', count: cloudCount, status: cloudCount > 0 ? 'Available' : 'None loaded' },
    { name: 'Behavior', count: behaviorCount, status: profileStatus ? `Profile ${profileStatus}` : (behaviorCount > 0 ? 'Available' : 'None loaded') },
  ]
  return (
    <div className="grid gap-3 md:grid-cols-3">
      {cards.map((card, index) => (
        <div key={card.name} className={`intel-source-card intel-enter intel-enter-delay-${index + 1} rounded-3xl border border-[var(--panel-border)] bg-[var(--panel)] p-4`}>
          <div className="flex items-center justify-between">
            <p className="text-sm font-semibold cyber-text">{card.name}</p>
            <StatusDot active={card.count > 0} />
          </div>
          <p className="mt-2 text-2xl font-bold tabular-nums cyber-text"><CountUp value={card.count} /></p>
          <p className="mt-1 text-xs muted-text">{card.status}</p>
        </div>
      ))}
    </div>
  )
}

function OperationalSnapshot({ overview }) {
  const items = [
    ['Linux', overview.linuxEvents],
    ['Cloud', overview.cloudEvents],
    ['Behavioral', overview.behavioralEvents],
    ['High risk', overview.highRiskEvents],
    ['Users', overview.activeUsers],
    ['Servers', overview.servers],
    ['Profiles', overview.behaviorProfiles],
  ]
  return (
    <div className="intel-enter intel-enter-delay-3 grid grid-cols-2 gap-2 sm:grid-cols-4 xl:grid-cols-7">
      {items.map(([label, value]) => (
        <div key={label} className="rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] px-3 py-2">
          <p className="text-[10px] font-semibold uppercase tracking-wide muted-text">{label}</p>
          <p className="mt-1 text-lg font-bold tabular-nums cyber-text">{value ?? 0}</p>
        </div>
      ))}
    </div>
  )
}

export default function Intelligence() {
  const [events, setEvents] = useState([])
  const [profiles, setProfiles] = useState([])
  const [behavioralSummary, setBehavioralSummary] = useState(null)
  const [behavioralAnomalies, setBehavioralAnomalies] = useState([])
  const [openStackStatus, setOpenStackStatus] = useState(null)
  const [alerts, setAlerts] = useState([])
  const [servers, setServers] = useState([])
  const [highRiskEvents, setHighRiskEvents] = useState([])
  const [loading, setLoading] = useState(true)
  const [errors, setErrors] = useState([])
  const [filter, setFilter] = useState('All')
  const [selectedIdentity, setSelectedIdentity] = useState('')
  const [selectedEventId, setSelectedEventId] = useState('')
  const [demoLoading, setDemoLoading] = useState(false)
  const [demoMessage, setDemoMessage] = useState('')
  const [demoError, setDemoError] = useState('')
  const [cloudDemoLoading, setCloudDemoLoading] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    const nextErrors = []
    const [allEvents, cloudEvents, behavioralEvents, highRisk, osStatus, bSummary, bProfiles, bAnomalies, alertRows, serverRows] = await Promise.allSettled([
      getEvents({ limit: 1000, sort_order: 'newest' }),
      getEvents({ limit: 1000, source_type: 'CLOUD', provider: 'OPENSTACK', sort_order: 'newest' }),
      getEvents({ limit: 1000, source_type: 'BEHAVIORAL', sort_order: 'newest' }),
      getHighRiskEvents(100),
      getOpenStackDatasetStatus(),
      getBehavioralSummary(),
      getBehavioralProfiles(),
      getBehavioralAnomalies(100),
      getAlerts({ limit: 100 }),
      getServers(false),
    ])

    const merged = []
    const seen = new Set()
    const addRows = (rows) => {
      normalizeRows(rows).forEach((event, index) => {
        const id = eventId(event, index)
        if (seen.has(id)) return
        seen.add(id)
        merged.push(event)
      })
    }

    if (allEvents.status === 'fulfilled') addRows(allEvents.value)
    else nextErrors.push(`Events API unavailable: ${allEvents.reason?.message || 'failed to load events'}`)
    if (cloudEvents.status === 'fulfilled') addRows(cloudEvents.value)
    else nextErrors.push(`OpenStack event filter unavailable: ${cloudEvents.reason?.message || 'failed to load OpenStack records'}`)
    if (behavioralEvents.status === 'fulfilled') addRows(behavioralEvents.value)
    else nextErrors.push(`Behavioral event filter unavailable: ${behavioralEvents.reason?.message || 'failed to load behavioral records'}`)

    setEvents(merged.sort((a, b) => eventTime(b) - eventTime(a)))

    if (highRisk.status === 'fulfilled') setHighRiskEvents(normalizeRows(highRisk.value))
    else nextErrors.push(`High-risk event API unavailable: ${highRisk.reason?.message || 'failed to load high-risk records'}`)
    if (osStatus.status === 'fulfilled') setOpenStackStatus(osStatus.value)
    else nextErrors.push(`OpenStack summary unavailable: ${osStatus.reason?.message || 'failed to load OpenStack summary'}`)
    if (bSummary.status === 'fulfilled') setBehavioralSummary(bSummary.value)
    else nextErrors.push(`Behavioral summary unavailable: ${bSummary.reason?.message || 'failed to load behavioral summary'}`)
    if (bProfiles.status === 'fulfilled') {
      const rows = normalizeRows(bProfiles.value)
      setProfiles(rows)
      setSelectedIdentity((current) => {
        if (current && rows.some((profile) => profile.identity_key === current)) return current
        const yogesh = rows.find((profile) => (profile.identity_key || '').toLowerCase() === 'yogesh')
        return yogesh?.identity_key || rows[0]?.identity_key || ''
      })
    } else nextErrors.push(`Behavioral profiles unavailable: ${bProfiles.reason?.message || 'failed to load profiles'}`)
    if (bAnomalies.status === 'fulfilled') setBehavioralAnomalies(normalizeRows(bAnomalies.value))
    else nextErrors.push(`Behavioral anomalies unavailable: ${bAnomalies.reason?.message || 'failed to load anomalies'}`)
    if (alertRows.status === 'fulfilled') setAlerts(normalizeRows(alertRows.value))
    else nextErrors.push(`Alerts API unavailable: ${alertRows.reason?.message || 'failed to load alerts'}`)
    if (serverRows.status === 'fulfilled') setServers(normalizeRows(serverRows.value))
    else nextErrors.push(`Servers API unavailable: ${serverRows.reason?.message || 'failed to load servers'}`)

    setErrors(nextErrors)
    setLoading(false)
  }, [])

  const handleLoadDemo = useCallback(async () => {
    setDemoLoading(true)
    setDemoError('')
    setDemoMessage('')
    try {
      const result = await loadBehavioralDemo()
      const imported = result.already_imported ? 'already imported' : `imported ${result.imported ?? 0} rows`
      setDemoMessage(
        `Synthetic behavioral data ${imported}. Active profiles: ${result.profiles_active ?? 0}. Events analyzed: ${result.events_analyzed ?? 0}.`,
      )
      setSelectedIdentity('yogesh')
      await load()
    } catch (err) {
      setDemoError(err.response?.data?.error || err.response?.data?.detail || err.message || 'Failed to load synthetic behavioral demo data.')
    } finally {
      setDemoLoading(false)
    }
  }, [load])

  const handleLoadOpenStackDemo = useCallback(async () => {
    setCloudDemoLoading(true)
    setDemoError('')
    setDemoMessage('')
    try {
      const result = await loadOpenStackDemo()
      const imported = result.already_imported ? 'already imported' : `imported ${result.records_imported ?? 0} rows`
      setDemoMessage(
        `SYNTHETIC OPENSTACK DEMO ${imported}. Status: ${result.status}. Origin: ${result.data_origin || 'SYNTHETIC_CLOUD_DEMO'}.`,
      )
      await load()
    } catch (err) {
      setDemoError(err.response?.data?.error || err.response?.data?.detail || err.message || 'Failed to load OpenStack demo data.')
    } finally {
      setCloudDemoLoading(false)
    }
  }, [load])

  useEffect(() => {
    load()
  }, [load])

  const sourceCounts = useMemo(() => {
    const counts = { Linux: 0, OpenStack: 0, Behavioral: 0 }
    events.forEach((event) => { counts[sourceOf(event)] += 1 })
    return counts
  }, [events])

  const selectedProfile = useMemo(
    () => profiles.find((profile) => profile.identity_key === selectedIdentity) || profiles[0],
    [profiles, selectedIdentity],
  )

  const behavioralEvents = useMemo(() => events.filter((event) => sourceOf(event) === 'Behavioral'), [events])
  const cloudEvents = useMemo(() => events.filter((event) => sourceOf(event) === 'OpenStack'), [events])
  const linuxEvents = useMemo(() => events.filter((event) => sourceOf(event) === 'Linux'), [events])
  const correlations = useMemo(() => computeCorrelation(events), [events])

  const selectedBehaviorEvent = useMemo(() => {
    if (!selectedProfile) return behavioralEvents[0]
    return behavioralEvents
      .filter((event) => actorOf(event) === selectedProfile.identity_key)
      .sort((a, b) => riskOf(b) - riskOf(a))[0] || behavioralEvents[0]
  }, [behavioralEvents, selectedProfile])

  const filteredEvents = useMemo(() => events.filter((event) => {
    const source = sourceOf(event)
    const label = labelOf(event).toString().toUpperCase()
    const risk = riskOf(event)
    if (filter === 'Linux') return source === 'Linux'
    if (filter === 'OpenStack') return source === 'OpenStack'
    if (filter === 'Behavioral') return source === 'Behavioral'
    if (filter === 'Normal') return risk < 30 || label === 'NORMAL'
    if (filter === 'Anomalous') return risk >= 50 || !['NORMAL', 'INFO', 'LOW'].includes(label)
    if (filter === 'High Risk') return risk >= 70
    if (filter === 'Critical') return risk >= 85 || (event.severity || '').toLowerCase() === 'critical'
    return true
  }).slice(0, 150), [events, filter])

  const selectedEvent = useMemo(() => (
    events.find((event, index) => eventId(event, index) === selectedEventId)
    || correlations[0]?.latestEvent
    || highRiskEvents[0]
    || events[0]
  ), [correlations, events, highRiskEvents, selectedEventId])

  const relatedEvents = useMemo(() => relatedEventsFor(selectedEvent, events), [events, selectedEvent])
  const selectedCorrelation = useMemo(() => {
    const actor = actorOf(selectedEvent)
    return correlations.find((item) => item.actor === actor)
  }, [correlations, selectedEvent])

  const selectedAnalysis = parseJson(selectedBehaviorEvent?.normalized_data, {})?.behavioral_analysis || {}
  const overview = useMemo(() => {
    const uniqueUsers = new Set(events.map(actorOf).filter((actor) => actor && actor !== 'unknown')).size
    return {
      linuxEvents: sourceCounts.Linux,
      cloudEvents: openStackStatus?.summary?.total_openstack_events ?? sourceCounts.OpenStack,
      behavioralEvents: behavioralSummary?.total_behavioral_events ?? sourceCounts.Behavioral,
      highRiskEvents: highRiskEvents.length || events.filter((event) => riskOf(event) >= 70).length,
      criticalEvents: events.filter((event) => riskOf(event) >= 85 || (event.severity || '').toLowerCase() === 'critical').length,
      activeUsers: uniqueUsers,
      servers: servers.length || new Set(events.map((event) => event.server_id || event.hostname).filter(Boolean)).size,
      behaviorProfiles: profiles.length,
    }
  }, [behavioralSummary, events, highRiskEvents.length, openStackStatus, profiles.length, servers.length, sourceCounts])

  const riskBreakdown = useMemo(() => {
    const behaviorRisk = riskOf(selectedBehaviorEvent)
    const cloudSeverity = cloudEvents.length ? Math.round(cloudEvents.reduce((sum, event) => sum + severityScore(event), 0) / cloudEvents.length) : 0
    const correlationScore = selectedCorrelation?.score || 0
    const overall = Math.round((behaviorRisk * 0.4) + (cloudSeverity * 0.25) + (correlationScore * 0.35))
    return { behaviorRisk, cloudSeverity, correlationScore, overall }
  }, [cloudEvents, selectedBehaviorEvent, selectedCorrelation])

  const recommendation = recommendationFor(riskBreakdown.overall, selectedCorrelation?.evidence || [])
  const leadIncident = correlations[0] || null
  const investigationRecommendation = recommendationFor(leadIncident?.score || 0, leadIncident?.evidence || [])
  const linuxActive = sourceCounts.Linux > 0
  const cloudActive = sourceCounts.OpenStack > 0 || (openStackStatus?.summary?.total_openstack_events || 0) > 0
  const behaviorActive = sourceCounts.Behavioral > 0 || profiles.length > 0

  const trend = useMemo(() => {
    const buckets = new Map()
    events.slice(0, 300).forEach((event) => {
      const date = event.timestamp ? new Date(event.timestamp) : null
      const label = date && !Number.isNaN(date.getTime()) ? `${date.getMonth() + 1}/${date.getDate()} ${date.getHours()}:00` : 'unknown'
      const current = buckets.get(label) || { label, count: 0, risk: 0 }
      current.count += 1
      current.risk += riskOf(event)
      buckets.set(label, current)
    })
    return [...buckets.values()].slice(-18).map((item) => ({
      label: item.label,
      risk: item.count ? Math.round(item.risk / item.count) : 0,
      count: item.count,
    }))
  }, [events])

  return (
    <div className="page-shell">
      <header className="intel-enter flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.18em] muted-text">DefenSync Intelligence</p>
          <h1 className="mt-1 text-3xl font-bold tracking-tight cyber-text">Hybrid Behavioral Threat Intelligence</h1>
          <div className="mt-3 flex flex-wrap gap-2">
            {[
              ['Linux', linuxActive],
              ['OpenStack', cloudActive],
              ['Behavioral', behaviorActive],
              ['ML Analysis', true],
            ].map(([label, active]) => (
              <span key={label} className="inline-flex items-center gap-2 rounded-full border border-[var(--panel-border)] bg-white px-3 py-1 text-xs font-semibold cyber-text">
                <StatusDot active={active} />
                {label}
              </span>
            ))}
          </div>
          <p className="mt-3 text-sm muted-text">Monitoring multiple security evidence sources — activity, behavior, correlation, risk, and recommendation.</p>
        </div>
        <details className="rounded-3xl border border-[var(--panel-border)] bg-[var(--panel)] px-4 py-3 xl:min-w-[280px]">
          <summary className="cursor-pointer text-sm font-semibold cyber-text">Data sources / actions</summary>
          <div className="mt-3 space-y-2">
            <Button variant="secondary" className="w-full" onClick={handleLoadDemo} disabled={demoLoading || cloudDemoLoading || loading}>
              {demoLoading ? 'Loading demo...' : 'Load Behavioral Demo Data'}
            </Button>
            <Button variant="secondary" className="w-full" onClick={handleLoadOpenStackDemo} disabled={demoLoading || cloudDemoLoading || loading}>
              {cloudDemoLoading ? 'Loading OpenStack...' : 'Load OpenStack Demo Data'}
            </Button>
            <Button className="w-full" onClick={load} disabled={loading || demoLoading || cloudDemoLoading}><RefreshCw className="h-4 w-4" /> Refresh</Button>
            <p className="text-[11px] leading-5 muted-text">
              Behavioral metrics are generated research telemetry, not live keystroke capture.
              OpenStack records use imported or demonstration origin metadata. Azure is not used.
            </p>
          </div>
        </details>
      </header>

      {demoMessage && <AlertBanner type="success" message={demoMessage} />}
      {demoError && <AlertBanner type="error" message={demoError} />}
      {errors.length > 0 && (
        <div className="space-y-2">
          {errors.map((error) => <AlertBanner key={error} type="warning" message={error} />)}
        </div>
      )}
      {loading && <Card><p className="py-8 text-center text-sm muted-text">Loading Security Intelligence Center...</p></Card>}

      {!loading && (
        <>
          <section className="grid gap-4 lg:grid-cols-2 2xl:grid-cols-3">
            <SecurityPosture
              score={riskBreakdown.overall}
              incidents={correlations.length}
              linuxActive={linuxActive}
              cloudActive={cloudActive}
              behaviorActive={behaviorActive}
            />
            <IntelligenceFlow
              linuxCount={overview.linuxEvents}
              cloudCount={overview.cloudEvents}
              behaviorCount={overview.behavioralEvents}
              risk={riskBreakdown.overall}
            />
            <ActiveInvestigation
              incident={leadIncident}
              recommendation={investigationRecommendation}
              classification={leadIncident ? (events.filter((event) => actorOf(event) === leadIncident.actor && sourceOf(event) === 'Behavioral').sort((a, b) => riskOf(b) - riskOf(a))[0]?.behavioral_classification) : null}
            />
          </section>

          <OperationalSnapshot overview={overview} />
          <SourceCards
            linuxCount={overview.linuxEvents}
            cloudCount={overview.cloudEvents}
            behaviorCount={overview.behavioralEvents}
            profileStatus={selectedProfile?.status}
          />

          <UnifiedEventStream events={filteredEvents} filter={filter} setFilter={setFilter} onSelect={setSelectedEventId} selectedEvent={selectedEvent} />
          <section className="grid gap-4 xl:grid-cols-[1fr_0.9fr]">
            <BehavioralAnalytics
              profiles={profiles}
              selectedIdentity={selectedIdentity}
              setSelectedIdentity={setSelectedIdentity}
              selectedProfile={selectedProfile}
              selectedBehaviorEvent={selectedBehaviorEvent}
              selectedAnalysis={selectedAnalysis}
              behavioralSummary={behavioralSummary}
              behavioralEvents={behavioralEvents}
            />
            <CloudActivity cloudEvents={cloudEvents} openStackStatus={openStackStatus} />
          </section>
          <section className="grid gap-4 xl:grid-cols-[0.95fr_1.05fr]">
            <ThreatCorrelation correlations={correlations} />
            <ThreatInvestigation
              selectedEvent={selectedEvent}
              relatedEvents={relatedEvents}
              selectedCorrelation={selectedCorrelation}
              selectedBehaviorEvent={selectedBehaviorEvent}
              recommendation={recommendation}
            />
          </section>
          <section className="grid gap-4 xl:grid-cols-[0.9fr_1.1fr]">
            <RiskAnalysis breakdown={riskBreakdown} trend={trend} />
            <SecurityRecommendation recommendation={recommendation} selectedCorrelation={selectedCorrelation} selectedEvent={selectedEvent} alerts={alerts} />
          </section>
        </>
      )}
    </div>
  )
}

function UnifiedEventStream({ events, filter, setFilter, onSelect, selectedEvent }) {
  return (
    <Card title="Live activity" subtitle="Existing event records from Linux, OpenStack and Behavioral sources">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap gap-2">
          {FILTERS.map((item) => (
            <button
              key={item}
              type="button"
              onClick={() => setFilter(item)}
              className={`rounded-full px-3 py-1.5 text-xs font-semibold ${filter === item ? 'bg-[#111111] text-white' : 'border border-[var(--panel-border)] bg-white muted-text'}`}
            >
              {item}
            </button>
          ))}
        </div>
        <span className="inline-flex items-center gap-2 text-xs font-semibold cyber-text">
          <StatusDot active />
          Active
        </span>
      </div>
      <div className="max-h-[420px] overflow-auto rounded-3xl border border-[var(--panel-border)]">
        {events.map((event, index) => {
          const id = eventId(event, index)
          const active = eventId(selectedEvent) === id
          const time = event.timestamp ? new Date(event.timestamp) : null
          const timeLabel = time && !Number.isNaN(time.getTime())
            ? time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
            : '-'
          return (
            <button
              key={id}
              type="button"
              onClick={() => onSelect(id)}
              className={`intel-feed-row flex w-full items-center gap-3 border-t border-[var(--panel-border)] px-4 py-2.5 text-left ${active ? 'bg-[#D8ECE6]' : 'bg-[var(--panel)] hover:bg-[var(--panel-strong)]'}`}
            >
              <span className="w-12 shrink-0 font-mono text-[11px] muted-text">{timeLabel}</span>
              <span className="w-[108px] shrink-0">{sourceBadge(event)}</span>
              <span className="min-w-0 flex-1 truncate text-sm font-semibold cyber-text">{event.event_type || '-'}</span>
              <span className="hidden min-w-0 max-w-[140px] truncate text-xs muted-text md:block">{actorOf(event)}</span>
              <SeverityBadge severity={event.severity || 'info'} />
              <span className="w-8 text-right text-xs font-semibold tabular-nums cyber-text">{riskOf(event)}</span>
            </button>
          )
        })}
      </div>
    </Card>
  )
}

function BehavioralAnalytics({ profiles, selectedIdentity, setSelectedIdentity, selectedProfile, selectedBehaviorEvent, selectedAnalysis, behavioralSummary, behavioralEvents }) {
  const observed = selectedAnalysis.observed_values || selectedBehaviorEvent || {}
  const deviations = selectedAnalysis.deviations || {}
  const identityEvents = (behavioralEvents || []).filter((event) => actorOf(event) === selectedIdentity || event.username === selectedIdentity)
  const normalExample = [...identityEvents].filter((event) => (event.behavioral_classification || event.original_label) === 'NORMAL').sort((a, b) => riskOf(a) - riskOf(b))[0]
  const suspiciousExample = [...identityEvents].filter((event) => riskOf(event) >= 50 || ['OVER_EFFICIENCY', 'AUTOMATED_ACTIVITY', 'SUSPICIOUS_BEHAVIOR'].includes(event.behavioral_classification || event.original_label)).sort((a, b) => riskOf(b) - riskOf(a))[0]
  const comparison = [
    ['Typing Speed', selectedProfile?.average_typing_speed, observed.typing_speed_cpm, deviations.typing_speed_deviation],
    ['Command Rate', selectedProfile?.average_command_rate, observed.command_rate_per_minute, deviations.command_rate_deviation],
    ['Error Rate', selectedProfile?.average_command_error_rate, observed.command_error_rate, deviations.error_rate_deviation],
    ['Idle Time', selectedProfile?.average_idle_time, observed.idle_time_seconds, deviations.idle_time_deviation],
    ['Repetition', selectedProfile?.average_repeated_command_ratio, observed.repeated_command_ratio, deviations.repetition_deviation],
    ['Session Duration', selectedProfile?.average_session_duration, observed.session_duration_minutes, deviations.session_duration_deviation],
  ]
  return (
    <Card title="Behavioral Analytics" subtitle="Baseline, current behavior, deviation, behavior risk and reasons">
      <div className="mb-4 grid gap-3 md:grid-cols-[260px_1fr]">
        <Select label="Identity" value={selectedIdentity} onChange={(event) => setSelectedIdentity(event.target.value)}>
          {profiles.map((profile) => (
            <option key={`${profile.identity_key}-${profile.server_id}`} value={profile.identity_key}>
              {profile.identity_key} / {profile.server_id || 'all servers'}
            </option>
          ))}
        </Select>
        <div className="grid gap-2 md:grid-cols-3">
          <MiniRow label="Behavior Risk" value={riskOf(selectedBehaviorEvent)} />
          <MiniRow label="Classification" value={selectedBehaviorEvent?.behavioral_classification || 'N/A'} />
          <MiniRow label="Profiles" value={behavioralSummary?.users_profiled ?? profiles.length} />
        </div>
      </div>
      <div className="mb-4 grid gap-2 md:grid-cols-3">
        <MiniRow label="Baseline status" value={selectedProfile?.status || 'No profile'} />
        <MiniRow label="Baseline samples" value={selectedProfile?.profile_sample_count ?? 0} />
        <MiniRow label="Origin" value={selectedBehaviorEvent?.data_origin || selectedProfile?.data_origin || 'research telemetry'} />
      </div>
      <div className="mb-4 grid gap-3 md:grid-cols-2">
        <div className="rounded-3xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-4">
          <p className="text-xs font-semibold uppercase tracking-wide muted-text">Normal behavior example</p>
          <p className="mt-2 text-sm font-semibold cyber-text">{normalExample ? `${actorOf(normalExample)} · risk ${riskOf(normalExample)}` : 'No NORMAL record for this identity yet'}</p>
          <p className="mt-1 text-xs muted-text">{normalExample?.behavioral_classification || 'Load the synthetic demo to populate this panel.'}</p>
        </div>
        <div className="rounded-3xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-4">
          <p className="text-xs font-semibold uppercase tracking-wide muted-text">Suspicious / over-efficiency example</p>
          <p className="mt-2 text-sm font-semibold cyber-text">{suspiciousExample ? `${actorOf(suspiciousExample)} · ${suspiciousExample.behavioral_classification || 'ANOMALY'} · risk ${riskOf(suspiciousExample)}` : 'No over-efficiency record for this identity yet'}</p>
          <p className="mt-1 text-xs muted-text">{(parseJson(suspiciousExample?.risk_reasons, []) || [])[0] || 'Detection reasons appear here after analysis.'}</p>
        </div>
      </div>
      <div className="grid gap-3 md:grid-cols-2">
        {comparison.map(([label, baseline, current, deviation]) => (
          <div key={label} className="rounded-3xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-4">
            <p className="text-xs font-semibold uppercase tracking-wide muted-text">{label}</p>
            <div className="mt-3 grid grid-cols-3 gap-2 text-sm">
              <div><p className="text-xs muted-text">Baseline</p><p className="font-semibold cyber-text">{formatNumber(baseline)}</p></div>
              <div><p className="text-xs muted-text">Current</p><p className="font-semibold cyber-text">{formatNumber(current)}</p></div>
              <div><p className="text-xs muted-text">Deviation</p><p className="font-semibold cyber-text">{formatNumber(deviation)}</p></div>
            </div>
          </div>
        ))}
      </div>
      <div className="mt-4 rounded-3xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-4">
        <p className="text-xs font-semibold uppercase tracking-wide muted-text">Reasons</p>
        <div className="mt-2 space-y-2">
          {(selectedAnalysis.reasons || parseJson(selectedBehaviorEvent?.risk_reasons, []) || []).map((reason) => (
            <p key={reason} className="rounded-2xl bg-[var(--panel)] p-3 text-sm cyber-text">{reason}</p>
          ))}
          {!(selectedAnalysis.reasons || parseJson(selectedBehaviorEvent?.risk_reasons, []) || []).length && <p className="text-sm muted-text">No behavioral reason text available for the selected identity.</p>}
        </div>
      </div>
    </Card>
  )
}

function CloudActivity({ cloudEvents, openStackStatus }) {
  const auth = cloudEvents.filter((event) => /auth|login|token|identity/i.test(`${event.event_type} ${event.message}`)).length
  const vm = cloudEvents.filter((event) => /vm|instance|server|compute/i.test(`${event.event_type} ${event.message} ${event.resource_type}`)).length
  const failures = cloudEvents.filter((event) => /fail|error|unauthor|forbidden|exception/i.test(`${event.event_type} ${event.message}`)).length
  const warnings = cloudEvents.filter((event) => ['warning', 'warn', 'medium'].includes((event.severity || '').toLowerCase())).length
  const errors = cloudEvents.filter((event) => ['error', 'critical', 'high'].includes((event.severity || '').toLowerCase())).length
  const normalExample = cloudEvents.find((event) => (event.severity || '').toLowerCase() === 'info')
  const highRiskExample = [...cloudEvents].sort((a, b) => riskOf(b) - riskOf(a)).find((event) => riskOf(event) >= 65 || ['high', 'critical'].includes((event.severity || '').toLowerCase()))
  const origin = cloudEvents[0]?.data_origin || openStackStatus?.summary?.most_recent_import?.dataset_version || 'OPENSTACK'
  return (
    <Card title="Cloud Activity" subtitle="OpenStack only. Origin metadata is shown per record. Azure is not used.">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <MiniRow label="Authentication" value={auth} />
        <MiniRow label="VM Activity" value={vm} />
        <MiniRow label="API Failures" value={failures} />
        <MiniRow label="Warnings" value={warnings} />
        <MiniRow label="Errors" value={errors} />
      </div>
      <div className="mt-4 grid gap-2 md:grid-cols-2">
        <MiniRow label="Provider" value="OPENSTACK" />
        <MiniRow label="Data origin" value={origin} />
        <MiniRow label="Normal example" value={normalExample ? `${normalExample.event_type} · ${actorOf(normalExample)}` : 'None loaded'} />
        <MiniRow label="High-risk example" value={highRiskExample ? `${highRiskExample.event_type} · risk ${riskOf(highRiskExample)}` : 'None loaded'} />
      </div>
      <div className="mt-4 max-h-80 overflow-auto space-y-2">
        {cloudEvents.slice(0, 12).map((event, index) => (
          <div key={eventId(event, index)} className="rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-3">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={event.severity || 'info'} />
              <span className="text-xs font-semibold cyber-text">{event.event_type}</span>
              {sourceBadge(event)}
            </div>
            <p className="mt-1 font-mono text-[11px] muted-text">{event.timestamp ? new Date(event.timestamp).toLocaleString() : '-'}</p>
            <p className="text-xs muted-text">Actor: {actorOf(event)} · {event.resource_type || event.resource_id || event.hostname || 'no resource'}</p>
            <p className="mt-2 line-clamp-2 text-sm muted-text">{event.message || event.raw_log}</p>
          </div>
        ))}
        {!cloudEvents.length && <p className="py-6 text-center text-sm muted-text">No OpenStack records loaded. Summary total: {openStackStatus?.summary?.total_openstack_events ?? 0}</p>}
      </div>
    </Card>
  )
}

function ThreatCorrelation({ correlations }) {
  return (
    <Card title="Threat Correlation" subtitle="Rule-based correlation derived from actor, source, time and risk evidence">
      <div className="space-y-3">
        {correlations.map((incident) => (
          <div key={incident.id} className="rounded-3xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <p className="text-sm font-semibold cyber-text">{incident.actor}</p>
                <p className="text-xs muted-text">{incident.sources.join(' + ')} - {incident.relatedEvents.length} related records</p>
              </div>
              <Badge variant={incident.score >= 85 ? 'critical' : incident.score >= 70 ? 'high' : 'medium'}>{incident.confidence}% confidence</Badge>
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              {incident.evidence.map((item) => <Badge key={item} variant="info">{item}</Badge>)}
            </div>
          </div>
        ))}
        {!correlations.length && <p className="py-8 text-center text-sm muted-text">No multi-evidence correlations found in the currently loaded records.</p>}
      </div>
    </Card>
  )
}

function ThreatInvestigation({ selectedEvent, relatedEvents, selectedCorrelation, selectedBehaviorEvent, recommendation }) {
  return (
    <Card title="Threat Investigation" subtitle="Select a row in Unified Event Stream to inspect related evidence">
      <div className="grid gap-3 md:grid-cols-2">
        <MiniRow label="Selected Source" value={selectedEvent ? sourceOf(selectedEvent) : '-'} />
        <MiniRow label="Actor" value={selectedEvent ? actorOf(selectedEvent) : '-'} />
        <MiniRow label="Risk" value={selectedEvent ? riskOf(selectedEvent) : '-'} />
        <MiniRow label="Recommendation" value={recommendation.level} />
      </div>
      <div className="mt-4 rounded-3xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-4">
        <p className="text-xs font-semibold uppercase tracking-wide muted-text">Evidence</p>
        <div className="mt-2 flex flex-wrap gap-2">
          {(selectedCorrelation?.evidence || []).map((item) => <Badge key={item} variant="medium">{item}</Badge>)}
          {!selectedCorrelation?.evidence?.length && <span className="text-sm muted-text">No correlated evidence found for this actor yet.</span>}
        </div>
      </div>
      <EvidenceTimeline events={relatedEvents} recommendation={recommendation} />
      <div className="mt-4 grid gap-2 md:grid-cols-2">
        <MiniRow label="Behavior" value={selectedBehaviorEvent?.behavioral_classification || 'No linked behavior record'} />
        <MiniRow label="Cloud Activity" value={(selectedCorrelation?.sources || []).includes('OpenStack') ? 'Related OpenStack evidence' : 'No linked OpenStack evidence'} />
      </div>
    </Card>
  )
}

function RiskAnalysis({ breakdown, trend }) {
  const chartData = [
    { name: 'Behavior', value: breakdown.behaviorRisk },
    { name: 'Cloud', value: breakdown.cloudSeverity },
    { name: 'Correlation', value: breakdown.correlationScore },
  ]
  return (
    <Card title="Risk Analysis" subtitle="Overall risk combines behavior risk, cloud severity and correlation score">
      <div className="grid gap-4 lg:grid-cols-[160px_1fr]">
        <RiskWidget score={breakdown.overall} label="Overall Risk" size="lg" />
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={trend}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--panel-border)" />
              <XAxis dataKey="label" tick={{ fontSize: 10 }} />
              <YAxis tick={{ fontSize: 11 }} />
              <Tooltip {...TOOLTIP} />
              <Area type="monotone" dataKey="risk" stroke="#9F5F68" fill="#9F5F68" fillOpacity={0.18} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
      <div className="mt-4 h-56">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--panel-border)" />
            <XAxis dataKey="name" tick={{ fontSize: 11 }} />
            <YAxis tick={{ fontSize: 11 }} />
            <Tooltip {...TOOLTIP} />
            <Bar dataKey="value" fill="#B89B5E" radius={[8, 8, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Card>
  )
}

function SecurityRecommendation({ recommendation, selectedCorrelation, selectedEvent, alerts }) {
  return (
    <Card title="Security Recommendation" subtitle="Analyst guidance only; no adaptive enforcement is executed">
      <div className="rounded-3xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-5">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant={recommendation.level === 'Critical' ? 'critical' : recommendation.level === 'High' ? 'high' : recommendation.level === 'Medium' ? 'medium' : 'info'}>
            {recommendation.level}
          </Badge>
          <span className="text-xs muted-text">{alerts.length} alert record(s) loaded</span>
        </div>
        <p className="mt-4 text-xl font-bold cyber-text">{recommendation.action}</p>
        <p className="mt-3 text-sm muted-text">{recommendation.reason}</p>
      </div>
      <div className="mt-4 grid gap-2 md:grid-cols-2">
        <MiniRow label="Selected Event" value={selectedEvent?.event_type || '-'} />
        <MiniRow label="Actor" value={selectedEvent ? actorOf(selectedEvent) : '-'} />
        <MiniRow label="Correlation Confidence" value={selectedCorrelation ? `${selectedCorrelation.confidence}%` : 'No correlation'} />
        <MiniRow label="Related Evidence" value={selectedCorrelation?.evidence?.length || 0} />
      </div>
      <AlertBanner type="info" message="Recommendations are generated from existing risk levels and correlated evidence. This page does not block accounts, terminate SSH sessions, isolate cloud resources, or modify firewall rules." />
    </Card>
  )
}

function formatNumber(value) {
  if (value === null || value === undefined || value === '') return '-'
  const number = Number(value)
  if (Number.isNaN(number)) return value
  return Math.round(number * 100) / 100
}

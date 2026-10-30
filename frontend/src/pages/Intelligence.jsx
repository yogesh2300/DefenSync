import { useCallback, useEffect, useMemo, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { Link } from 'react-router-dom'
import {
  getAccountList,
  getAlerts,
  getAccountSummary,
  getDashboardSummary,
  getEvents,
  getHighRiskEvents,
  getOpenStackDatasetStatus,
  getServers,
  getIncidents,
  getN8nStatus,
  loadOpenStackDemo,
  exportInvestigation,
  runCorrelation,
} from '../api/client'
import DetectionPanel from '../components/intelligence/DetectionPanel'
import { useAuth } from '../context/AuthContext'
import { useEnvironment } from '../context/EnvironmentContext'
import { useSelectedServer } from '../context/SelectedServerContext'
import { CLOUD, LINUX } from '../environment'
import {
  actorOf,
  environmentOf,
  eventTime,
  eventRiskFractionClass,
  formatEventRisk,
  formatEventRiskFraction,
  mergeCorrelations,
  riskOf,
  sourceOf,
  stableEventId,
} from '../intelligence/investigation'
import {
  PRIMARY_SCORE_LABEL,
  accountIdForSummaryRequest,
  primaryScoreSeverity,
  resolvePrimarySecurityScore,
} from '../intelligence/primaryScore'
import AlertBanner from '../components/ui/AlertBanner'
import Badge, { SeverityBadge } from '../components/ui/Badge'
import Button from '../components/ui/Button'
import Card from '../components/ui/Card'
import './Intelligence.css'

const RISK_FILTERS = ['Normal', 'Anomalous', 'High Risk', 'Critical']

// What each workspace shows. Sources match sourceOf(); nothing from the other environment is loaded.
const ENV_VIEW = {
  [LINUX]: {
    title: 'Linux Threat Intelligence',
    sources: ['Linux'],
    streamSubtitle: 'Private LIVE_LINUX events for the selected account and server scope',
    correlationSubtitle: 'Private Linux activity correlated from loaded account telemetry.',
    accountSubtitle: 'Private Linux telemetry for this account (environment=LINUX). Counts use database aggregation, not the event list length.',
    note: 'Detection readiness and predictions come from eligible LIVE_LINUX security events. Snapshots and collector SSH logins are excluded from the ML baseline.',
    safety: 'Recommendations are generated from existing risk levels and correlated evidence. This page does not block accounts, terminate SSH sessions, or modify firewall rules.',
  },
  [CLOUD]: {
    title: 'Cloud Threat Intelligence',
    sources: ['Azure'],
    streamSubtitle: 'Private cloud events for connected Azure accounts',
    correlationSubtitle: 'Private cloud activity linked to correlated evidence from loaded records.',
    accountSubtitle: 'Private cloud telemetry for this account (environment=CLOUD). Counts use database aggregation, not the event list length.',
    note: 'Azure telemetry is collected read-only from the Log Analytics workspaces connected as cloud sources.',
    safety: 'Recommendations are generated from existing risk levels and correlated evidence. This page does not disable identities, isolate cloud resources, or change cloud configuration.',
  },
}

function normalizeRows(value) {
  if (Array.isArray(value)) return value
  if (Array.isArray(value?.items)) return value.items
  return []
}

const ENVIRONMENT_LABELS = { LINUX: 'Linux', CLOUD: 'Cloud', HPC: 'HPC', BEHAVIORAL: 'Behavioral', MIXED_LEGACY: 'Mixed (legacy)', UNKNOWN: 'Unknown' }
const CLOUD_SIGN_IN_TYPES = new Set(['CLOUD_LOGIN_SUCCESS', 'CLOUD_LOGIN_FAILURE', 'CLOUD_AUTHENTICATION'])

function labelOf(event) {
  return event?.behavioral_classification || event?.original_label || event?.classification || event?.severity || 'UNLABELLED'
}

function eventId(event) {
  return stableEventId(event)
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

function recommendationFor(score, evidence = []) {
  if (score >= 85) {
    return {
      level: 'Critical',
      action: 'Escalate immediately, require identity verification, review related activity for this identity, and prepare containment approval.',
      reason: 'Overall risk is critical based on event risk, behavioral signals, and correlated evidence.',
    }
  }
  if (score >= 70) {
    return {
      level: 'High',
      action: 'Prioritize analyst review and validate the identity, session, and affected asset involved.',
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

function environmentEvidence(environment, sorted) {
  const text = (event) => `${event.event_type} ${event.message}`
  if (environment === 'LINUX') {
    return [
      sorted.some((event) => /login|ssh|auth/i.test(text(event))) && 'Linux login/authentication activity',
      sorted.some((event) => /sudo|privilege|root|escalat|admin/i.test(text(event))) && 'Privilege-related Linux activity',
    ]
  }
  if (environment === 'CLOUD') {
    const types = new Set(sorted.map((event) => String(event.event_type || '').toUpperCase()))
    return [
      [...types].some((type) => CLOUD_SIGN_IN_TYPES.has(type)) && 'Cloud sign-in/authentication activity',
      types.has('CLOUD_PRIVILEGE_CHANGE') && 'Cloud privilege/role change',
      types.has('CLOUD_RESOURCE_OPERATION') && 'Cloud resource operation',
    ]
  }
  if (environment === 'HPC') return ['HPC/BGL operational log activity']
  if (environment === 'BEHAVIORAL') return [sorted.some((event) => riskOf(event) >= 50) && 'Behavioral anomaly or over-efficiency']
  return []
}

// Correlation never crosses environments: groups are keyed by (environment, actor).
function computeCorrelation(events) {
  const groups = new Map()
  events.forEach((event) => {
    const actor = actorOf(event)
    const environment = environmentOf(event)
    if (!actor || actor === 'unknown' || environment === 'UNKNOWN') return
    const key = `${environment}|${actor}`
    if (!groups.has(key)) groups.set(key, { actor, environment, rows: [] })
    groups.get(key).rows.push(event)
  })

  const incidents = []
  groups.forEach(({ actor, environment, rows }) => {
    const sorted = [...rows].sort((a, b) => eventTime(a) - eventTime(b))
    const highRisk = sorted.filter((event) => riskOf(event) >= 70 || ['critical', 'high', 'error'].includes((event.severity || '').toLowerCase()))
    const evidence = [
      ...environmentEvidence(environment, sorted),
      highRisk.length > 0 && `${highRisk.length} high-risk record(s)`,
    ].filter(Boolean)
    if (evidence.length < 2) return
    const confidence = Math.min(100, Math.round((evidence.length / 5) * 80 + Math.min(highRisk.length, 4) * 5))
    const maxRisk = Math.max(...sorted.map(riskOf), 0)
    const lastEvent = sorted[sorted.length - 1]
    incidents.push({
      id: `${environment}-${actor}-${eventTime(lastEvent)}`,
      actor,
      environment,
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

function SecurityPosture({ primaryScore, environment, incidents, sources }) {
  const available = primaryScore?.available
  const score = available ? primaryScore.score : 0
  const level = available ? primaryScoreSeverity(score) : { label: 'Unavailable', variant: 'info' }
  const radius = 54
  const circ = 2 * Math.PI * radius
  const offset = available ? circ - (Math.min(100, Math.max(0, score)) / 100) * circ : circ
  return (
    <Card className="intel-enter h-full">
      <div data-primary-security-score>
      <p className="text-[11px] font-semibold uppercase tracking-wide muted-text">{PRIMARY_SCORE_LABEL}</p>
      <p className="mt-1 text-xs muted-text">Same average event-risk score as the Dashboard Security Pulse for this account, environment, and server scope.</p>
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
            {available ? (
              <CountUp value={score} className="text-4xl font-bold tabular-nums cyber-text" />
            ) : (
              <span className="px-2 text-center text-sm font-bold leading-tight cyber-text">Unavailable</span>
            )}
            <Badge variant={level.variant}>{level.label}</Badge>
          </div>
        </div>
        <div className="w-full space-y-2">
          {!available && <p className="text-sm muted-text" data-primary-score-unavailable>{primaryScore?.reason}</p>}
          {available && <p className="text-xs muted-text">{primaryScore.explanation}</p>}
          <MiniRow label={`Correlated ${ENVIRONMENT_LABELS[environment] || 'Unknown'} incidents`} value={incidents} />
          <div className={`grid gap-2 text-center ${sources.length > 1 ? 'grid-cols-2 sm:grid-cols-3' : 'grid-cols-1'}`}>
            {sources.map((source) => (
              <div key={source.label} className="rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] px-2 py-2">
                <div className="flex items-center justify-center gap-1 text-[11px] muted-text"><StatusDot active={source.active} /> {source.label}</div>
                <p className="mt-1 text-xs font-semibold cyber-text">{source.active ? 'Available' : 'None loaded'}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
      </div>
    </Card>
  )
}

function IntelligenceFlow({ sources }) {
  return (
    <Card className="intel-enter intel-enter-delay-1 h-full">
      <p className="text-[11px] font-semibold uppercase tracking-wide muted-text">Intelligence Flow</p>
      <p className="mt-1 text-sm muted-text">Evidence sources feed correlation. Source counts are operational totals, not competing security scores.</p>
      <div className="mt-4 space-y-3">
        {sources.map(({ label, count }, index) => (
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
        <span className="text-xs muted-text">Feeds investigation confidence</span>
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
          <p className="mt-1 text-sm muted-text">{ENVIRONMENT_LABELS[incident.environment] || 'Unknown'} finding · {incident.sources.join(' → ')}</p>
        </div>
        <div className="text-right">
          <p className="text-3xl font-bold tabular-nums cyber-text" data-investigation-confidence>{incident.confidence}%</p>
          <p className="text-xs muted-text">Investigation confidence</p>
          <p className="mt-1 text-[11px] muted-text">Finding score {incident.score} (not the account/system risk)</p>
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
          <div key={`${eventId(event)}-${index}`} className="intel-timeline-item flex gap-3" style={{ animationDelay: `${index * 60}ms` }}>
            <div className="flex w-4 flex-col items-center">
              <span className="mt-1 h-2.5 w-2.5 rounded-full bg-[#6EA779]" />
              <span className="mt-1 w-px flex-1 bg-[var(--panel-border)]" />
            </div>
            <div className="pb-4">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-[11px] muted-text">{event.timestamp ? new Date(event.timestamp).toLocaleString() : '-'}</span>
                {sourceBadge(event)}
                <SeverityBadge severity={event.severity || 'info'} />
                <span className={eventRiskFractionClass(event)} data-event-risk-score title="Individual event risk score">
                  {formatEventRiskFraction(event)}
                </span>
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

function SourceCards({ sources }) {
  const cols = sources.length >= 3 ? 'md:grid-cols-3' : sources.length === 2 ? 'md:grid-cols-2' : ''
  return (
    <div className={`grid gap-3 ${cols}`}>
      {sources.map((card, index) => (
        <div key={card.label} data-intel-source={card.label} className={`intel-source-card intel-enter intel-enter-delay-${index + 1} rounded-3xl border border-[var(--panel-border)] bg-[var(--panel)] p-4`}>
          <div className="flex items-center justify-between">
            <p className="text-sm font-semibold cyber-text">{card.label}</p>
            <StatusDot active={card.count > 0} />
          </div>
          <p className="mt-2 text-2xl font-bold tabular-nums cyber-text"><CountUp value={card.count} /></p>
          <p className="mt-1 text-xs muted-text">{card.status || (card.count > 0 ? 'Available' : 'None loaded')}</p>
        </div>
      ))}
    </div>
  )
}

function OperationalSnapshot({ items }) {
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
  const { environment } = useEnvironment()
  const { selectedServerId, selectedServer, isAllServers } = useSelectedServer()
  const { isAdmin } = useAuth()
  const isLinux = environment !== CLOUD
  const view = ENV_VIEW[isLinux ? LINUX : CLOUD]
  const [events, setEvents] = useState([])
  const [openStackStatus, setOpenStackStatus] = useState(null)
  const [alerts, setAlerts] = useState([])
  const [servers, setServers] = useState([])
  const [highRiskEvents, setHighRiskEvents] = useState([])
  const [loading, setLoading] = useState(true)
  const [errors, setErrors] = useState([])
  const [filter, setFilter] = useState('All')
  const [selectedEventId, setSelectedEventId] = useState('')
  const [demoMessage, setDemoMessage] = useState('')
  const [demoError, setDemoError] = useState('')
  const [cloudDemoLoading, setCloudDemoLoading] = useState(false)
  const [backendIncidents, setBackendIncidents] = useState([])
  const [dashboardSummary, setDashboardSummary] = useState(null)
  const [accountSummary, setAccountSummary] = useState(null)
  const [summariesLoaded, setSummariesLoaded] = useState(false)
  const [highRiskTotal, setHighRiskTotal] = useState(0)
  const [n8nStatus, setN8nStatus] = useState(null)
  const [correlating, setCorrelating] = useState(false)
  const [adminAccountId, setAdminAccountId] = useState('')
  const [accountOptions, setAccountOptions] = useState([])

  useEffect(() => {
    getN8nStatus().then(setN8nStatus).catch(() => setN8nStatus(null))
  }, [])

  useEffect(() => {
    if (!isAdmin) {
      setAccountOptions([])
      setAdminAccountId('')
      return undefined
    }
    let cancelled = false
    getAccountList()
      .then((listed) => {
        if (!cancelled) setAccountOptions(listed?.accounts || [])
      })
      .catch(() => {
        if (!cancelled) setAccountOptions([])
      })
    return () => { cancelled = true }
  }, [isAdmin])

  const load = useCallback(async () => {
    setLoading(true)
    setSummariesLoaded(false)
    const nextErrors = []
    const skipped = Promise.resolve(null)
    const linuxOnly = (request) => (isLinux ? request() : skipped)
    const cloudOnly = (request) => (isLinux ? skipped : request())
    const serverId = isLinux ? (selectedServerId || null) : null
    const summaryAccountId = accountIdForSummaryRequest({ isAdmin, selectedAccountId: adminAccountId })
    const [allEvents, cloudEvents, hdfsEvents, highRisk, osStatus, alertRows, serverRows, dashRow, accountRow] = await Promise.allSettled([
      getEvents({ limit: 200, sort_order: 'newest', scope: 'private', environment }),
      cloudOnly(() => getEvents({ limit: 200, source_type: 'CLOUD', provider: 'OPENSTACK', sort_order: 'newest', scope: 'global' })),
      cloudOnly(() => getEvents({ limit: 200, source_type: 'CLOUD', provider: 'HDFS', sort_order: 'newest', scope: 'global' })),
      getHighRiskEvents(100, serverId, environment),
      cloudOnly(getOpenStackDatasetStatus),
      getAlerts({ limit: 100, environment }),
      linuxOnly(() => getServers(false)),
      getDashboardSummary(serverId, environment),
      getAccountSummary(serverId, summaryAccountId, environment),
    ])

    const merged = []
    const seen = new Set()
    const addRows = (rows) => {
      normalizeRows(rows).forEach((event, index) => {
        const id = eventId(event) || `row-${merged.length}-${index}`
        if (seen.has(id)) return
        seen.add(id)
        merged.push(event)
      })
    }

    if (allEvents.status === 'fulfilled') addRows(allEvents.value)
    else nextErrors.push(`Events API unavailable: ${allEvents.reason?.message || 'failed to load events'}`)
    if (cloudEvents.status === 'fulfilled') addRows(cloudEvents.value)
    else if (!isLinux) nextErrors.push(`OpenStack event filter unavailable: ${cloudEvents.reason?.message || 'failed to load OpenStack records'}`)
    if (hdfsEvents.status === 'fulfilled') addRows(hdfsEvents.value)

    setEvents(merged.sort((a, b) => eventTime(b) - eventTime(a)))

    if (highRisk.status === 'fulfilled') {
      setHighRiskEvents(normalizeRows(highRisk.value?.items || highRisk.value))
      setHighRiskTotal(Number(highRisk.value?.total ?? normalizeRows(highRisk.value).length))
    }
    else nextErrors.push(`High-risk event API unavailable: ${highRisk.reason?.message || 'failed to load high-risk records'}`)
    if (osStatus.status === 'fulfilled') setOpenStackStatus(osStatus.value)
    else if (!isLinux) nextErrors.push(`OpenStack summary unavailable: ${osStatus.reason?.message || 'failed to load OpenStack summary'}`)
    if (alertRows.status === 'fulfilled') setAlerts(normalizeRows(alertRows.value))
    else nextErrors.push(`Alerts API unavailable: ${alertRows.reason?.message || 'failed to load alerts'}`)
    if (serverRows.status === 'fulfilled') setServers(normalizeRows(serverRows.value))
    else if (isLinux) nextErrors.push(`Servers API unavailable: ${serverRows.reason?.message || 'failed to load servers'}`)
    if (dashRow.status === 'fulfilled') setDashboardSummary(dashRow.value)
    else {
      setDashboardSummary(null)
      nextErrors.push(`Dashboard risk summary unavailable: ${dashRow.reason?.message || 'failed to load average risk'}`)
    }
    if (accountRow.status === 'fulfilled') setAccountSummary(accountRow.value)
    else setAccountSummary(null)
    setSummariesLoaded(true)

    try {
      const incidents = await getIncidents(12, environment)
      setBackendIncidents(Array.isArray(incidents) ? incidents : incidents?.incidents || [])
    } catch {
      setBackendIncidents([])
    }

    setErrors(nextErrors)
    setLoading(false)
  }, [adminAccountId, environment, isAdmin, isLinux, selectedServerId])

  useEffect(() => {
    setFilter('All')
    setSelectedEventId('')
  }, [environment])

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

  const handleCorrelate = useCallback(async () => {
    setCorrelating(true)
    setDemoError('')
    setDemoMessage('')
    try {
      const result = await runCorrelation()
      setDemoMessage(`Correlation complete: ${result.count ?? 0} incident(s) stored or updated from collected telemetry.`)
      await load()
    } catch (err) {
      setDemoError(err.response?.data?.error || err.response?.data?.detail || err.message || 'Correlation failed.')
    } finally {
      setCorrelating(false)
    }
  }, [load])

  const handleExport = useCallback(async () => {
    try {
      const payload = await exportInvestigation('json')
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `defensync-investigation-${new Date().toISOString().slice(0, 10)}.json`
      link.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      setDemoError(err.response?.data?.error || err.message || 'Export failed.')
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const sourceCounts = useMemo(() => {
    const counts = { Linux: 0, OpenStack: 0, Azure: 0, HDFS: 0, BGL: 0, Behavioral: 0, Unknown: 0 }
    events.forEach((event) => { counts[sourceOf(event)] += 1 })
    return counts
  }, [events])

  const localCorrelations = useMemo(() => computeCorrelation(events), [events])
  const correlations = useMemo(
    () => mergeCorrelations(backendIncidents, localCorrelations, events),
    [backendIncidents, events, localCorrelations],
  )

  const filteredEvents = useMemo(() => events.filter((event) => {
    const source = sourceOf(event)
    const label = labelOf(event).toString().toUpperCase()
    const risk = riskOf(event)
    if (view.sources.includes(filter)) return source === filter
    if (filter === 'Normal') return risk < 30 || label === 'NORMAL'
    if (filter === 'Anomalous') return risk >= 50 || !['NORMAL', 'INFO', 'LOW'].includes(label)
    if (filter === 'High Risk') return risk >= 70
    if (filter === 'Critical') return risk >= 85 || (event.severity || '').toLowerCase() === 'critical'
    return true
  }).slice(0, 150), [events, filter, view])

  const selectedEvent = useMemo(() => (
    events.find((event) => eventId(event) === selectedEventId)
    || correlations[0]?.latestEvent
    || highRiskEvents[0]
    || events[0]
  ), [correlations, events, highRiskEvents, selectedEventId])

  useEffect(() => {
    if (selectedEventId) return
    const fallback = correlations[0]?.latestEvent || highRiskEvents[0] || events[0]
    if (fallback) setSelectedEventId(eventId(fallback))
  }, [correlations, events, highRiskEvents, selectedEventId])

  const relatedEvents = useMemo(() => relatedEventsFor(selectedEvent, events), [events, selectedEvent])
  const findingEnvironment = environmentOf(selectedEvent)
  const selectedCorrelation = useMemo(() => {
    if (!selectedEvent) return null
    const selectedId = eventId(selectedEvent)
    const byEvidence = correlations.find((item) => (
      (item.relatedEvents || []).some((event) => eventId(event) === selectedId)
      || (item.event_ids || []).includes(selectedId)
    ))
    if (byEvidence) return byEvidence
    const actor = actorOf(selectedEvent)
    return correlations.find((item) => (
      item.actor === actor
      && (item.environment === findingEnvironment || item.environment === 'MIXED_LEGACY')
    )) || null
  }, [correlations, selectedEvent, findingEnvironment])

  const overview = useMemo(() => {
    const uniqueUsers = new Set(events.map(actorOf).filter((actor) => actor && actor !== 'unknown')).size
    return {
      privateEvents: accountSummary?.events ?? (isLinux ? sourceCounts.Linux : sourceCounts.Azure),
      failedLogins: accountSummary?.failed_logins ?? 0,
      cloudEvents: openStackStatus?.summary?.public_openstack_events ?? sourceCounts.OpenStack,
      hdfsEvents: sourceCounts.HDFS,
      highRiskEvents: accountSummary?.high_risk_events ?? highRiskTotal,
      anomalies: accountSummary?.anomalies ?? 0,
      criticalEvents: events.filter((event) => riskOf(event) >= 85 || (event.severity || '').toLowerCase() === 'critical').length,
      activeUsers: accountSummary?.users ?? uniqueUsers,
      servers: accountSummary?.servers ?? servers.length,
      accountName: accountSummary?.account_name || 'My account',
    }
  }, [accountSummary, events, highRiskTotal, isLinux, openStackStatus, servers.length, sourceCounts])

  const primaryScore = useMemo(
    () => resolvePrimarySecurityScore({
      summary: dashboardSummary,
      accountSummary,
      loaded: summariesLoaded,
      selectedAccountId: adminAccountId,
      isAdmin,
      expectedEnvironment: environment,
    }),
    [accountSummary, adminAccountId, dashboardSummary, environment, isAdmin, summariesLoaded],
  )

  // Finding-level signals for investigation only — never used as the primary security score.
  const findingSignals = useMemo(() => {
    const correlationScore = selectedCorrelation?.score
    const eventRisk = formatEventRisk(selectedEvent)
    const selectedFindingRisk = selectedCorrelation && correlationScore != null
      ? Math.round(Number(correlationScore) || 0)
      : eventRisk
    return {
      environment: findingEnvironment,
      correlationScore: correlationScore ?? 0,
      selectedFindingRisk,
      confidence: selectedCorrelation?.confidence ?? null,
    }
  }, [findingEnvironment, selectedCorrelation, selectedEvent])

  const recommendation = recommendationFor(
    primaryScore.available ? primaryScore.score : (findingSignals.selectedFindingRisk || 0),
    selectedCorrelation?.evidence || [],
  )
  const leadIncident = correlations[0] || null
  const investigationRecommendation = recommendationFor(leadIncident?.score || 0, leadIncident?.evidence || [])
  const sources = isLinux
    ? [
      { label: 'Linux', count: overview.privateEvents, active: sourceCounts.Linux > 0 || overview.privateEvents > 0 },
    ]
    : [
      { label: 'Cloud account', count: overview.privateEvents, active: overview.privateEvents > 0 || sourceCounts.Azure > 0 },
    ]
  const snapshotItems = isLinux
    ? [
      ['Linux events', overview.privateEvents],
      ['High risk', overview.highRiskEvents],
      ['Anomalies', overview.anomalies],
      ['Users', overview.activeUsers],
      ['Servers', overview.servers],
    ]
    : [
      ['Cloud events', overview.privateEvents],
      ['High risk', overview.highRiskEvents],
      ['Anomalies', overview.anomalies],
      ['Identities', overview.activeUsers],
      ['Failed sign-ins', overview.failedLogins],
    ]
  const streamFilters = ['All', ...view.sources, ...RISK_FILTERS]

  return (
    <div className="page-shell" data-intelligence-environment={isLinux ? LINUX : CLOUD}>
      <header className="intel-enter flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.18em] muted-text">{view.title}</p>
          <h1 className="mt-1 text-3xl font-bold tracking-tight cyber-text">DefenSync Intelligence</h1>
          <div className="mt-3 flex flex-wrap gap-2">
            {sources.map((source) => (
              <span key={source.label} className="inline-flex items-center gap-2 rounded-full border border-[var(--panel-border)] bg-white px-3 py-1 text-xs font-semibold cyber-text">
                <StatusDot active={source.active} />
                {source.label}
              </span>
            ))}
          </div>
          <p className="mt-3 text-sm muted-text">Security overview, detection controls, live activity, and investigation evidence for the selected workspace.</p>
          {isAdmin && accountOptions.length > 0 && (
            <label className="mt-3 block text-xs font-semibold muted-text">
              Account scope
              <select
                className="mt-1 w-full max-w-md rounded-full border border-[var(--panel-border)] bg-white px-3 py-2 text-sm font-semibold cyber-text"
                value={adminAccountId}
                onChange={(event) => setAdminAccountId(event.target.value)}
                data-admin-account-scope
              >
                <option value="">Platform overview</option>
                {accountOptions.map((account) => (
                  <option key={account.id} value={account.id}>{account.name} — {account.linux_events} Linux</option>
                ))}
              </select>
            </label>
          )}
        </div>
        <details className="rounded-3xl border border-[var(--panel-border)] bg-[var(--panel)] px-4 py-3 xl:min-w-[280px]">
          <summary className="cursor-pointer text-sm font-semibold cyber-text">Data sources / actions</summary>
          <div className="mt-3 space-y-2">
            {!isLinux && (
              <Button variant="secondary" className="w-full" onClick={handleLoadOpenStackDemo} disabled={cloudDemoLoading || loading}>
                {cloudDemoLoading ? 'Loading OpenStack...' : 'Load OpenStack Demo Data'}
              </Button>
            )}
            <Button variant="secondary" className="w-full" onClick={handleCorrelate} disabled={correlating || loading}>
              {correlating ? 'Correlating...' : 'Run correlation'}
            </Button>
            <Button variant="secondary" className="w-full" onClick={handleExport} disabled={loading}>
              Export investigation JSON
            </Button>
            <Link to="/ml-demo" className="flex w-full items-center justify-center rounded-full border border-[#DADDD8] bg-white px-4 py-2 text-sm font-semibold text-[#111111] hover:bg-[#F2F3F1]">
              ML demonstrations (OpenStack IF / synthetic RF)
            </Link>
            {n8nStatus && (
              <p className="text-[11px] leading-5 muted-text" data-n8n-configured={n8nStatus.configured ? 'true' : 'false'}>
                n8n (HIGH/CRITICAL incidents + every 2nd successful Linux/Cloud collection):{' '}
                <span className="font-semibold cyber-text">{n8nStatus.configured ? 'Configured' : 'Not configured'}</span>
              </p>
            )}
            <Button className="w-full" onClick={load} disabled={loading || cloudDemoLoading}><RefreshCw className="h-4 w-4" /> Refresh</Button>
            <p className="text-[11px] leading-5 muted-text">{view.note}</p>
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
          <DetectionPanel
            isLinux={isLinux}
            selectedServerId={selectedServerId}
            selectedServer={selectedServer}
            isAllServers={isAllServers}
          />
          <section className="grid gap-4">
            <Card title={`MY ACCOUNT${overview.accountName ? ` — ${overview.accountName}` : ''}`} subtitle={view.accountSubtitle}>
              <OperationalSnapshot items={snapshotItems} />
              <p className="mt-2 text-[11px] muted-text">
                Primary {PRIMARY_SCORE_LABEL.toLowerCase()} is shown once above detection status. Event, alert, and anomaly counts here are operational totals — not competing risk scores. Anomaly counts are windowed stored detections, not a full population census.
              </p>
            </Card>
            {isLinux && (
              <Card title="MY SERVERS" subtitle="Linux hosts registered to this account">
                <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                  {servers.map((server) => (
                    <div key={server.id} className="rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] px-3 py-2">
                      <p className="text-sm font-semibold cyber-text">{server.server_name}</p>
                      <p className="text-[11px] muted-text">{server.health_status || server.status || 'unknown'}</p>
                    </div>
                  ))}
                  {!servers.length && <p className="text-sm muted-text">No servers registered to this account.</p>}
                </div>
              </Card>
            )}
          </section>
          <section className="grid gap-4 lg:grid-cols-2 2xl:grid-cols-3">
            <SecurityPosture
              primaryScore={primaryScore}
              environment={environment}
              incidents={correlations.filter((item) => item.environment === (isLinux ? 'LINUX' : 'CLOUD')).length}
              sources={sources}
            />
            <IntelligenceFlow sources={sources} />
            <ActiveInvestigation
              incident={leadIncident}
              recommendation={investigationRecommendation}
              classification={null}
            />
          </section>

          <SourceCards sources={sources} />

          <UnifiedEventStream
            events={filteredEvents}
            filters={streamFilters}
            subtitle={view.streamSubtitle}
            filter={filter}
            setFilter={setFilter}
            onSelect={setSelectedEventId}
            selectedEvent={selectedEvent}
          />
          <section className="grid gap-4 xl:grid-cols-2">
            <Card title="CORRELATED THREATS" subtitle={view.correlationSubtitle}>
              <ThreatCorrelation correlations={correlations} />
            </Card>
            <ThreatInvestigation
              isLinux={isLinux}
              selectedEvent={selectedEvent}
              relatedEvents={relatedEvents}
              selectedCorrelation={selectedCorrelation}
              recommendation={recommendation}
            />
          </section>
          <section className="grid gap-4">
            <SecurityRecommendation safety={view.safety} recommendation={recommendation} selectedCorrelation={selectedCorrelation} selectedEvent={selectedEvent} alerts={alerts} primaryScore={primaryScore} />
          </section>
        </>
      )}
    </div>
  )
}

function UnifiedEventStream({ events, filters, subtitle, filter, setFilter, onSelect, selectedEvent }) {
  return (
    <Card title="Live activity" subtitle={subtitle}>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap gap-2">
          {filters.map((item) => (
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
          const id = eventId(event) || `feed-${index}`
          const active = selectedEvent ? eventId(selectedEvent) === eventId(event) : false
          const time = event.timestamp ? new Date(event.timestamp) : null
          const timeLabel = time && !Number.isNaN(time.getTime())
            ? time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
            : '-'
          return (
            <button
              key={id}
              type="button"
              onClick={() => onSelect(eventId(event))}
              className={`intel-feed-row flex w-full items-center gap-3 border-t border-[var(--panel-border)] px-4 py-2.5 text-left ${active ? 'bg-[#D8ECE6]' : 'bg-[var(--panel)] hover:bg-[var(--panel-strong)]'}`}
            >
              <span className="w-12 shrink-0 font-mono text-[11px] muted-text">{timeLabel}</span>
              <span className="w-[108px] shrink-0">{sourceBadge(event)}</span>
              <span className="min-w-0 flex-1 truncate text-sm font-semibold cyber-text">{event.event_type || '-'}</span>
              <span className="hidden min-w-0 max-w-[140px] truncate text-xs muted-text md:block">{actorOf(event)}</span>
              <SeverityBadge severity={event.severity || 'info'} />
              <span className="w-8 text-right text-xs font-semibold tabular-nums cyber-text">{formatEventRisk(event)}</span>
            </button>
          )
        })}
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
                <p className="text-xs muted-text">{ENVIRONMENT_LABELS[incident.environment] || 'Unknown'} finding · {incident.sources.join(' + ')} - {incident.relatedEvents.length} related records</p>
              </div>
              <Badge variant={incident.score >= 85 ? 'critical' : incident.score >= 70 ? 'high' : 'medium'}>{incident.confidence}% confidence</Badge>
            </div>
              {incident.explanation && <p className="mt-2 text-xs muted-text">{incident.explanation}</p>}
              {incident.recommendation && <p className="mt-1 text-xs muted-text">{incident.recommendation}</p>}
          </div>
        ))}
        {!correlations.length && <p className="py-8 text-center text-sm muted-text">No multi-evidence correlations found in the currently loaded records.</p>}
      </div>
    </Card>
  )
}

function ThreatInvestigation({ isLinux, selectedEvent, relatedEvents, selectedCorrelation, recommendation }) {
  const cloudSources = (selectedCorrelation?.sources || []).filter((source) => source === 'Azure' || source === 'OpenStack' || source === 'HDFS')
  return (
    <Card title="Threat Investigation" subtitle="Select a row in Unified Event Stream to inspect related evidence">
      <div className="grid gap-3 md:grid-cols-2">
        <MiniRow label="Selected Source" value={selectedEvent ? sourceOf(selectedEvent) : '-'} />
        <MiniRow label="Actor" value={selectedEvent ? actorOf(selectedEvent) : '-'} />
        <MiniRow label="Selected event risk" value={selectedEvent ? formatEventRisk(selectedEvent) : 'Unavailable'} />
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
      {!isLinux && (
        <div className="mt-4 grid gap-2 md:grid-cols-2">
          <MiniRow label="Cloud Activity" value={cloudSources.length ? `Related ${cloudSources.join(' + ')} evidence` : 'No linked cloud evidence'} />
        </div>
      )}
    </Card>
  )
}

function SecurityRecommendation({ safety, recommendation, selectedCorrelation, selectedEvent, alerts, primaryScore }) {
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
        <p className="mt-3 text-xs muted-text">
          {primaryScore?.available
            ? `Guidance uses ${PRIMARY_SCORE_LABEL.toLowerCase()} ${primaryScore.score} plus correlated evidence where available.`
            : `Primary ${PRIMARY_SCORE_LABEL.toLowerCase()} is unavailable (${primaryScore?.reason || 'insufficient data'}). Guidance falls back to selected finding evidence only.`}
        </p>
      </div>
      <div className="mt-4 grid gap-2 md:grid-cols-2">
        <MiniRow label="Selected Event" value={selectedEvent?.event_type || '-'} />
        <MiniRow label="Actor" value={selectedEvent ? actorOf(selectedEvent) : '-'} />
        <MiniRow label="Investigation confidence" value={selectedCorrelation ? `${selectedCorrelation.confidence}%` : 'No correlation'} />
        <MiniRow label="Related Evidence" value={selectedCorrelation?.evidence?.length || 0} />
      </div>
      <AlertBanner type="info" message={safety} />
    </Card>
  )
}

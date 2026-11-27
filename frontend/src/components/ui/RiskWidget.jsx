import { primaryScoreSeverity } from '../../intelligence/primaryScore'

export default function RiskWidget({ score = 0, label = 'Risk Score', size = 'md' }) {
  const normalized = Math.min(100, Math.max(0, Number(score) || 0))
  const level = primaryScoreSeverity(normalized).level
  const colors = {
    critical: { stroke: '#ef4444', text: 'text-red-400', bg: 'from-red-500/20' },
    high: { stroke: '#f97316', text: 'text-orange-400', bg: 'from-orange-500/20' },
    medium: { stroke: '#f59e0b', text: 'text-amber-400', bg: 'from-amber-500/20' },
    low: { stroke: '#10b981', text: 'text-emerald-400', bg: 'from-emerald-500/20' },
  }
  const c = colors[level]
  const dim = size === 'lg' ? 120 : 88
  const r = (dim - 12) / 2
  const circ = 2 * Math.PI * r
  const offset = circ - (normalized / 100) * circ

  return (
    <div className="cyber-card flex flex-col items-center gap-2 rounded-xl border border-[var(--panel-border)] p-4">
      <div className="relative" style={{ width: dim, height: dim }}>
        <svg width={dim} height={dim} className="-rotate-90">
          <circle cx={dim / 2} cy={dim / 2} r={r} fill="none" stroke="rgba(148, 163, 184, 0.18)" strokeWidth="8" />
          <circle
            cx={dim / 2}
            cy={dim / 2}
            r={r}
            fill="none"
            stroke={c.stroke}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circ}
            strokeDashoffset={offset}
            className="transition-all duration-700"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-3xl font-bold tabular-nums ${c.text}`}>{normalized}</span>
        </div>
      </div>
      <span className="text-xs font-semibold uppercase tracking-wide muted-text">{label}</span>
      <Badge level={level} />
    </div>
  )
}

function Badge({ level }) {
  return (
    <span className={`text-xs font-semibold uppercase ${level === 'critical' ? 'text-red-400' : level === 'high' ? 'text-orange-400' : level === 'medium' ? 'text-amber-400' : 'text-emerald-400'}`}>
      {level}
    </span>
  )
}

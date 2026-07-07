import { useNavigate } from 'react-router-dom'
import { Cpu, HardDrive, Loader2, Network, Server, Terminal } from 'lucide-react'
import { motion } from 'framer-motion'
import { StatusBadge } from './Badge'
import Button from './Button'

export default function ServerCard({ server, onOpen, onTest, onCollect, onDelete, isAdmin, busy = false }) {
  const navigate = useNavigate()
  const isOnline = (server.connection_state || server.status || '').toLowerCase().includes('online')
  const risk = Number(server.risk_score || 0)
  const health = isOnline ? Math.max(62, 100 - risk) : 28

  const openServer = () => {
    if (onOpen) onOpen()
    else navigate(`/servers/${server.id}`)
  }

  return (
    <motion.article whileHover={{ y: -4 }} className="cyber-card group p-5">
      <div className="mb-4 flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="mb-3 flex items-center gap-3">
            <div className="relative rounded-xl border border-neutral-500/20 bg-neutral-500/10 p-3 text-neutral-300">
              <Server className="relative h-6 w-6" />
            </div>
            <div className="min-w-0">
              <button
                type="button"
                onClick={openServer}
                className="block truncate text-left text-lg font-semibold cyber-text transition-opacity hover:opacity-70"
              >
                {server.server_name}
              </button>
              <p className="mt-1 font-mono text-xs muted-text">{server.host}:{server.port}</p>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <StatusBadge status={isOnline ? 'online' : 'offline'}>{server.connection_state || server.status}</StatusBadge>
            <span className="rounded-full border border-[var(--panel-border)] bg-[var(--panel-strong)] px-2.5 py-1 text-[11px] font-semibold uppercase muted-text">{server.operating_system || 'linux'}</span>
          </div>
        </div>
        <div className={`rounded-xl border px-3 py-2 text-center ${risk >= 70 ? 'border-red-500/20 bg-red-500/10 text-red-400' : risk >= 40 ? 'border-amber-500/20 bg-amber-500/10 text-amber-400' : 'border-emerald-500/20 bg-emerald-500/10 text-emerald-400'}`}>
          <p className="text-[10px] font-semibold uppercase">Risk</p>
          <p className="text-xl font-bold">{risk}</p>
        </div>
      </div>

      <div className="mb-4 grid grid-cols-3 gap-2">
        {[
          { icon: Cpu, label: 'CPU', value: `${Math.min(99, risk + 18)}%` },
          { icon: HardDrive, label: 'Disk', value: `${Math.min(98, risk + 24)}%` },
          { icon: Network, label: 'SSH', value: server.authentication_type || 'ssh' },
        ].map((metric) => {
          const Icon = metric.icon
          return (
            <div key={metric.label} className="rounded-xl border border-[var(--panel-border)] bg-[var(--panel-strong)] p-3">
              <Icon className="mb-2 h-4 w-4 text-neutral-300" />
              <p className="text-[10px] font-semibold uppercase muted-text">{metric.label}</p>
              <p className="truncate text-sm font-semibold cyber-text">{metric.value}</p>
            </div>
          )
        })}
      </div>

      <div className="mb-4">
        <div className="mb-2 flex justify-between text-[11px] font-bold uppercase muted-text">
          <span>Health Meter</span>
          <span>{health}%</span>
        </div>
        <div className="h-2 overflow-hidden rounded-full bg-[var(--panel-strong)]">
          <div className={`h-full rounded-full ${isOnline ? 'bg-emerald-500' : 'bg-red-500'}`} style={{ width: `${health}%` }} />
        </div>
      </div>

      <div className="mb-4 grid grid-cols-2 gap-3 text-sm">
        <div>
          <p className="text-[10px] font-semibold uppercase muted-text">User</p>
          <p className="truncate cyber-text">{server.username}</p>
        </div>
        <div className="min-w-0">
          <p className="text-[10px] font-semibold uppercase muted-text">Last Seen</p>
          <p className="truncate font-mono text-xs muted-text">{server.last_seen || server.last_connected ? new Date(server.last_seen || server.last_connected).toLocaleString() : 'Never'}</p>
        </div>
      </div>

      <div className="flex flex-wrap gap-2 border-t border-[var(--panel-border)] pt-3">
        <Button variant="ghost" size="sm" disabled={busy} onClick={openServer}>
          <Terminal className="h-4 w-4" /> Open
        </Button>
        <Button variant="secondary" size="sm" disabled={busy} onClick={() => onTest?.()}>
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
          Test
        </Button>
        <Button variant="primary" size="sm" disabled={busy} onClick={() => onCollect?.()}>
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
          Collect
        </Button>
        {isAdmin && (
          <Button variant="danger" size="sm" disabled={busy} onClick={() => onDelete?.()}>
            Delete
          </Button>
        )}
      </div>
    </motion.article>
  )
}

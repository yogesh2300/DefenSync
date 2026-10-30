import { useMemo, useState } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import {
  Activity, BarChart3, Bell, BrainCircuit, Cloud, DatabaseZap, LayoutDashboard, LayoutGrid,
  LogOut, Server, Settings, Shield, TerminalSquare, Users,
} from 'lucide-react'
import { useAuth } from '../../context/AuthContext'
import { useEnvironment } from '../../context/EnvironmentContext'
import { ENVIRONMENT_LABELS, postAuthPath } from '../../environment'
import UserMenu from '../UserMenu'
import './admin.css'

const NAV = [
  { to: '/admin/dashboard', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/admin/users', label: 'Users', icon: Users },
  { to: '/admin/servers', label: 'Servers', icon: Server },
  { to: '/admin/cloud-accounts', label: 'Cloud Accounts', icon: Cloud },
  { to: '/admin/collections', label: 'Collections', icon: DatabaseZap },
  { to: '/admin/events', label: 'Events', icon: TerminalSquare },
  { to: '/admin/alerts', label: 'Alerts', icon: Bell },
  { to: '/admin/detections', label: 'Detections', icon: Activity },
  { to: '/admin/ml', label: 'Machine Learning', icon: BrainCircuit },
  { to: '/admin/system-health', label: 'System Health', icon: Shield },
  { to: '/admin/analytics', label: 'Analytics', icon: BarChart3 },
  { to: '/admin/settings', label: 'Settings', icon: Settings },
]

export default function AdminLayout() {
  const { user, logout } = useAuth()
  const { environment } = useEnvironment()
  const navigate = useNavigate()
  const [collapsed, setCollapsed] = useState(false)
  const initial = useMemo(() => user?.username?.slice(0, 1)?.toUpperCase() || 'A', [user])
  const menuLinks = [{
    to: postAuthPath(user, environment),
    label: environment ? `${ENVIRONMENT_LABELS[environment]} Workspace` : 'Choose Environment',
    icon: LayoutGrid,
  }]

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <div className="admin-shell flex min-h-screen">
      <aside className={`admin-sidebar fixed inset-y-0 left-0 z-30 flex flex-col p-4 transition-all ${collapsed ? 'w-[4.5rem]' : 'w-60'}`}>
        <div className="mb-6 flex items-center gap-3 px-2">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-white/10 text-white">
            <Shield className="h-5 w-5" />
          </div>
          {!collapsed && (
            <div>
              <p className="text-sm font-bold text-white">DefenSync</p>
              <p className="text-[10px] uppercase tracking-wider text-zinc-500">Admin Console</p>
            </div>
          )}
        </div>

        <nav className="flex-1 space-y-1 overflow-y-auto">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition ${
                  isActive ? 'admin-nav-active text-white' : 'text-zinc-400 hover:bg-white/5 hover:text-zinc-200'
                }`
              }
            >
              <Icon className="h-4 w-4 shrink-0" />
              {!collapsed && <span>{label}</span>}
            </NavLink>
          ))}
        </nav>

        <div className="mt-4 space-y-2 border-t border-zinc-800 pt-4">
          {!collapsed && (
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 px-3 py-2">
              <p className="truncate text-sm font-medium text-white">{user?.username}</p>
              <p className="text-xs uppercase text-zinc-500">{user?.role}</p>
            </div>
          )}
          <button
            type="button"
            onClick={handleLogout}
            className="flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm text-zinc-400 hover:bg-white/5 hover:text-white"
          >
            <LogOut className="h-4 w-4" />
            {!collapsed && 'Logout'}
          </button>
        </div>

        <button
          type="button"
          onClick={() => setCollapsed((v) => !v)}
          className="mt-3 rounded-lg border border-zinc-800 px-2 py-1 text-[10px] text-zinc-500 hover:text-zinc-300"
        >
          {collapsed ? '»' : '«'}
        </button>
      </aside>

      <main className={`flex-1 transition-all ${collapsed ? 'ml-[4.5rem]' : 'ml-60'}`}>
        <div className="flex items-center justify-between gap-4 border-b border-zinc-800 bg-[#0a0a0b]/90 px-6 py-4 backdrop-blur">
          <div>
            <p className="text-xs uppercase tracking-[0.2em] text-zinc-500">Security Monitoring</p>
            <h1 className="text-xl font-semibold text-white">Admin Console</h1>
          </div>
          <UserMenu username={user?.username} role={user?.role} onLogout={handleLogout} links={menuLinks} variant="dark" />
        </div>
        <div className="p-6">
          <Outlet />
        </div>
      </main>
    </div>
  )
}

export function AdminMetric({ label, value, sub }) {
  return (
    <div className="admin-metric p-4">
      <p className="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">{label}</p>
      <p className="mt-2 text-2xl font-bold text-white">{value}</p>
      {sub && <p className="mt-1 text-xs text-zinc-500">{sub}</p>}
    </div>
  )
}

export function AdminCard({ title, subtitle, children, className = '' }) {
  return (
    <div className={`admin-card p-5 ${className}`}>
      {(title || subtitle) && (
        <div className="mb-4">
          {title && <h3 className="text-sm font-semibold text-white">{title}</h3>}
          {subtitle && <p className="text-xs text-zinc-500">{subtitle}</p>}
        </div>
      )}
      {children}
    </div>
  )
}

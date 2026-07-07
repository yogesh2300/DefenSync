import { useEffect, useMemo, useState } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import {
  Activity, Bell, BrainCircuit, ChevronLeft, ChevronRight, DatabaseZap,
  LayoutDashboard, LogOut, Menu, Search, Server, ShieldCheck, TerminalSquare,
  TriangleAlert,
} from 'lucide-react'
import { motion } from 'framer-motion'
import { useAuth } from '../context/AuthContext'
import { useSelectedServer } from '../context/SelectedServerContext'
import { Select } from './ui/Input'

const NAV = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/servers', label: 'Servers', icon: Server },
  { to: '/events', label: 'Events', icon: TerminalSquare },
  { to: '/alerts', label: 'Alerts', icon: TriangleAlert },
  { to: '/detection', label: 'Detection', icon: BrainCircuit },
  { to: '/collection', label: 'Collection', icon: DatabaseZap, adminOnly: true },
]

function NavItem({ to, label, icon: Icon, end, collapsed, onClick }) {
  return (
    <NavLink
      to={to}
      end={end}
      onClick={onClick}
      className={({ isActive }) =>
        `group relative flex items-center gap-3 rounded-2xl px-3 py-3 text-sm font-medium transition ${
          isActive ? 'bg-[#111111] text-white shadow-sm' : 'text-[#6F746F] hover:bg-white hover:text-[#111111]'
        }`
      }
    >
      {({ isActive }) => (
        <>
          {isActive && <motion.span layoutId="active-dot" className="absolute -left-1 top-1/2 h-2 w-2 -translate-y-1/2 rounded-full bg-[#111111]" />}
          <Icon className="h-5 w-5 shrink-0" />
          {!collapsed && <span>{label}</span>}
        </>
      )}
    </NavLink>
  )
}

export default function Layout() {
  const { user, logout, isAdmin } = useAuth()
  const { servers, selectedServerId, setSelectedServerId, loading: serversLoading } = useSelectedServer()
  const navigate = useNavigate()
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [collapsed, setCollapsed] = useState(false)
  const [now, setNow] = useState(new Date())

  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(id)
  }, [])

  const visibleNav = NAV.filter((item) => !item.adminOnly || isAdmin)
  const userInitial = useMemo(() => user?.username?.slice(0, 1)?.toUpperCase() || 'U', [user])

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  const sidebar = (
    <aside className="flex h-full flex-col rounded-[2rem] border border-[#DADDD8] bg-[#F7F8F6]/90 p-3 shadow-[0_20px_80px_rgba(17,17,17,0.08)] backdrop-blur">
      <div className="mb-4 flex items-center gap-3 px-2 py-2">
        <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-[#111111] text-white">
          <ShieldCheck className="h-6 w-6" />
        </div>
        {!collapsed && (
          <div>
            <h1 className="text-lg font-bold tracking-tight text-[#111111]">DefenSync</h1>
            <p className="text-xs text-[#6F746F]">Security Monitoring</p>
          </div>
        )}
      </div>

      <nav className="flex-1 space-y-2">
        {visibleNav.map((item) => (
          <NavItem key={item.to} {...item} collapsed={collapsed} onClick={() => setSidebarOpen(false)} />
        ))}
      </nav>

      <div className="mt-4 space-y-3 border-t border-[#DADDD8] pt-4">
        {!collapsed && (
          <div className="rounded-3xl border border-[#DADDD8] bg-white p-3">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#111111] text-sm font-semibold text-white">
                {userInitial}
              </div>
              <div className="min-w-0">
                <p className="truncate text-sm font-semibold text-[#111111]">{user?.username}</p>
                <p className="text-xs capitalize text-[#6F746F]">{user?.role || 'analyst'}</p>
              </div>
            </div>
          </div>
        )}
        <button
          type="button"
          onClick={handleLogout}
          className="flex w-full items-center gap-3 rounded-2xl px-3 py-3 text-sm text-[#6F746F] transition hover:bg-white hover:text-[#111111]"
        >
          <LogOut className="h-5 w-5" />
          {!collapsed && 'Sign Out'}
        </button>
      </div>
    </aside>
  )

  return (
    <div className="grid-bg min-h-screen bg-[var(--app-bg)]">
      <div className={`fixed inset-y-3 left-3 z-30 hidden transition-all duration-300 lg:block ${collapsed ? 'w-[4.5rem]' : 'w-56'}`}>
        {sidebar}
        <button
          type="button"
          onClick={() => setCollapsed((value) => !value)}
          className="absolute -right-3 top-24 rounded-full border border-[#DADDD8] bg-white p-1.5 text-[#111111] shadow-sm"
          aria-label="Toggle sidebar"
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
        </button>
      </div>

      {sidebarOpen && (
        <div className="fixed inset-0 z-40 flex lg:hidden">
          <button aria-label="Close sidebar" className="fixed inset-0 bg-black/30" onClick={() => setSidebarOpen(false)} />
          <div className="relative z-50 m-3 h-[calc(100vh-1.5rem)] w-64 max-w-[85vw]">{sidebar}</div>
        </div>
      )}

      <div className={`flex min-h-screen w-full flex-col transition-all duration-300 ${collapsed ? 'lg:pl-[5.25rem]' : 'lg:pl-[15.5rem]'}`}>
        <header className="sticky top-0 z-20 px-3 py-3 sm:px-5 lg:px-6">
          <div className="flex h-14 w-full items-center gap-3 rounded-[1.75rem] border border-[#DADDD8] bg-white/90 px-3 shadow-[0_14px_60px_rgba(17,17,17,0.07)] backdrop-blur sm:px-4">
            <button type="button" className="rounded-2xl p-2 text-[#6F746F] hover:bg-[#F0F1EF] lg:hidden" onClick={() => setSidebarOpen(true)} aria-label="Open sidebar">
              <Menu className="h-5 w-5" />
            </button>
            <div className="flex min-w-0 flex-1 items-center gap-2 rounded-full border border-[#DADDD8] bg-[#F7F8F6] px-4 py-2">
              <Search className="h-4 w-4 shrink-0 text-[#6F746F]" />
              <span className="truncate text-sm text-[#6F746F]">Search events, users, hosts...</span>
            </div>

            <div className="flex shrink-0 items-center gap-2">
              <Select
                value={selectedServerId}
                onChange={(event) => setSelectedServerId(event.target.value)}
                className="hidden w-44 sm:block"
                disabled={serversLoading}
                aria-label="Filter by server"
              >
                <option value="">All Servers</option>
                {servers.map((server) => (
                  <option key={server.id} value={server.id}>{server.server_name}</option>
                ))}
              </Select>
              <Select
                value={selectedServerId}
                onChange={(event) => setSelectedServerId(event.target.value)}
                className="w-36 sm:hidden"
                disabled={serversLoading}
                aria-label="Filter by server"
              >
                <option value="">All</option>
                {servers.map((server) => (
                  <option key={server.id} value={server.id}>{server.server_name}</option>
                ))}
              </Select>
              <div className="hidden items-center gap-2 rounded-full bg-[#D8ECE6] px-3 py-2 text-xs font-semibold text-[#111111] md:flex">
                <Activity className="h-4 w-4" />
                Server status
              </div>
              <div className="hidden rounded-full border border-[#DADDD8] bg-[#F7F8F6] px-3 py-2 font-mono text-xs text-[#111111] md:block">
                {now.toLocaleTimeString()}
              </div>
              <button type="button" className="rounded-full border border-[#DADDD8] bg-[#F7F8F6] p-2.5 text-[#111111] transition hover:bg-[#ECEFED]" aria-label="Notifications">
                <Bell className="h-5 w-5" />
              </button>
            </div>
          </div>
        </header>

        <main className="w-full flex-1 px-3 pb-5 sm:px-5 lg:px-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}

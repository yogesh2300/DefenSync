import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { ChevronDown, LogOut } from 'lucide-react'

const VARIANTS = {
  light: {
    button: 'border-[#DADDD8] bg-[#F7F8F6] text-[#111111] hover:bg-[#ECEFED]',
    chevron: 'text-[#6F746F]',
    menu: 'border-[#DADDD8] bg-white',
    role: 'text-[#6F746F]',
    item: 'text-[#111111] hover:bg-[#F0F1EF]',
  },
  dark: {
    button: 'border-zinc-800 bg-zinc-900/60 text-white hover:bg-zinc-800',
    chevron: 'text-zinc-500',
    menu: 'border-zinc-800 bg-[#111113]',
    role: 'text-zinc-500',
    item: 'text-zinc-200 hover:bg-white/5',
  },
}

export default function UserMenu({ username, role, onLogout, links = [], variant = 'light' }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)
  const styles = VARIANTS[variant] || VARIANTS.light

  useEffect(() => {
    if (!open) return undefined
    const close = (event) => {
      if (!ref.current?.contains(event.target)) setOpen(false)
    }
    const escape = (event) => {
      if (event.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', close)
    document.addEventListener('keydown', escape)
    return () => {
      document.removeEventListener('mousedown', close)
      document.removeEventListener('keydown', escape)
    }
  }, [open])

  if (!username) return null

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`Account menu for ${username}`}
        data-header-username={username}
        className={`flex items-center gap-1.5 rounded-full border py-2 pl-3 pr-2 text-sm font-semibold transition ${styles.button}`}
      >
        <span className="max-w-[10rem] truncate">{username}</span>
        <ChevronDown className={`h-4 w-4 ${styles.chevron}`} />
      </button>
      {open && (
        <div role="menu" className={`absolute right-0 z-50 mt-2 w-44 rounded-2xl border p-2 shadow-lg ${styles.menu}`}>
          {role && <p className={`px-3 py-1 text-xs uppercase tracking-wide ${styles.role}`}>{role}</p>}
          {links.map(({ to, label, icon: Icon }) => (
            <Link
              key={to}
              to={to}
              role="menuitem"
              onClick={() => setOpen(false)}
              className={`flex w-full items-center gap-2 rounded-xl px-3 py-2 text-sm ${styles.item}`}
            >
              {Icon && <Icon className="h-4 w-4" />}
              {label}
            </Link>
          ))}
          <button
            type="button"
            role="menuitem"
            onClick={onLogout}
            className={`flex w-full items-center gap-2 rounded-xl px-3 py-2 text-sm ${styles.item}`}
          >
            <LogOut className="h-4 w-4" />
            Sign Out
          </button>
        </div>
      )}
    </div>
  )
}

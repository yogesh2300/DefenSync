import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Cloud, LogOut, Server } from 'lucide-react'
import Button from '../components/ui/Button'
import { useAuth } from '../context/AuthContext'
import { useEnvironment } from '../context/EnvironmentContext'
import { CLOUD, LINUX, environmentEntryPath } from '../environment'

const OPTIONS = [
  { value: LINUX, title: 'Linux', icon: Server, description: 'Linux server monitoring', detail: 'SSH log collection, server health, events, alerts and intelligence for your Linux hosts.' },
  { value: CLOUD, title: 'Cloud', icon: Cloud, description: 'Azure / cloud security monitoring', detail: 'Read-only Azure telemetry: Entra ID sign-ins and Activity Log, with cloud events, alerts and intelligence.' },
]

export default function EnvironmentSelect() {
  const { user, logout } = useAuth()
  const { setEnvironment } = useEnvironment()
  const navigate = useNavigate()
  const [pending, setPending] = useState(null)

  // A push (not replace) keeps Environment Selection in history, so Back from the dashboard returns here.
  const choose = (value) => {
    setPending(value)
    setEnvironment(value)
    navigate(environmentEntryPath(value))
  }

  return (
    <div className="grid-bg relative flex min-h-screen items-center justify-center overflow-hidden p-6">
      <main className="w-full max-w-3xl">
        <motion.header initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="mb-8 text-center">
          <p className="text-sm font-semibold muted-text">Signed in as {user?.username}</p>
          <h1 className="mt-2 text-4xl font-bold tracking-tight cyber-text">Choose your environment</h1>
          <p className="mt-3 text-sm muted-text">Choose what you want to configure or manage first. You can switch at any time from the navigation.</p>
        </motion.header>
        <div className="grid gap-4 sm:grid-cols-2">
          {OPTIONS.map(({ value, title, icon: Icon, description, detail }) => (
            <motion.section
              key={value}
              initial={{ opacity: 0, scale: 0.98 }}
              animate={{ opacity: 1, scale: 1 }}
              className="cyber-card flex flex-col p-6"
              data-environment-option={value}
            >
              <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-2xl bg-[#111111] text-white">
                <Icon className="h-6 w-6" />
              </div>
              <h2 className="text-2xl font-bold tracking-tight cyber-text">{title.toUpperCase()}</h2>
              <p className="mt-1 text-sm font-semibold cyber-text">{description}</p>
              <p className="mt-2 flex-1 text-sm leading-6 muted-text">{detail}</p>
              <Button className="mt-6 w-full" onClick={() => choose(value)} disabled={pending !== null} aria-label={`Continue with ${title}`}>
                {pending === value ? 'Opening...' : 'Continue'}
              </Button>
            </motion.section>
          ))}
        </div>
        <div className="mt-6 text-center">
          <button type="button" onClick={logout} className="inline-flex items-center gap-2 text-sm muted-text hover:opacity-70">
            <LogOut className="h-4 w-4" /> Sign out
          </button>
        </div>
      </main>
    </div>
  )
}

import { useEffect, useState } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Eye, EyeOff, Fingerprint, ShieldCheck } from 'lucide-react'
import { getServers, register } from '../api/client'
import AlertBanner from '../components/ui/AlertBanner'
import Button from '../components/ui/Button'
import { Input } from '../components/ui/Input'
import { useAuth } from '../context/AuthContext'

export default function Login() {
  const { user, login } = useAuth()
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [email, setEmail] = useState('')
  const [mode, setMode] = useState('login')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [redirectTo, setRedirectTo] = useState(null)

  useEffect(() => {
    if (!user) return
    let cancelled = false
    getServers()
      .then((servers) => {
        if (cancelled) return
        setRedirectTo(Array.isArray(servers) && servers.length > 0 ? '/' : '/servers/new')
      })
      .catch(() => {
        if (cancelled) return
        setRedirectTo('/servers/new')
      })
    return () => {
      cancelled = true
    }
  }, [user])

  if (redirectTo) return <Navigate to={redirectTo} replace />

  const handleSubmit = async (event) => {
    event.preventDefault()
    setError('')
    setLoading(true)
    try {
      if (mode === 'register') {
        await register(username, email, password)
        await login(username, password)
      } else {
        await login(username, password)
      }
      const servers = await getServers()
      navigate(Array.isArray(servers) && servers.length > 0 ? '/' : '/servers/new', { replace: true })
    } catch (err) {
      setError(err.response?.data?.detail || err.response?.data?.error || err.message || 'Authentication failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="grid-bg relative flex min-h-screen items-center justify-center overflow-hidden p-6">
      <main className="grid w-full max-w-5xl gap-10 lg:grid-cols-[0.9fr_1.1fr] lg:items-center">
        <motion.section initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} className="text-center lg:text-left">
          <div className="mx-auto mb-8 flex h-16 w-16 items-center justify-center rounded-3xl border border-[var(--panel-border)] bg-[var(--panel)] lg:mx-0">
            <ShieldCheck className="h-8 w-8 text-neutral-300" />
          </div>
          <p className="mb-4 text-sm font-semibold muted-text">Security Monitoring</p>
          <h1 className="text-6xl font-bold tracking-[-0.06em] cyber-text sm:text-7xl">DefenSync</h1>
          <p className="mt-6 max-w-md text-base leading-7 muted-text lg:max-w-lg">
            Monitor servers, events, detections and alerts from one quiet, focused interface.
          </p>
        </motion.section>

        <motion.section
          initial={{ opacity: 0, scale: 0.98 }}
          animate={{ opacity: 1, scale: 1 }}
          className="cyber-card mx-auto w-full max-w-md p-8"
        >
          <div className="mb-8">
            <div className="mb-5 flex h-14 w-14 items-center justify-center rounded-3xl border border-[var(--panel-border)] bg-[var(--panel-strong)]">
              <Fingerprint className="h-7 w-7 text-neutral-300" />
            </div>
            <h2 className="text-3xl font-semibold cyber-text">{mode === 'login' ? 'Sign in' : 'Create account'}</h2>
            <p className="mt-2 text-sm muted-text">Security Monitoring</p>
          </div>

          <AlertBanner message={error} type="error" />

          <form onSubmit={handleSubmit} className="space-y-4">
            <Input label="Username" value={username} onChange={(event) => setUsername(event.target.value)} required minLength={3} autoComplete="username" />
            {mode === 'register' && (
              <Input label="Email" type="email" value={email} onChange={(event) => setEmail(event.target.value)} required autoComplete="email" />
            )}
            <div className="relative">
              <Input
                label="Password"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
                minLength={8}
                autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                className="pr-12"
              />
              <button
                type="button"
                onClick={() => setShowPassword((value) => !value)}
                className="absolute bottom-3 right-3 rounded-lg p-1 muted-text hover:bg-[var(--panel)]"
                aria-label="Toggle password visibility"
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? 'Authenticating...' : mode === 'login' ? 'Sign In' : 'Register'}
            </Button>
          </form>

          <p className="mt-6 text-center text-sm muted-text">
            {mode === 'login' ? 'No account?' : 'Already registered?'}{' '}
            <button type="button" className="font-semibold cyber-text hover:opacity-70" onClick={() => setMode(mode === 'login' ? 'register' : 'login')}>
              {mode === 'login' ? 'Create one' : 'Sign in'}
            </button>
          </p>
        </motion.section>
      </main>
    </div>
  )
}

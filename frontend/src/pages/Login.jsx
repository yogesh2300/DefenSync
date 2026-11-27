import { useEffect, useState } from 'react'
import { Link, Navigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Eye, EyeOff, Fingerprint, KeyRound, ShieldCheck } from 'lucide-react'
import AlertBanner from '../components/ui/AlertBanner'
import Button from '../components/ui/Button'
import { Input } from '../components/ui/Input'
import { useAuth } from '../context/AuthContext'
import { useEnvironment } from '../context/EnvironmentContext'
import { postAuthPath } from '../environment'
import {
  authErrorMessage, challengeDeadlines, channelLabel, expiryState, otpRequiresRestart, registrationStartedMessage, resendState,
  resentMessage, retryAfterDeadline,
} from '../auth/otp'

function errorCode(err) {
  return err?.response?.data?.code || null
}

export default function Login() {
  const { user, login, sendOtp, verifyOtp, register, verifyRegistration } = useAuth()
  const { environment } = useEnvironment()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [email, setEmail] = useState('')
  const [mode, setMode] = useState('login')
  const [step, setStep] = useState('credentials')
  const [challenge, setChallenge] = useState(null)
  const [otp, setOtp] = useState('')
  const [expiresAt, setExpiresAt] = useState(null)
  const [resendAt, setResendAt] = useState(0)
  const [now, setNow] = useState(Date.now())
  const [error, setError] = useState('')
  const [info, setInfo] = useState('')
  const [loading, setLoading] = useState(false)
  const [showPassword, setShowPassword] = useState(false)

  useEffect(() => {
    if (step !== 'otp') return undefined
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [step])

  if (user) return <Navigate to={postAuthPath(user, environment)} replace />

  const registering = mode === 'register'
  const sentMessage = (destination) => (registering ? registrationStartedMessage() : `We sent a verification code to ${destination}.`)

  const applyChallenge = (next) => {
    const stamp = Date.now()
    const deadlines = challengeDeadlines(next, stamp)
    setChallenge(next)
    setExpiresAt(deadlines.expiresAt)
    setResendAt(deadlines.resendAt)
    setNow(stamp)
  }

  const restart = (message) => {
    setStep('credentials')
    setChallenge(null)
    setOtp('')
    setInfo('')
    setError(message)
  }

  const handleCredentials = async (event) => {
    event.preventDefault()
    setError('')
    setInfo('')
    setLoading(true)
    try {
      const next = registering
        ? await register(username.trim(), email.trim(), password)
        : await login(email.trim(), password)
      applyChallenge(next)
      setPassword('')
      setOtp('')
      setStep('otp')
      if (next.delivery) setInfo(sentMessage(next.destination))
    } catch (err) {
      setError(authErrorMessage(err, { registering }))
    } finally {
      setLoading(false)
    }
  }

  const handleSend = async (channel = null, { resending = false } = {}) => {
    setError('')
    setInfo('')
    setLoading(true)
    try {
      const next = await sendOtp(challenge.challenge_id, channel)
      applyChallenge(next)
      setOtp('')
      setInfo(resending ? resentMessage({ registering, destination: next.destination }) : sentMessage(next.destination))
    } catch (err) {
      const message = authErrorMessage(err, { registering, resending })
      const serverResendAt = retryAfterDeadline(err, Date.now())
      if (serverResendAt) setResendAt(serverResendAt)
      if (otpRequiresRestart(errorCode(err))) restart(message)
      else setError(message)
    } finally {
      setLoading(false)
    }
  }

  const handleVerify = async (event) => {
    event.preventDefault()
    setError('')
    setLoading(true)
    try {
      if (registering) await verifyRegistration(challenge.challenge_id, otp.trim())
      else await verifyOtp(challenge.challenge_id, otp.trim())
    } catch (err) {
      if (errorCode(err) === 'OTP_EXPIRED') setExpiresAt(Date.now())
      if (otpRequiresRestart(errorCode(err))) restart(authErrorMessage(err, { registering }))
      else setError(authErrorMessage(err, { registering }))
      setOtp('')
    } finally {
      setLoading(false)
    }
  }

  const awaitingChannel = step === 'otp' && challenge && !challenge.delivery
  const expiry = expiryState(expiresAt, now)
  const resend = resendState(resendAt, now)

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
          {step === 'credentials' ? (
            <>
              <div className="mb-8">
                <div className="mb-5 flex h-14 w-14 items-center justify-center rounded-3xl border border-[var(--panel-border)] bg-[var(--panel-strong)]">
                  <Fingerprint className="h-7 w-7 text-neutral-300" />
                </div>
                <h2 className="text-3xl font-semibold cyber-text">{mode === 'login' ? 'Sign in' : 'Create account'}</h2>
                <p className="mt-2 text-sm muted-text">
                  {mode === 'login'
                    ? 'Email and password, then a one-time code sent to your email'
                    : 'Username, email and password, then a code sent to your email to finish'}
                </p>
              </div>

              <AlertBanner message={error} type="error" />

              <form onSubmit={handleCredentials} className="space-y-4">
                {mode === 'register' && (
                  <Input label="Username" value={username} onChange={(event) => setUsername(event.target.value)} required minLength={3} maxLength={50} autoComplete="nickname" />
                )}
                <Input label="Email" type="email" value={email} onChange={(event) => setEmail(event.target.value)} required maxLength={100} autoComplete="email" />                <div className="relative">
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
                {mode === 'login' && (
                  <div className="-mt-1 text-right">
                    <Link to="/forgot-password" className="text-sm font-semibold cyber-text hover:opacity-70">
                      Forgot password?
                    </Link>
                  </div>
                )}
                <Button type="submit" className="w-full" disabled={loading}>
                  {loading ? 'Checking...' : mode === 'login' ? 'Sign In' : 'Register'}
                </Button>
              </form>

              <p className="mt-6 text-center text-sm muted-text">
                {mode === 'login' ? 'No account?' : 'Already registered?'}{' '}
                <button
                  type="button"
                  className="font-semibold cyber-text hover:opacity-70"
                  onClick={() => {
                    setError('')
                    setMode(mode === 'login' ? 'register' : 'login')
                  }}
                >
                  {mode === 'login' ? 'Create one' : 'Sign in'}
                </button>
              </p>
            </>
          ) : (
            <>
              <div className="mb-6">
                <div className="mb-5 flex h-14 w-14 items-center justify-center rounded-3xl border border-[var(--panel-border)] bg-[var(--panel-strong)]">
                  <KeyRound className="h-7 w-7 text-neutral-300" />
                </div>
                <h2 className="text-3xl font-semibold cyber-text">
                  {awaitingChannel ? 'Send code to' : registering ? 'Complete registration' : 'Enter verification code'}
                </h2>
                <p className="mt-2 text-sm muted-text">
                  {registering
                    ? 'Your account is created only after this code is verified.'
                    : 'Second step of sign-in. You are not signed in until the code is verified.'}
                </p>
              </div>

              <AlertBanner message={error} type="error" />
              {info && !error && <AlertBanner message={info} type="success" />}

              {awaitingChannel ? (
                <div className="space-y-3">
                  {challenge.channels.map((item) => (
                    <Button key={item.channel} variant="secondary" className="w-full" disabled={loading} onClick={() => handleSend(item.channel)}>
                      {channelLabel(item.channel)} · {item.destination}
                    </Button>
                  ))}
                </div>
              ) : (
                <form onSubmit={handleVerify} className="space-y-4">
                  <label className="block">
                    <span className="mb-2 block text-sm font-medium muted-text">Enter verification code</span>
                    <input
                      value={otp}
                      onChange={(event) => setOtp(event.target.value.replace(/\D/g, '').slice(0, 6))}
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      pattern="\d{6}"
                      maxLength={6}
                      required
                      autoFocus
                      aria-label="6-digit verification code"
                      placeholder="••••••"
                      className="w-full rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] px-4 py-3 text-center font-mono text-2xl tracking-[0.6em] cyber-text outline-none focus:border-neutral-400"
                    />
                  </label>
                  <p className={`text-center text-sm ${expiry.expired ? 'font-medium cyber-text' : 'muted-text'}`} aria-live="polite">
                    {expiry.label}
                  </p>
                  <Button type="submit" className="w-full" disabled={loading || otp.length !== 6 || expiry.expired}>
                    {loading ? 'Verifying...' : 'Verify'}
                  </Button>
                  <div className="space-y-2 pt-2 text-center">
                    <p className="text-sm muted-text">Didn&apos;t receive the code?</p>
                    <Button
                      type="button"
                      variant="ghost"
                      className="w-full"
                      disabled={loading || !resend.available}
                      onClick={() => handleSend(null, { resending: true })}
                    >
                      <span className="font-mono">{resend.label}</span>
                    </Button>
                  </div>
                </form>
              )}

              <p className="mt-6 text-center text-sm muted-text">
                <button type="button" className="font-semibold cyber-text hover:opacity-70" onClick={() => restart('')}>
                  {registering ? 'Start registration over' : 'Use a different account'}
                </button>
              </p>
            </>
          )}
        </motion.section>
      </main>
    </div>
  )
}

import { useEffect, useState } from 'react'
import { Link, Navigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { CheckCircle2, Eye, EyeOff, KeyRound, LockKeyhole, MailQuestion } from 'lucide-react'
import AlertBanner from '../components/ui/AlertBanner'
import Button from '../components/ui/Button'
import { Input } from '../components/ui/Input'
import { completePasswordReset, requestPasswordReset, resendPasswordReset, verifyPasswordReset } from '../api/client'
import { useAuth } from '../context/AuthContext'
import { useEnvironment } from '../context/EnvironmentContext'
import { postAuthPath } from '../environment'
import { challengeDeadlines, expiryState, resendState, retryAfterDeadline } from '../auth/otp'
import {
  PASSWORD_RESET_REQUESTED_MESSAGE, PASSWORD_RESET_SUCCESS_MESSAGE, newPasswordProblem, resetErrorMessage, resetRequiresRestart,
} from '../auth/passwordReset'

const STEP_ICONS = { email: MailQuestion, code: KeyRound, password: LockKeyhole, done: CheckCircle2 }

export default function ForgotPassword() {
  const { user } = useAuth()
  const { environment } = useEnvironment()
  const [step, setStep] = useState('email')
  const [email, setEmail] = useState('')
  const [challengeId, setChallengeId] = useState(null)
  const [otp, setOtp] = useState('')
  // Held in memory only: never in storage or the URL, and gone once the password is set.
  const [resetToken, setResetToken] = useState(null)
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [expiresAt, setExpiresAt] = useState(null)
  const [resendAt, setResendAt] = useState(0)
  const [now, setNow] = useState(Date.now())
  const [error, setError] = useState('')
  const [info, setInfo] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (step !== 'code') return undefined
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [step])

  if (user) return <Navigate to={postAuthPath(user, environment)} replace />

  const applyChallenge = (next) => {
    const stamp = Date.now()
    const deadlines = challengeDeadlines(next, stamp)
    setChallengeId(next.challenge_id)
    setExpiresAt(deadlines.expiresAt)
    setResendAt(deadlines.resendAt)
    setNow(stamp)
  }

  const startOver = (message) => {
    setStep('email')
    setChallengeId(null)
    setResetToken(null)
    setOtp('')
    setNewPassword('')
    setConfirmPassword('')
    setInfo('')
    setError(message)
  }

  const run = async (action, { resending = false } = {}) => {
    setError('')
    setLoading(true)
    try {
      await action()
    } catch (err) {
      const serverResendAt = retryAfterDeadline(err, Date.now())
      if (serverResendAt) setResendAt(serverResendAt)
      if (err?.response?.data?.code === 'OTP_EXPIRED') setExpiresAt(Date.now())
      if (resetRequiresRestart(err)) startOver(resetErrorMessage(err, { resending }))
      else setError(resetErrorMessage(err, { resending }))
    } finally {
      setLoading(false)
    }
  }

  const handleRequest = (event) => {
    event.preventDefault()
    run(async () => {
      applyChallenge(await requestPasswordReset(email.trim()))
      setOtp('')
      setInfo(PASSWORD_RESET_REQUESTED_MESSAGE)
      setStep('code')
    })
  }

  const handleResend = () => run(async () => {
    setInfo('')
    applyChallenge(await resendPasswordReset(challengeId))
    setOtp('')
    setInfo('If the account exists, a new verification code has been sent. Earlier codes no longer work.')
  }, { resending: true })

  const handleVerify = (event) => {
    event.preventDefault()
    run(async () => {
      try {
        const { reset_token: token } = await verifyPasswordReset(challengeId, otp.trim())
        setResetToken(token)
        setChallengeId(null)
        setInfo('')
        setStep('password')
      } finally {
        setOtp('')
      }
    })
  }

  const handleComplete = (event) => {
    event.preventDefault()
    const problem = newPasswordProblem(newPassword, confirmPassword)
    if (problem) {
      setError(problem)
      return
    }
    run(async () => {
      await completePasswordReset(resetToken, newPassword, confirmPassword)
      setResetToken(null)
      setNewPassword('')
      setConfirmPassword('')
      setInfo('')
      setStep('done')
    })
  }

  const expiry = expiryState(expiresAt, now)
  const resend = resendState(resendAt, now)
  const Icon = STEP_ICONS[step]
  const titles = { email: 'Forgot Password', code: 'Enter Verification Code', password: 'Set New Password', done: 'Password Reset' }

  return (
    <div className="grid-bg relative flex min-h-screen items-center justify-center overflow-hidden p-6">
      <motion.section
        initial={{ opacity: 0, scale: 0.98 }}
        animate={{ opacity: 1, scale: 1 }}
        className="cyber-card mx-auto w-full max-w-md p-8"
      >
        <div className="mb-6">
          <div className="mb-5 flex h-14 w-14 items-center justify-center rounded-3xl border border-[var(--panel-border)] bg-[var(--panel-strong)]">
            <Icon className="h-7 w-7 text-neutral-300" />
          </div>
          <h2 className="text-3xl font-semibold cyber-text">{titles[step]}</h2>
          {step === 'email' && <p className="mt-2 text-sm muted-text">Enter your registered email.</p>}
          {step === 'password' && <p className="mt-2 text-sm muted-text">Choose a new password of at least 8 characters.</p>}
        </div>

        <AlertBanner message={error} type="error" />
        {info && !error && <AlertBanner message={info} type="success" />}

        {step === 'email' && (
          <form onSubmit={handleRequest} className="space-y-4">
            <Input label="Email" type="email" value={email} onChange={(event) => setEmail(event.target.value)} required maxLength={100} autoComplete="email" />
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? 'Sending...' : 'Send Reset Code'}
            </Button>
          </form>
        )}

        {step === 'code' && (
          <form onSubmit={handleVerify} className="space-y-4">
            <label className="block">
              <span className="mb-2 block text-sm font-medium muted-text">Verification code</span>
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
              {loading ? 'Verifying...' : 'Verify Code'}
            </Button>
            <div className="space-y-2 pt-2 text-center">
              <p className="text-sm muted-text">Didn&apos;t receive the code?</p>
              <Button type="button" variant="ghost" className="w-full" disabled={loading || !resend.available} onClick={handleResend}>
                <span className="font-mono">{resend.label}</span>
              </Button>
            </div>
          </form>
        )}

        {step === 'password' && (
          <form onSubmit={handleComplete} className="space-y-4">
            <div className="relative">
              <Input
                label="New Password"
                type={showPassword ? 'text' : 'password'}
                value={newPassword}
                onChange={(event) => setNewPassword(event.target.value)}
                required
                minLength={8}
                autoComplete="new-password"
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
            <Input
              label="Confirm New Password"
              type={showPassword ? 'text' : 'password'}
              value={confirmPassword}
              onChange={(event) => setConfirmPassword(event.target.value)}
              required
              minLength={8}
              autoComplete="new-password"
            />
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? 'Resetting...' : 'Reset Password'}
            </Button>
          </form>
        )}

        {step === 'done' && <AlertBanner message={PASSWORD_RESET_SUCCESS_MESSAGE} type="success" />}

        <p className="mt-6 text-center text-sm muted-text">
          {step === 'code' && (
            <>
              <button type="button" className="font-semibold cyber-text hover:opacity-70" onClick={() => startOver('')}>
                Use a different email
              </button>
              <span className="mx-2">·</span>
            </>
          )}
          <Link to="/login" className="font-semibold cyber-text hover:opacity-70">
            Back to Login
          </Link>
        </p>
      </motion.section>
    </div>
  )
}

// User-facing wording for second-factor errors. Backend detail text is never shown verbatim.

export const CODE_EXPIRED_MESSAGE = 'Code expired. Request a new code.'
export const REGISTRATION_SENT_MESSAGE = 'Verification code sent to your registered email.'

const MESSAGES = {
  OTP_INVALID: 'Incorrect verification code',
  OTP_EXPIRED: CODE_EXPIRED_MESSAGE,
  OTP_TOO_MANY_ATTEMPTS: 'Too many attempts. Please sign in again.',
  OTP_RESEND_COOLDOWN: 'Please wait before requesting another code',
  OTP_RESEND_LIMIT: 'Too many codes requested. Please sign in again.',
  OTP_CHALLENGE_INVALID: 'Your verification session ended. Please sign in again.',
  OTP_NOT_SENT: 'Choose where to send your code first.',
  OTP_CHANNEL_UNAVAILABLE: 'That delivery method is not available.',
  OTP_DELIVERY_FAILED: "The verification email couldn't be sent: the mail server rejected or didn't answer. Try again later or contact an administrator.",
  MFA_NOT_CONFIGURED: "Verification codes can't be sent: email delivery (SMTP) is not configured on this server. Contact an administrator.",
}

// During registration no account exists yet, so failures say the registration did not complete.
const REGISTRATION_MESSAGES = {
  MFA_NOT_CONFIGURED: 'Registration could not be completed because verification email delivery is not configured.',
  OTP_DELIVERY_FAILED: "Registration could not be completed because the verification email couldn't be sent. Try again later.",
  REGISTRATION_UNAVAILABLE: 'Too many registrations are pending right now. Try again in a few minutes.',
  OTP_RESEND_LIMIT: 'Too many codes requested for this email. Try again later.',
  OTP_TOO_MANY_ATTEMPTS: 'Too many attempts. Please register again.',
  OTP_CHALLENGE_INVALID: 'Your registration session ended. Please register again.',
}

// A failed resend keeps the challenge (and a pending registration) on the server, so the user stays on the code screen.
const RESEND_MESSAGES = {
  OTP_DELIVERY_FAILED: "The new code couldn't be sent. Select Resend OTP to try again.",
}
const REGISTRATION_RESEND_MESSAGES = {
  OTP_DELIVERY_FAILED: "The new code couldn't be sent. Your registration is still pending; select Resend OTP to try again.",
}

export const INVALID_CREDENTIALS_MESSAGE = 'Incorrect email or password.'
export const SERVER_UNREACHABLE_MESSAGE = "Can't reach the DefenSync server. Check that the backend is running."

const RESTART_CODES = new Set(['OTP_TOO_MANY_ATTEMPTS', 'OTP_RESEND_LIMIT', 'OTP_CHALLENGE_INVALID'])

export function otpErrorMessage(code, { registering = false, resending = false } = {}) {
  return (
    (resending && registering && REGISTRATION_RESEND_MESSAGES[code])
    || (resending && RESEND_MESSAGES[code])
    || (registering && REGISTRATION_MESSAGES[code])
    || MESSAGES[code]
    || 'Verification failed. Please try again.'
  )
}

export function registrationStartedMessage() {
  return REGISTRATION_SENT_MESSAGE
}

export function resentMessage({ registering = false, destination = '' } = {}) {
  return registering || !destination
    ? 'A new verification code was sent to your registered email.'
    : `A new verification code was sent to ${destination}.`
}

// One message per failure kind for the register, sign-in, send and verify calls (axios-style errors).
// `resending` marks the Resend OTP call; otherwise a cooldown means sign-in/registration was started again too soon.
export function authErrorMessage(err, { registering = false, resending = false } = {}) {
  const response = err?.response
  if (!response) return SERVER_UNREACHABLE_MESSAGE
  const data = response.data || {}
  if (data.code) {
    const message = otpErrorMessage(data.code, { registering, resending })
    if (data.code === 'OTP_INVALID' && data.attempts_remaining) return `${message} (${data.attempts_remaining} attempts left)`
    if (data.code === 'OTP_RESEND_COOLDOWN' && data.retry_after) {
      const wait = formatCountdown(data.retry_after)
      return resending ? `${message} (${wait})` : `A verification code was sent recently. Request a new one in ${wait}.`
    }
    return message
  }
  if (response.status === 401) return INVALID_CREDENTIALS_MESSAGE
  if (typeof data.error === 'string') return data.error
  if (Array.isArray(data.error) && typeof data.error[0]?.msg === 'string') return data.error[0].msg
  if (typeof data.detail === 'string') return data.detail
  return 'Sign-in failed. Please try again.'
}

export function otpRequiresRestart(code) {
  return RESTART_CODES.has(code)
}

export function formatCountdown(seconds) {
  const safe = Math.max(0, Math.floor(Number(seconds) || 0))
  return `${Math.floor(safe / 60)}:${String(safe % 60).padStart(2, '0')}`
}

// Countdowns are absolute deadlines taken from the server's challenge view, so re-renders don't reset them.
// The server enforces the cooldown; these only decide what the screen shows.
export function challengeDeadlines(challenge, now) {
  return {
    expiresAt: challenge?.expires_in != null ? now + challenge.expires_in * 1000 : null,
    resendAt: now + Math.max(0, Number(challenge?.resend_available_in) || 0) * 1000,
  }
}

export function retryAfterDeadline(err, now) {
  const data = err?.response?.data
  return data?.code === 'OTP_RESEND_COOLDOWN' && data.retry_after ? now + data.retry_after * 1000 : null
}

function secondsUntil(deadline, now) {
  return deadline ? Math.max(0, Math.ceil((deadline - now) / 1000)) : 0
}

export function resendState(resendAt, now) {
  const seconds = secondsUntil(resendAt, now)
  return { available: seconds === 0, seconds, label: seconds > 0 ? `Resend code in ${formatCountdown(seconds)}` : 'Resend OTP' }
}

export function expiryState(expiresAt, now) {
  const seconds = secondsUntil(expiresAt, now)
  return { expired: seconds === 0, seconds, label: seconds > 0 ? `Code expires in ${formatCountdown(seconds)}` : CODE_EXPIRED_MESSAGE }
}

export function channelLabel(channel) {
  return channel === 'SMS' ? 'Mobile (SMS)' : 'Email'
}

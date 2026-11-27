// Wording and checks for the Forgot Password flow. Countdowns reuse the OTP helpers in ./otp.js.
import { authErrorMessage } from './otp.js'

export const MIN_PASSWORD_LENGTH = 8
export const PASSWORD_RESET_REQUESTED_MESSAGE = 'If the account exists, a verification code has been sent to the registered email.'
export const PASSWORD_RESET_SUCCESS_MESSAGE = 'Password reset successfully. Please sign in with your new password.'

const MESSAGES = {
  OTP_CHALLENGE_INVALID: 'Your reset session ended. Request a new code.',
  OTP_TOO_MANY_ATTEMPTS: 'Too many attempts. Request a new code.',
  OTP_RESEND_LIMIT: 'Too many codes requested for this email. Try again later.',
  PASSWORD_RESET_INVALID: 'This password reset is no longer valid. Request a new code.',
  PASSWORD_RESET_UNAVAILABLE: 'Too many password resets are pending right now. Try again in a few minutes.',
}

const RESTART_CODES = new Set(['OTP_CHALLENGE_INVALID', 'OTP_TOO_MANY_ATTEMPTS', 'OTP_RESEND_LIMIT', 'PASSWORD_RESET_INVALID'])

export function newPasswordProblem(password, confirm) {
  if (!password) return 'Enter a new password.'
  if (password.length < MIN_PASSWORD_LENGTH) return `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`
  if (password !== confirm) return 'Passwords do not match.'
  return null
}

export function resetErrorMessage(err, { resending = false } = {}) {
  const code = err?.response?.data?.code
  return MESSAGES[code] || authErrorMessage(err, { resending })
}

export function resetRequiresRestart(err) {
  return RESTART_CODES.has(err?.response?.data?.code)
}

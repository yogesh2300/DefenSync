import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { describe, it } from 'node:test'
import { challengeDeadlines, expiryState, resendState } from '../src/auth/otp.js'
import {
  PASSWORD_RESET_REQUESTED_MESSAGE, PASSWORD_RESET_SUCCESS_MESSAGE, newPasswordProblem, resetErrorMessage, resetRequiresRestart,
} from '../src/auth/passwordReset.js'

const source = (path) => readFileSync(new URL(path, import.meta.url), 'utf8')
const apiError = (status, data) => ({ response: { status, data } })

describe('login layout', () => {
  it('"Forgot password?" sits directly below the password field, above Sign In and "No account? Create one"', () => {
    const login = source('../src/pages/Login.jsx')
    const order = ['label="Password"', 'Forgot password?', "'Sign In'", 'No account?'].map((marker) => login.indexOf(marker))
    assert.ok(order.every((index) => index > 0), `all markers present: ${order}`)
    assert.deepEqual([...order].sort((a, b) => a - b), order)
    const between = login.slice(order[0], order[1])
    assert.match(between, /<\/div>\s*\{mode === 'login' && \(\s*<div[^>]*>\s*<Link to="\/forgot-password"/)
    assert.doesNotMatch(between, /<Input|<Button/)
  })

  it('the reset page is a public route and offers the requested steps', () => {
    assert.match(source('../src/App.jsx'), /<Route path="\/forgot-password" element=\{<ForgotPassword \/>\} \/>/)
    const page = source('../src/pages/ForgotPassword.jsx')
    for (const text of ['Forgot Password', 'Enter your registered email.', 'Send Reset Code', 'Back to Login', 'Enter Verification Code',
      "Didn&apos;t receive the code?", 'Set New Password', 'New Password', 'Confirm New Password', 'Reset Password']) {
      assert.ok(page.includes(text), text)
    }
  })

  it('reset secrets never go to browser storage, the URL, or the session', () => {
    for (const file of ['../src/pages/ForgotPassword.jsx', '../src/auth/passwordReset.js']) {
      const text = source(file)
      assert.doesNotMatch(text, /localStorage|sessionStorage|useSearchParams|navigate\(/, file)
    }
    const page = source('../src/pages/ForgotPassword.jsx')
    assert.doesNotMatch(page, /verifyOtp|verifyRegistration|storeVerifiedToken|access_token/)
  })
})

describe('password reset helpers', () => {
  it('uses the generic request message and the required success message', () => {
    assert.equal(PASSWORD_RESET_REQUESTED_MESSAGE, 'If the account exists, a verification code has been sent to the registered email.')
    assert.equal(PASSWORD_RESET_SUCCESS_MESSAGE, 'Password reset successfully. Please sign in with your new password.')
  })

  it('rejects weak or mismatched new passwords before calling the server', () => {
    assert.equal(newPasswordProblem('', ''), 'Enter a new password.')
    assert.equal(newPasswordProblem('short', 'short'), 'Password must be at least 8 characters.')
    assert.equal(newPasswordProblem('New-Password-2', 'New-Password-3'), 'Passwords do not match.')
    assert.equal(newPasswordProblem('New-Password-2', 'New-Password-2'), null)
  })

  it('maps reset failures to clear messages and restarts only when the reset is gone', () => {
    assert.equal(resetErrorMessage(apiError(401, { code: 'OTP_INVALID', attempts_remaining: 3 })), 'Incorrect verification code (3 attempts left)')
    assert.equal(resetErrorMessage(apiError(401, { code: 'OTP_EXPIRED' })), 'Code expired. Request a new code.')
    assert.equal(resetErrorMessage(apiError(401, { code: 'PASSWORD_RESET_INVALID' })), 'This password reset is no longer valid. Request a new code.')
    assert.equal(resetErrorMessage(apiError(429, { code: 'OTP_RESEND_COOLDOWN', retry_after: 61 }), { resending: true }), 'Please wait before requesting another code (1:01)')
    assert.equal(resetErrorMessage(apiError(422, { error: 'Passwords do not match.' })), 'Passwords do not match.')
    for (const code of ['OTP_CHALLENGE_INVALID', 'OTP_TOO_MANY_ATTEMPTS', 'OTP_RESEND_LIMIT', 'PASSWORD_RESET_INVALID']) {
      assert.ok(resetRequiresRestart(apiError(401, { code })), code)
    }
    for (const code of ['OTP_INVALID', 'OTP_EXPIRED', 'OTP_RESEND_COOLDOWN']) assert.ok(!resetRequiresRestart(apiError(401, { code })), code)
  })

  it('the code screen counts down expiry and the 120-second resend cooldown from the server values', () => {
    const t0 = 1_760_000_000_000
    const challenge = { message: PASSWORD_RESET_REQUESTED_MESSAGE, challenge_id: 'p'.repeat(43), expires_in: 300, resend_available_in: 120, attempts_remaining: 5, sends_remaining: 2 }
    const { expiresAt, resendAt } = challengeDeadlines(challenge, t0)
    assert.equal(expiryState(expiresAt, t0 + 1000).label, 'Code expires in 4:59')
    assert.equal(resendState(resendAt, t0 + 1000).label, 'Resend code in 1:59')
    assert.equal(resendState(resendAt, t0 + 119_000).available, false)
    assert.deepEqual(resendState(resendAt, t0 + 120_000), { available: true, seconds: 0, label: 'Resend OTP' })
  })
})

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import {
  CODE_EXPIRED_MESSAGE, INVALID_CREDENTIALS_MESSAGE, SERVER_UNREACHABLE_MESSAGE, authErrorMessage, challengeDeadlines, channelLabel,
  expiryState, formatCountdown, otpErrorMessage, otpRequiresRestart, registrationStartedMessage, resendState, resentMessage,
  retryAfterDeadline,
} from '../src/auth/otp.js'

const apiError = (status, data) => ({ response: { status, data } })

describe('OTP screen helpers', () => {
  it('maps backend codes to the required safe messages', () => {
    assert.equal(otpErrorMessage('OTP_INVALID'), 'Incorrect verification code')
    assert.match(otpErrorMessage('OTP_EXPIRED'), /^Code expired/)
    assert.match(otpErrorMessage('OTP_TOO_MANY_ATTEMPTS'), /^Too many attempts/)
    assert.equal(otpErrorMessage('OTP_RESEND_COOLDOWN'), 'Please wait before requesting another code')
  })

  it('never echoes unknown backend text', () => {
    assert.equal(otpErrorMessage('something internal 123456'), 'Verification failed. Please try again.')
    assert.equal(otpErrorMessage(undefined), 'Verification failed. Please try again.')
  })

  it('sends the user back to the password step only when the challenge is gone', () => {
    for (const code of ['OTP_TOO_MANY_ATTEMPTS', 'OTP_RESEND_LIMIT', 'OTP_CHALLENGE_INVALID']) assert.ok(otpRequiresRestart(code), code)
    for (const code of ['OTP_INVALID', 'OTP_EXPIRED', 'OTP_RESEND_COOLDOWN', 'OTP_DELIVERY_FAILED', 'MFA_NOT_CONFIGURED']) {
      assert.ok(!otpRequiresRestart(code), code)
    }
  })

  it('formats countdowns as m:ss', () => {
    assert.equal(formatCountdown(300), '5:00')
    assert.equal(formatCountdown(119), '1:59')
    assert.equal(formatCountdown(61), '1:01')
    assert.equal(formatCountdown(0), '0:00')
    assert.equal(formatCountdown(-5), '0:00')
    assert.equal(formatCountdown('abc'), '0:00')
  })

  it('labels delivery channels', () => {
    assert.equal(channelLabel('EMAIL'), 'Email')
    assert.equal(channelLabel('SMS'), 'Mobile (SMS)')
  })
})

describe('sign-in error messages', () => {
  it('invalid credentials, MFA delivery unavailable, incorrect OTP and expired OTP are all distinct', () => {
    const messages = [
      authErrorMessage(apiError(401, { success: false, error: 'Invalid email or password.', type: 'AuthenticationError' })),
      authErrorMessage(apiError(503, { error: 'Two-factor verification is not configured', code: 'MFA_NOT_CONFIGURED' })),
      authErrorMessage(apiError(401, { error: 'Invalid verification code.', code: 'OTP_INVALID', attempts_remaining: 4 })),
      authErrorMessage(apiError(401, { error: 'The verification code has expired.', code: 'OTP_EXPIRED' })),
    ]
    assert.equal(new Set(messages).size, 4)
    assert.equal(messages[0], INVALID_CREDENTIALS_MESSAGE)
    assert.match(messages[1], /email delivery \(SMTP\) is not configured/)
    assert.equal(messages[2], 'Incorrect verification code (4 attempts left)')
    assert.match(messages[3], /^Code expired/)
  })

  it('a delivery failure is reported separately from missing configuration', () => {
    const failed = authErrorMessage(apiError(503, { code: 'OTP_DELIVERY_FAILED' }))
    assert.notEqual(failed, authErrorMessage(apiError(503, { code: 'MFA_NOT_CONFIGURED' })))
    assert.match(failed, /couldn't be sent/)
  })

  it('a 401 without an MFA code is a credential failure, whatever the backend text says', () => {
    assert.equal(authErrorMessage(apiError(401, { error: 'anything 123456' })), INVALID_CREDENTIALS_MESSAGE)
  })

  it('reports an unreachable backend instead of a credential error', () => {
    assert.equal(authErrorMessage(new Error('Network Error')), SERVER_UNREACHABLE_MESSAGE)
    assert.equal(authErrorMessage(undefined), SERVER_UNREACHABLE_MESSAGE)
  })

  it('registration states are distinct and never claim an account was created', () => {
    const registering = { registering: true }
    const messages = {
      started: registrationStartedMessage(),
      exists: authErrorMessage(apiError(422, { error: 'Email already exists.' }), registering),
      noDelivery: authErrorMessage(apiError(503, { code: 'MFA_NOT_CONFIGURED' }), registering),
      invalid: authErrorMessage(apiError(422, { error: 'Enter a valid email address.' }), registering),
      wrongCode: authErrorMessage(apiError(401, { code: 'OTP_INVALID', attempts_remaining: 2 }), registering),
      expired: authErrorMessage(apiError(401, { code: 'OTP_EXPIRED' }), registering),
      cooldown: authErrorMessage(apiError(429, { code: 'OTP_RESEND_COOLDOWN', retry_after: 30 }), registering),
      resendLimit: authErrorMessage(apiError(429, { code: 'OTP_RESEND_LIMIT' }), registering),
    }
    assert.equal(new Set(Object.values(messages)).size, Object.keys(messages).length)
    assert.equal(messages.started, 'Verification code sent to your registered email.')
    assert.equal(messages.noDelivery, 'Registration could not be completed because verification email delivery is not configured.')
    assert.equal(messages.exists, 'Email already exists.')
    assert.equal(messages.wrongCode, 'Incorrect verification code (2 attempts left)')
    assert.equal(messages.cooldown, 'A verification code was sent recently. Request a new one in 0:30.')
    for (const text of Object.values(messages)) assert.doesNotMatch(text, /account (was )?created/i)
    assert.notEqual(messages.noDelivery, authErrorMessage(apiError(503, { code: 'MFA_NOT_CONFIGURED' })))
    assert.match(authErrorMessage(apiError(503, { code: 'OTP_DELIVERY_FAILED' }), registering), /^Registration could not be completed/)
    assert.match(authErrorMessage(apiError(503, { code: 'REGISTRATION_UNAVAILABLE' }), registering), /Too many registrations/)
  })

  it('shows registration validation text, including FastAPI validation arrays', () => {
    assert.equal(authErrorMessage(apiError(422, { error: 'Email already exists.' })), 'Email already exists.')
    assert.equal(authErrorMessage(apiError(422, { error: [{ msg: 'String should have at least 8 characters' }] })), 'String should have at least 8 characters')
    assert.equal(authErrorMessage(apiError(500, {})), 'Sign-in failed. Please try again.')
  })
})

describe('OTP resend countdown', () => {
  const T0 = 1_760_000_000_000
  const sent = { otp_required: true, challenge_id: 'c'.repeat(43), delivery: 'EMAIL', destination: 't***@example.test', expires_in: 300, resend_available_in: 120 }
  const at = (seconds) => T0 + seconds * 1000

  it('displays the countdown from the server cooldown', () => {
    const { resendAt } = challengeDeadlines(sent, T0)
    assert.equal(resendState(resendAt, at(1)).label, 'Resend code in 1:59')
    assert.equal(resendState(resendAt, at(60.4)).label, 'Resend code in 1:00')
    assert.equal(resendState(resendAt, at(119)).label, 'Resend code in 0:01')
  })

  it('keeps resend disabled for the whole cooldown', () => {
    const { resendAt } = challengeDeadlines(sent, T0)
    for (const seconds of [0, 1, 30, 90, 119, 119.9]) assert.equal(resendState(resendAt, at(seconds)).available, false, `${seconds}s`)
  })

  it('enables Resend OTP after 120 seconds', () => {
    const { resendAt } = challengeDeadlines(sent, T0)
    assert.deepEqual(resendState(resendAt, at(120)), { available: true, seconds: 0, label: 'Resend OTP' })
    assert.equal(resendState(resendAt, at(500)).available, true)
  })

  it('a successful resend restarts the countdown and confirms the new code', () => {
    const resentAt = at(125)
    const { resendAt, expiresAt } = challengeDeadlines(sent, resentAt)
    assert.equal(resendState(resendAt, resentAt + 1000).label, 'Resend code in 1:59')
    assert.equal(expiryState(expiresAt, resentAt + 1000).label, 'Code expires in 4:59')
    assert.equal(resentMessage({ registering: true, destination: 't***@example.test' }), 'A new verification code was sent to your registered email.')
    assert.equal(resentMessage({ destination: 't***@example.test' }), 'A new verification code was sent to t***@example.test.')
  })

  it('shows the expired-code message once the code lifetime passes or the server says so', () => {
    const { expiresAt } = challengeDeadlines(sent, T0)
    assert.equal(expiryState(expiresAt, at(299)).expired, false)
    assert.deepEqual(expiryState(expiresAt, at(300)), { expired: true, seconds: 0, label: 'Code expired. Request a new code.' })
    assert.equal(authErrorMessage(apiError(401, { code: 'OTP_EXPIRED' }), { registering: true }), CODE_EXPIRED_MESSAGE)
    assert.equal(resendState(challengeDeadlines(sent, T0).resendAt, at(300)).available, true)
  })

  it('a failed resend shows a delivery error and keeps the user on the code screen', () => {
    const failed = apiError(503, { code: 'OTP_DELIVERY_FAILED' })
    assert.equal(otpRequiresRestart('OTP_DELIVERY_FAILED'), false)
    assert.equal(
      authErrorMessage(failed, { registering: true, resending: true }),
      "The new code couldn't be sent. Your registration is still pending; select Resend OTP to try again.",
    )
    assert.equal(authErrorMessage(failed, { resending: true }), "The new code couldn't be sent. Select Resend OTP to try again.")
    assert.match(authErrorMessage(failed, { registering: true }), /^Registration could not be completed/)
  })

  it('after a refresh the server cooldown still applies: the countdown follows retry_after, never a local reset', () => {
    const tooSoon = apiError(429, { code: 'OTP_RESEND_COOLDOWN', retry_after: 100 })
    assert.equal(authErrorMessage(tooSoon), 'A verification code was sent recently. Request a new one in 1:40.')
    assert.equal(authErrorMessage(tooSoon, { resending: true }), 'Please wait before requesting another code (1:40)')
    const serverResendAt = retryAfterDeadline(tooSoon, T0)
    assert.equal(serverResendAt, at(100))
    assert.equal(resendState(serverResendAt, at(99)).available, false)
    assert.equal(retryAfterDeadline(apiError(401, { code: 'OTP_INVALID' }), T0), null)
    const remembered = challengeDeadlines({ ...sent, resend_available_in: 45 }, T0)
    assert.equal(resendState(remembered.resendAt, at(1)).label, 'Resend code in 0:44')
  })
})

import assert from 'node:assert/strict'
import { beforeEach, describe, it } from 'node:test'

const store = new Map()
globalThis.localStorage = {
  getItem: (key) => (store.has(key) ? store.get(key) : null),
  setItem: (key, value) => store.set(key, String(value)),
  removeItem: (key) => store.delete(key),
}
const dispatched = []
globalThis.window = { dispatchEvent: (event) => dispatched.push(event.type) }
if (typeof globalThis.CustomEvent === 'undefined') {
  globalThis.CustomEvent = class CustomEvent extends Event {}
}

const client = await import('../src/api/client.js')
const api = client.default

let calls = []
let reply = () => ({})
api.defaults.adapter = async (config) => {
  calls.push(config)
  return { data: reply(config), status: 200, statusText: 'OK', headers: {}, config }
}

beforeEach(() => {
  calls = []
  reply = () => ({})
  store.clear()
  dispatched.length = 0
})

describe('OTP login client', () => {
  it('email + password step stores no token and returns only the challenge', async () => {
    store.set('defensync_token', 'stale')
    reply = () => ({ otp_required: true, challenge_id: 'c'.repeat(43), delivery: 'EMAIL' })
    const challenge = await client.login('alice@example.test', 'pw')
    assert.equal(challenge.otp_required, true)
    assert.equal(store.get('defensync_token'), undefined)
    assert.equal(calls[0].url, '/api/v1/auth/token')
    const form = new URLSearchParams(String(calls[0].data))
    assert.equal(form.get('email'), 'alice@example.test')
    assert.equal(form.get('username'), null)
  })

  it('verify stores the token, signals authentication, and does not return the token', async () => {
    reply = () => ({ access_token: 'jwt-value', token_type: 'bearer' })
    const result = await client.verifyOtp('c'.repeat(43), '123456')
    assert.deepEqual(result, { token_type: 'bearer' })
    assert.equal(store.get('defensync_token'), 'jwt-value')
    assert.deepEqual(dispatched, ['defensync:authenticated'])
    assert.equal(calls[0].url, '/api/v1/auth/otp/verify')
  })

  it('resend posts only the challenge and optional channel', async () => {
    await client.sendOtp('c'.repeat(43))
    await client.sendOtp('c'.repeat(43), 'EMAIL')
    assert.deepEqual(JSON.parse(calls[0].data), { challenge_id: 'c'.repeat(43) })
    assert.deepEqual(JSON.parse(calls[1].data), { challenge_id: 'c'.repeat(43), channel: 'EMAIL' })
  })
})

describe('registration client', () => {
  it('starting registration returns only the verification challenge and stores no token', async () => {
    store.set('defensync_token', 'stale')
    reply = () => ({ otp_required: true, challenge_id: 'r'.repeat(43), delivery: 'EMAIL', destination: 'a***@example.test' })
    const challenge = await client.register('alice', 'alice@example.test', 'Strong-Password-1')
    assert.equal(challenge.otp_required, true)
    assert.equal(challenge.access_token, undefined)
    assert.equal(store.get('defensync_token'), undefined)
    assert.deepEqual(dispatched, [])
    assert.equal(calls[0].url, '/api/v1/auth/register')
    assert.deepEqual(JSON.parse(calls[0].data), { username: 'alice', email: 'alice@example.test', password: 'Strong-Password-1' })
  })

  it('only the verified registration code stores a session', async () => {
    reply = () => ({ access_token: 'jwt-registered', token_type: 'bearer' })
    const result = await client.verifyRegistration('r'.repeat(43), '654321')
    assert.deepEqual(result, { token_type: 'bearer' })
    assert.equal(store.get('defensync_token'), 'jwt-registered')
    assert.deepEqual(dispatched, ['defensync:authenticated'])
    assert.equal(calls[0].url, '/api/v1/auth/register/verify')
    assert.deepEqual(JSON.parse(calls[0].data), { challenge_id: 'r'.repeat(43), otp: '654321' })
  })
})

describe('password reset client', () => {
  it('posts each step to its endpoint and never stores or signals a session', async () => {
    store.set('defensync_token', 'existing-session')
    reply = (config) => (config.url.endsWith('/verify') ? { reset_token: 't'.repeat(43), expires_in: 600 } : { success: true })
    await client.requestPasswordReset('member@example.test')
    await client.resendPasswordReset('p'.repeat(43))
    const verified = await client.verifyPasswordReset('p'.repeat(43), '123456')
    await client.completePasswordReset(verified.reset_token, 'New-Password-2', 'New-Password-2')
    assert.deepEqual(calls.map((call) => call.url), [
      '/api/v1/auth/password-reset/request',
      '/api/v1/auth/password-reset/resend',
      '/api/v1/auth/password-reset/verify',
      '/api/v1/auth/password-reset/complete',
    ])
    assert.deepEqual(JSON.parse(calls[0].data), { email: 'member@example.test' })
    assert.deepEqual(JSON.parse(calls[1].data), { challenge_id: 'p'.repeat(43) })
    assert.deepEqual(JSON.parse(calls[2].data), { challenge_id: 'p'.repeat(43), otp: '123456' })
    assert.deepEqual(JSON.parse(calls[3].data), { reset_token: 't'.repeat(43), new_password: 'New-Password-2', confirm_password: 'New-Password-2' })
    assert.equal(store.get('defensync_token'), 'existing-session')
    assert.equal(store.size, 1)
    assert.deepEqual(dispatched, [])
  })
})

describe('cloud source client', () => {
  it('sends the client secret only in request bodies and stores nothing', async () => {
    store.set('defensync_token', 'jwt-value')
    const credentials = {
      provider: 'AZURE', source_type: 'AZURE_LOG_ANALYTICS', tenant_id: 't', client_id: 'c', client_secret: 'browser-secret', workspace_id: 'w',
    }
    reply = (config) => (config.url === '/api/v1/cloud/sources' && config.method === 'get' ? { sources: [], count: 0 } : { id: 'src/1' })
    assert.deepEqual(await client.getCloudSources(), { sources: [], count: 0 })
    await client.testCloudConnection(credentials)
    await client.createCloudSource(credentials)
    await client.getCloudSource('src/1')
    await client.testCloudSource('src/1')
    await client.collectCloudSource('src/1', { lookback_minutes: 15 })
    await client.deleteCloudSource('src/1')
    assert.deepEqual(calls.map((call) => `${call.method} ${call.url}`), [
      'get /api/v1/cloud/sources',
      'post /api/v1/cloud/sources/test-connection',
      'post /api/v1/cloud/sources',
      'get /api/v1/cloud/sources/src%2F1',
      'post /api/v1/cloud/sources/src%2F1/test-connection',
      'post /api/v1/cloud/sources/src%2F1/collect',
      'delete /api/v1/cloud/sources/src%2F1',
    ])
    assert.deepEqual(JSON.parse(calls[1].data), credentials)
    assert.deepEqual(JSON.parse(calls[2].data), credentials)
    for (const call of calls) {
      assert.ok(!call.url.includes('browser-secret'))
      assert.equal(call.params, undefined)
    }
    assert.deepEqual([...store.keys()], ['defensync_token'])
    assert.deepEqual(dispatched, ['defensync:data-refresh'])
  })
})

describe('environment-filtered API calls', () => {
  it('U: events carry the selected environment', async () => {
    await client.getEvents({ limit: 10, environment: 'CLOUD' })
    assert.equal(calls[0].url, '/api/v1/events')
    assert.equal(calls[0].params.environment, 'CLOUD')
  })

  it('V: alerts carry the selected environment', async () => {
    await client.getAlerts({ limit: 10, environment: 'LINUX' })
    assert.equal(calls[0].url, '/api/v1/alerts')
    assert.equal(calls[0].params.environment, 'LINUX')
  })

  it('W: incidents and behavior history carry the selected environment', async () => {
    await client.getIncidents(12, 'CLOUD')
    await client.getBehaviorHistory(null, 'LINUX')
    assert.deepEqual(calls[0].params, { limit: 12, environment: 'CLOUD' })
    assert.equal(calls[1].params.environment, 'LINUX')
  })

  it('X: dashboard aggregates and account summary follow the environment', async () => {
    await client.getDashboardSummary(null, 'CLOUD')
    await client.getEventStats(null, 'CLOUD')
    await client.getAlertSummary(null, 'CLOUD')
    await client.getRecentEvents(10, null, 'CLOUD')
    await client.getAccountSummary(null, null, 'CLOUD')
    for (const call of calls) assert.equal(call.params.environment, 'CLOUD', call.url)
    for (const call of calls) assert.equal(call.params.server_id, undefined, call.url)
  })

  it('the bearer token is attached only after OTP verification', async () => {
    await client.getEvents({})
    assert.equal(calls[0].headers.Authorization, undefined)
    reply = () => ({ access_token: 'jwt-value', token_type: 'bearer' })
    await client.verifyOtp('c'.repeat(43), '123456')
    reply = () => ([])
    await client.getEvents({})
    assert.equal(calls[2].headers.Authorization, 'Bearer jwt-value')
  })
})

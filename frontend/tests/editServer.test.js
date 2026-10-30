import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { describe, it } from 'node:test'
import {
  CHANGED_SETTINGS_NEED_SECRET, USERNAME_NEEDS_SECRET, apiErrorMessage, buildUpdatePayload, planConnectionTest,
} from '../src/servers/editServer.js'

const saved = {
  server_name: 'Yogesh Server', host: '192.0.2.10', port: 22, username: 'ysalve', authentication_type: 'password',
  operating_system: 'linux', environment: 'production', description: '', status: 'active',
}
const KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nunit-test-placeholder\n-----END OPENSSH PRIVATE KEY-----'

describe('Edit Server connection test never saves', () => {
  it('new credentials are tested through the test-before-save request', () => {
    const form = { ...saved, username: 'defensync', authentication_type: 'ssh_key' }
    const plan = planConnectionTest(saved, form, { password: '', privateKey: KEY })
    assert.equal(plan.mode, 'preview')
    assert.deepEqual(plan.request, {
      host: '192.0.2.10', port: 22, username: 'defensync', authentication_type: 'ssh_key', private_key: KEY,
    })
  })

  it('only the secret for the selected authentication type is used', () => {
    const plan = planConnectionTest(saved, saved, { password: 'pw', privateKey: KEY })
    assert.equal(plan.request.password, 'pw')
    assert.equal('private_key' in plan.request, false)
  })

  it('unchanged settings without a new secret test the saved server', () => {
    assert.deepEqual(planConnectionTest(saved, { ...saved, description: 'edited' }, {}), { mode: 'stored' })
  })

  it('changed connection settings without a secret are not tested against old credentials', () => {
    for (const change of [{ username: 'defensync' }, { host: '192.0.2.11' }, { port: 2222 }, { authentication_type: 'ssh_key' }]) {
      assert.deepEqual(planConnectionTest(saved, { ...saved, ...change }, {}), { mode: 'blocked', reason: CHANGED_SETTINGS_NEED_SECRET })
    }
  })

  it('the page uses the preview endpoint and no longer saves before testing', () => {
    const page = readFileSync(new URL('../src/pages/EditServer.jsx', import.meta.url), 'utf8')
    const handleTest = page.slice(page.indexOf('const handleTest'), page.indexOf('const handleSave'))
    assert.match(handleTest, /testServerCredentials\(plan\.request\)/)
    assert.doesNotMatch(handleTest, /updateServer/)
  })
})

describe('Edit Server save', () => {
  it('rejects a username change without a new secret', () => {
    assert.deepEqual(buildUpdatePayload(saved, { ...saved, username: 'defensync' }, {}), { error: USERNAME_NEEDS_SECRET })
  })

  it('sends the new key with a username change', () => {
    const form = { ...saved, username: ' defensync ', authentication_type: 'ssh_key' }
    const { payload } = buildUpdatePayload(saved, form, { password: 'ignored', privateKey: KEY })
    assert.equal(payload.username, 'defensync')
    assert.equal(payload.private_key, KEY)
    assert.equal('password' in payload, false)
  })

  it('other edits keep the stored secret', () => {
    const { payload } = buildUpdatePayload(saved, { ...saved, server_name: 'Renamed' }, {})
    assert.equal(payload.server_name, 'Renamed')
    assert.equal('password' in payload || 'private_key' in payload, false)
  })

  it('backend validation messages are shown', () => {
    assert.equal(apiErrorMessage({ response: { data: { error: USERNAME_NEEDS_SECRET } } }, 'Update failed'), USERNAME_NEEDS_SECRET)
    assert.equal(apiErrorMessage({ response: { data: { error: [{ msg: 'x' }] } } }, 'Update failed'), 'Update failed')
    assert.equal(apiErrorMessage(new Error('network'), 'Test failed'), 'Test failed')
  })
})

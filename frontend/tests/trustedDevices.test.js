import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { describe, it } from 'node:test'
import { formatDeviceTime, slotsLabel, slotsRatio } from '../src/auth/trustedDevice.js'

const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), 'utf8')

describe('trusted device UI helpers', () => {
  it('formats slot usage for the limit banner', () => {
    assert.equal(slotsLabel(2, 3), '2 of 3 trusted devices')
    assert.equal(slotsLabel(0, 3), '0 of 3 trusted devices')
    assert.equal(slotsLabel(3, 3), '3 of 3 trusted devices')
    assert.equal(slotsRatio(2, 3), '2 / 3')
    assert.equal(slotsRatio(0, 3), '0 / 3')
  })

  it('formats last-seen times without inventing values', () => {
    assert.equal(formatDeviceTime(null), 'Never')
    assert.equal(formatDeviceTime('not-a-date'), '—')
    assert.match(formatDeviceTime('2026-10-29T08:00:00.000Z'), /2026|29/)
  })

  it('Trusted Devices page covers loading, empty, limit, revoke, and session notice', () => {
    const page = source('pages/TrustedDevices.jsx')
    assert.match(page, /listTrustedDevices/)
    assert.match(page, /data-trusted-device-slots/)
    assert.match(page, /data-trusted-devices-empty/)
    assert.match(page, /data-session-revocation-notice/)
    assert.match(page, /slotsRatio/)
    assert.match(page, /Limit reached/)
    assert.match(page, /TRUSTED_DEVICE_LIMIT_EXCEEDED/)
    assert.match(page, /Revoke/)
    assert.match(page, /REVOKE_CONFIRM/)
    assert.match(page, /Trust this browser/)
    assert.match(page, /beginTrustedDeviceEnroll/)
    assert.match(page, /completeTrustedDeviceEnroll/)
    assert.match(page, /completeTrustedDeviceVerify/)
    assert.match(page, /device-bound session token/)
    assert.match(page, /MFA-only sessions without a device binding/)
    assert.match(page, /Created \{formatDeviceTime\(device\.created_at\)\}/)
    assert.match(page, /Last seen \{formatDeviceTime\(device\.last_seen_at\)\}/)
    assert.doesNotMatch(page, /fake device|hardcoded.*3 of 3/i)
    assert.doesNotMatch(page, /console\.log\([^)]*(token|key|challenge|signature)/i)
    assert.doesNotMatch(page, />\s*\{[^}]*(access_token|privateKey|signature|challenge)\s*\}/)
    assert.doesNotMatch(page, /terminates every session|logs you out immediately/i)
  })

  it('wires API client, menu route, and admin controls without claiming fingerprint identity', () => {
    const client = source('api/client.js')
    const cryptoHelper = source('auth/trustedDevice.js')
    const app = source('App.jsx')
    const layout = source('components/Layout.jsx')
    const admin = source('pages/admin/AdminUserDetail.jsx')
    assert.match(client, /\/api\/v1\/auth\/trusted-devices/)
    assert.match(client, /enroll\/begin/)
    assert.match(client, /verify\/complete/)
    assert.match(client, /storeVerifiedToken\(data\)/)
    assert.match(cryptoHelper, /ECDSA/)
    assert.match(cryptoHelper, /never treated as device identity/i)
    assert.match(app, /path="trusted-devices"/)
    assert.match(layout, /Trusted Devices/)
    assert.equal((layout.match(/Trusted Devices/g) || []).length, 1)
    assert.match(admin, /getAdminUserTrustedDevices/)
    assert.match(admin, /setAdminUserDeviceLimit/)
    assert.match(admin, /data-admin-trusted-device-slots/)
    assert.match(admin, /Trusted devices: \$\{devices\.active_count\} \/ \$\{devices\.device_limit\}/)
  })
})

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { describe, it } from 'node:test'
import {
  accountIdForSummaryRequest,
  pickScoreSource,
  resolvePrimarySecurityScore,
} from '../src/intelligence/primaryScore.js'

const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), 'utf8')

const platformDashboard = {
  total_events: 200,
  average_risk_score: 55,
  environment: 'LINUX',
}

const selectedAccount = {
  account_id: 'acct-a',
  account_name: 'Tenant A',
  events: 45,
  average_risk_score: 40,
  environment: 'LINUX',
  scope: 'account',
}

const otherAccount = {
  account_id: 'acct-b',
  events: 90,
  average_risk_score: 70,
  environment: 'LINUX',
  scope: 'account',
}

describe('admin account scope for primary score', () => {
  it('only admins may request a foreign account_id for getAccountSummary', () => {
    assert.equal(accountIdForSummaryRequest({ isAdmin: false, selectedAccountId: 'acct-a' }), null)
    assert.equal(accountIdForSummaryRequest({ isAdmin: true, selectedAccountId: '' }), null)
    assert.equal(accountIdForSummaryRequest({ isAdmin: true, selectedAccountId: null }), null)
    assert.equal(accountIdForSummaryRequest({ isAdmin: true, selectedAccountId: 'acct-a' }), 'acct-a')
  })

  it('uses the selected account summary and ignores platform dashboard averages', () => {
    const picked = pickScoreSource(platformDashboard, selectedAccount, {
      isAdmin: true,
      selectedAccountId: 'acct-a',
      expectedEnvironment: 'LINUX',
    })
    assert.equal(picked, selectedAccount)
    const resolved = resolvePrimarySecurityScore({
      summary: platformDashboard,
      accountSummary: selectedAccount,
      loaded: true,
      isAdmin: true,
      selectedAccountId: 'acct-a',
      expectedEnvironment: 'LINUX',
    })
    assert.equal(resolved.available, true)
    assert.equal(resolved.score, 40)
    assert.equal(resolved.accountId, 'acct-a')
  })

  it('does not fall back to a different account or platform score when selection is set', () => {
    const mismatch = resolvePrimarySecurityScore({
      summary: platformDashboard,
      accountSummary: otherAccount,
      loaded: true,
      isAdmin: true,
      selectedAccountId: 'acct-a',
      expectedEnvironment: 'LINUX',
    })
    assert.equal(mismatch.available, false)
    assert.match(mismatch.reason, /does not match the selected account/i)

    const missing = resolvePrimarySecurityScore({
      summary: platformDashboard,
      accountSummary: null,
      loaded: true,
      isAdmin: true,
      selectedAccountId: 'acct-a',
      expectedEnvironment: 'LINUX',
    })
    assert.equal(missing.available, false)
    assert.match(missing.reason, /selected account/i)
    assert.notEqual(missing.score, 55)
  })

  it('rejects environment-mismatched account summaries', () => {
    const cloudSummary = { ...selectedAccount, environment: 'CLOUD' }
    const resolved = resolvePrimarySecurityScore({
      summary: platformDashboard,
      accountSummary: cloudSummary,
      loaded: true,
      isAdmin: true,
      selectedAccountId: 'acct-a',
      expectedEnvironment: 'LINUX',
    })
    assert.equal(resolved.available, false)
    assert.match(resolved.reason, /environment/i)
  })

  it('keeps ordinary users on dashboard/account fallback without foreign account_id', () => {
    assert.equal(accountIdForSummaryRequest({ isAdmin: false, selectedAccountId: 'acct-a' }), null)
    const own = {
      account_id: 'own-1',
      events: 12,
      average_risk_score: 33,
      environment: 'LINUX',
      scope: 'account',
    }
    const resolved = resolvePrimarySecurityScore({
      summary: { total_events: 0, average_risk_score: 0, environment: 'LINUX' },
      accountSummary: own,
      loaded: true,
      isAdmin: false,
      selectedAccountId: 'acct-a',
      expectedEnvironment: 'LINUX',
    })
    assert.equal(resolved.available, true)
    assert.equal(resolved.score, 33)
  })

  it('admin platform overview does not silently use a tenant-specific account summary', () => {
    const picked = pickScoreSource(platformDashboard, selectedAccount, {
      isAdmin: true,
      selectedAccountId: '',
      expectedEnvironment: 'LINUX',
    })
    assert.equal(picked, platformDashboard)
    const noDashboard = pickScoreSource(
      { total_events: 0, average_risk_score: 0, environment: 'LINUX' },
      selectedAccount,
      { isAdmin: true, selectedAccountId: '', expectedEnvironment: 'LINUX' },
    )
    assert.equal(noDashboard, null)
  })

  it('wires Dashboard and Intelligence to the same authorized account summary path', () => {
    const dashboard = source('pages/Dashboard.jsx')
    const intelligence = source('pages/Intelligence.jsx')
    assert.match(dashboard, /accountIdForSummaryRequest\(\{ isAdmin, selectedAccountId: adminAccountId \}\)/)
    assert.match(dashboard, /getAccountSummary\(serverId, summaryAccountId, environment\)/)
    assert.match(dashboard, /selectedAccountId=\{adminAccountId\}/)
    assert.match(dashboard, /data-admin-account-scope/)
    assert.match(intelligence, /accountIdForSummaryRequest\(\{ isAdmin, selectedAccountId: adminAccountId \}\)/)
    assert.match(intelligence, /getAccountSummary\(serverId, summaryAccountId, environment\)/)
    assert.match(intelligence, /getDashboardSummary\(serverId, environment\)/)
    assert.match(intelligence, /data-admin-account-scope/)
    assert.match(intelligence, /selectedAccountId: adminAccountId/)
    assert.match(intelligence, /expectedEnvironment: environment/)
    assert.doesNotMatch(intelligence, /getAccountSummary\(serverId, null, environment\)/)
  })
})

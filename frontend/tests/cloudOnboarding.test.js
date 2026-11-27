import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { describe, it } from 'node:test'
import {
  ADD_CLOUD_SOURCE_PATH, ADD_SERVER_PATH, CLOUD, ENVIRONMENT_SELECT_PATH, LINUX, addScreenExitPath, adminConsoleLink,
  adminConsoleRedirect, environmentEntryPath, isAddScreen, isRouteAllowed, navForEnvironment, postAuthPath,
  switchTargetPath, workspaceRedirect, workspaceResources,
} from '../src/environment.js'
import {
  EMPTY_SOURCE_FORM, azureStatusLabel, canAddSource, cloudErrorMessage, collectionRunAlert, collectionRunSummary, connectionLabel,
  lastCollectionLabel, sourceFormProblems, testResultMessage, toSourcePayload,
} from '../src/cloud/cloudSource.js'

const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), 'utf8')
const admin = { username: 'admin', role: 'ADMIN' }
const analyst = { username: 'analyst', role: 'ANALYST' }
const validForm = {
  ...EMPTY_SOURCE_FORM,
  tenant_id: '11111111-2222-3333-4444-555555555555',
  client_id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
  client_secret: 'form-secret-value',
  workspace_id: '99999999-8888-7777-6666-555555555555',
}

const between = (text, start, end) => text.slice(text.indexOf(start), text.indexOf(end, text.indexOf(start)))

describe('environment dashboards and Add actions', () => {
  it('choosing an environment always opens its dashboard (a push, so Back returns to the selection)', () => {
    assert.equal(environmentEntryPath(LINUX), '/dashboard')
    assert.equal(environmentEntryPath(CLOUD), '/dashboard')
    const select = source('pages/EnvironmentSelect.jsx')
    assert.match(select, /navigate\(environmentEntryPath\(value\)\)/)
    assert.doesNotMatch(select, /replace: true|getServers|getCloudSources/)
  })

  it('1: Linux with zero servers shows the empty state with Add Server', () => {
    const linux = workspaceResources(LINUX, [])
    assert.deepEqual(
      [linux.empty, linux.count, linux.emptyTitle, linux.addLabel, linux.addPath],
      [true, 0, 'No Linux servers configured', 'Add Server', ADD_SERVER_PATH],
    )
    assert.equal(ADD_SERVER_PATH, '/servers/new')
  })

  it('2: Linux with servers shows the normal dashboard with the server count', () => {
    const linux = workspaceResources(LINUX, [{ id: 's1' }, { id: 's2' }])
    assert.deepEqual([linux.empty, linux.label, linux.resourceLabel, linux.count], [false, 'Linux', 'Servers', 2])
  })

  it('3 and 6: the dashboard always renders the Add button, empty or not', () => {
    const dashboard = source('pages/Dashboard.jsx')
    assert.match(dashboard, /<WorkspaceResources environment={environment} listing={isLinux \? servers : cloudSources} \/>/)
    const component = between(dashboard, 'function WorkspaceResources', 'function CloudAccountPanel')
    const emptyBranch = between(component, 'if (info.empty)', '  return (\n    <div')
    const fullBranch = component.slice(component.lastIndexOf('return ('))
    assert.match(emptyBranch, /{info\.emptyTitle}/)
    assert.match(emptyBranch, /{addButton}/)
    assert.match(fullBranch, /{info\.label} · {info\.resourceLabel}: {info\.count}/)
    assert.match(fullBranch, /{addButton}/)
    assert.match(component, /navigate\(info\.addPath, { replace: true }\)/)
  })

  it('4: Cloud with zero sources shows the empty state with Add Cloud Account', () => {
    const cloud = workspaceResources(CLOUD, { sources: [], count: 0 })
    assert.deepEqual(
      [cloud.empty, cloud.emptyTitle, cloud.addLabel, cloud.addPath],
      [true, 'No Cloud Accounts configured', 'Add Cloud Account', ADD_CLOUD_SOURCE_PATH],
    )
    assert.equal(workspaceResources(CLOUD, null).empty, true)
    assert.equal(ADD_CLOUD_SOURCE_PATH, '/cloud-accounts/new')
  })

  it('5: Cloud with sources shows the normal dashboard with the account count', () => {
    const cloud = workspaceResources(CLOUD, [{ id: 'c1' }])
    assert.deepEqual([cloud.empty, cloud.label, cloud.resourceLabel, cloud.count], [false, 'Cloud', 'Cloud Accounts', 1])
  })

  it('the Cloud Accounts page also offers Add Cloud Account and an empty state', () => {
    const page = source('pages/CloudAccounts.jsx')
    assert.match(page, /No Cloud Accounts configured/)
    assert.match(page, /navigate\(ADD_CLOUD_SOURCE_PATH\)/)
  })
})

describe('Add screen exits', () => {
  it('only the two Add routes are Add screens', () => {
    assert.ok(isAddScreen(ADD_SERVER_PATH) && isAddScreen(ADD_CLOUD_SOURCE_PATH))
    assert.ok(!isAddScreen('/servers') && !isAddScreen('/cloud-accounts') && !isAddScreen('/dashboard'))
  })

  it('7: Linux Add Server Cancel returns to Environment Selection', () => {
    assert.equal(addScreenExitPath('cancelled'), ENVIRONMENT_SELECT_PATH)
    assert.equal(ENVIRONMENT_SELECT_PATH, '/environment')
    const servers = source('pages/Servers.jsx')
    assert.match(servers, /if \(isAddScreen\(location\.pathname\)\) navigate\(addScreenExitPath\('cancelled'\), { replace: true }\)/)
  })

  it('8: Cloud Add Cloud Account Cancel returns to Environment Selection', () => {
    // Normalize newlines so the source scrape is stable on Windows (CRLF) checkouts.
    const page = source('pages/CloudAccounts.jsx').replace(/\r\n/g, '\n')
    const closeForm = between(page, 'const closeForm', 'const handleCreated')
    assert.match(closeForm, /if \(onAddRoute\) navigate\(addScreenExitPath\('cancelled'\), { replace: true }\)/)
    const addScreen = between(page, 'if (onAddRoute) {\n    return', 'if (loading')
    assert.match(addScreen, /onCancel={closeForm}/)
  })

  it('9: successful Linux server creation opens the Linux dashboard', () => {
    assert.equal(addScreenExitPath('created'), '/dashboard')
    const create = between(source('pages/Servers.jsx'), 'const handleCreate', 'const runAction')
    assert.match(create, /if \(isAddScreen\(location\.pathname\)\) {\s+navigate\(addScreenExitPath\('created'\), { replace: true }\)/)
  })

  it('10: successful Cloud source creation opens the Cloud dashboard', () => {
    const created = between(source('pages/CloudAccounts.jsx'), 'const handleCreated', 'const runAction')
    assert.match(created, /if \(onAddRoute\) {\s+navigate\(addScreenExitPath\('created'\), { replace: true }\)/)
  })
})

describe('route guards and environment switching', () => {
  it('11: Linux routes, including Add Server, are unavailable from Cloud', () => {
    for (const path of ['/servers', ADD_SERVER_PATH, '/servers/abc', '/collection']) {
      assert.ok(!isRouteAllowed(path, CLOUD), path)
      assert.equal(workspaceRedirect(analyst, CLOUD, path), '/dashboard', path)
    }
  })

  it('12: Cloud routes, including Add Cloud Account, are unavailable from Linux', () => {
    for (const path of ['/cloud-accounts', ADD_CLOUD_SOURCE_PATH]) {
      assert.ok(!isRouteAllowed(path, LINUX), path)
      assert.equal(workspaceRedirect(analyst, LINUX, path), '/dashboard', path)
    }
  })

  it('the Add screens open with zero resources (no resource-count guard)', () => {
    assert.equal(workspaceRedirect(analyst, LINUX, ADD_SERVER_PATH), null)
    assert.equal(workspaceRedirect(analyst, CLOUD, ADD_CLOUD_SOURCE_PATH), null)
    const app = source('App.jsx')
    assert.match(app, /path="servers\/new" element={<Servers \/>}/)
    assert.match(app, /path="cloud-accounts\/new" element={<CloudAccounts \/>}/)
  })

  it('13: the LINUX/CLOUD switch is the single environment control in the workspace', () => {
    assert.equal(switchTargetPath(ADD_SERVER_PATH, CLOUD), '/dashboard')
    assert.equal(switchTargetPath('/events', CLOUD), '/events')
    const layout = source('components/Layout.jsx')
    assert.match(layout, /<EnvironmentSwitch environment={environment} onChange={handleEnvironmentChange}/)
    assert.match(layout, /setEnvironment\(next\)/)
    assert.doesNotMatch(layout, /Switch Environment|ENVIRONMENT_SELECT_PATH/)
  })

  it('the Cloud header shows the real Azure connection state, not a static label', () => {
    assert.equal(azureStatusLabel(null), 'Azure')
    assert.equal(azureStatusLabel({ sources: [], count: 0 }), 'Azure · Not connected')
    assert.equal(azureStatusLabel({ sources: [{ connection_status: 'FAILED' }] }), 'Azure · Not connected')
    assert.equal(azureStatusLabel({ sources: [{ connection_status: 'FAILED' }, { connection_status: 'CONNECTED' }] }), 'Azure · Connected')
    const layout = source('components/Layout.jsx')
    assert.match(layout, /{azureStatusLabel\(cloudSources\)}/)
    assert.doesNotMatch(layout, /Azure · read-only/)
  })

  it('navigation matches the specified Linux and Cloud workspaces', () => {
    assert.deepEqual(navForEnvironment(LINUX).map((item) => item.label), ['Dashboard', 'Servers', 'Events', 'Alerts', 'DefenSync Intelligence'])
    assert.deepEqual(navForEnvironment(CLOUD).map((item) => item.label), ['Dashboard', 'Cloud Accounts', 'Events', 'Alerts', 'DefenSync Intelligence'])
  })
})

describe('environment selection is session-scoped', () => {
  it('is held in sessionStorage only and cleared on logout and on a new sign-in', () => {
    const context = source('context/EnvironmentContext.jsx')
    assert.match(context, /sessionStorage\.setItem\(ENVIRONMENT_STORAGE_KEY/)
    assert.doesNotMatch(context, /localStorage/)
    assert.match(context, /addEventListener\('defensync:logout', clearEnvironment\)/)
    assert.match(context, /addEventListener\('defensync:authenticated', clearEnvironment\)/)
  })
})

describe('14: admin routing stays compatible', () => {
  it('admins choose an environment, use both workspaces and Add screens, and keep the admin console', () => {
    assert.equal(postAuthPath(admin, null), '/environment')
    assert.equal(workspaceRedirect(admin, LINUX, ADD_SERVER_PATH), null)
    assert.equal(workspaceRedirect(admin, CLOUD, ADD_CLOUD_SOURCE_PATH), null)
    assert.equal(workspaceRedirect(admin, LINUX, ADD_CLOUD_SOURCE_PATH), '/dashboard')
    assert.equal(workspaceRedirect(admin, CLOUD, ADD_SERVER_PATH), '/dashboard')
    assert.equal(adminConsoleRedirect(admin, CLOUD), null)
    assert.equal(adminConsoleLink(admin), '/admin/dashboard')
    assert.match(source('App.jsx'), /path="cloud-accounts" element={<CloudAccounts admin \/>}/)
  })
})

describe('Add Cloud Source form rules', () => {
  it('requires every field and GUID-shaped identifiers', () => {
    assert.deepEqual(Object.keys(sourceFormProblems(EMPTY_SOURCE_FORM)).sort(), ['client_id', 'client_secret', 'tenant_id', 'workspace_id'])
    assert.deepEqual(sourceFormProblems(validForm), {})
    assert.deepEqual(sourceFormProblems({ ...validForm, tenant_id: 'contoso.onmicrosoft.com' }), {})
    assert.ok(sourceFormProblems({ ...validForm, workspace_id: 'my-workspace' }).workspace_id)
    assert.ok(sourceFormProblems({ ...validForm, client_id: 'app-name' }).client_id)
  })

  it('Add Cloud Source is only possible after a successful Test Connection', () => {
    assert.equal(canAddSource(validForm, null), false)
    assert.equal(canAddSource(validForm, { success: false, error: { code: 'INVALID_CREDENTIALS' } }), false)
    assert.equal(canAddSource(validForm, { success: true }), true)
    assert.equal(canAddSource(validForm, { success: true }, { busy: true }), false)
    assert.equal(canAddSource({ ...validForm, client_secret: '' }, { success: true }), false)
  })

  it('never claims a connection that was not verified', () => {
    assert.equal(connectionLabel('CONNECTED'), 'Connected')
    assert.equal(connectionLabel('FAILED'), 'Connection failed')
    assert.equal(connectionLabel(undefined), 'Not tested')
    assert.equal(testResultMessage(null), '')
    assert.match(testResultMessage({ success: true }), /successful/)
    assert.equal(testResultMessage({ success: false, error: { message: 'Azure rejected the credentials.' } }), 'Azure rejected the credentials.')
    const form = source('components/cloud/AddCloudSourceForm.jsx')
    assert.match(form, /disabled={!canAddSource\(form, testResult, { busy }\)}/)
    assert.match(form, /setTestResult\(null\)/)
  })

  it('a new source shows Last collection: Never', () => {
    assert.equal(lastCollectionLabel({ last_successful_collection: null }), 'Never')
    assert.equal(lastCollectionLabel({ last_successful_collection: '2026-10-05T07:00:00+00:00' }, () => 'formatted'), 'formatted')
  })

  it('the latest collection run shows its outcome, row counts and any failure', () => {
    assert.equal(collectionRunSummary(null), 'No collection runs yet')
    const partial = { status: 'PARTIAL', rows_retrieved: 12, rows_stored: 9, rows_duplicate: 3, error: { code: 'SOURCE_NOT_AVAILABLE', message: 'AZURE_ACTIVITY: table missing' } }
    assert.equal(collectionRunSummary(partial), 'PARTIAL · retrieved 12 · stored 9 · duplicates 3')
    assert.deepEqual(collectionRunAlert(partial), { type: 'warning', message: 'AZURE_ACTIVITY: table missing' })
    assert.equal(collectionRunAlert({ ...partial, status: 'FAILED' }).type, 'error')
    assert.equal(collectionRunAlert({ status: 'SUCCESS', error: null }), null)
    const page = source('pages/CloudAccounts.jsx')
    assert.match(page, /collectionRunSummary\(source\.last_collection_run\)/)
  })

  it('payloads are trimmed and only admins attach an account', () => {
    const payload = toSourcePayload({ ...validForm, tenant_id: ` ${validForm.tenant_id} ` })
    assert.equal(payload.tenant_id, validForm.tenant_id)
    assert.equal(payload.account_id, undefined)
    assert.equal(toSourcePayload(validForm, { accountId: 'acct-b' }).account_id, 'acct-b')
  })

  it('surfaces safe server messages', () => {
    assert.equal(cloudErrorMessage({ response: { data: { error: 'x', azure_error: { message: 'Tenant not found.' } } } }), 'Tenant not found.')
    assert.equal(cloudErrorMessage({ response: { data: { error: 'Required: Client Secret.' } } }), 'Required: Client Secret.')
    assert.equal(cloudErrorMessage({}, 'fallback'), 'fallback')
  })
})

describe('11: the client secret stays out of the browser', () => {
  it('the secret input is masked and the form never persists or logs it', () => {
    const form = source('components/cloud/AddCloudSourceForm.jsx')
    assert.match(form, /type={secret \? 'password' : 'text'}/)
    assert.match(form, /setForm\({ \.\.\.EMPTY_SOURCE_FORM }\)/)
    for (const file of ['components/cloud/AddCloudSourceForm.jsx', 'pages/CloudAccounts.jsx', 'cloud/cloudSource.js']) {
      const text = source(file)
      assert.doesNotMatch(text, /localStorage|sessionStorage|console\.|searchParams|URLSearchParams/, file)
    }
  })

  it('the source card never renders a secret value', () => {
    const page = source('pages/CloudAccounts.jsx')
    assert.match(page, /client_secret_configured \? 'Stored encrypted' : 'Not set'/)
    assert.doesNotMatch(page, /source\.client_secret[^_]/)
  })
})

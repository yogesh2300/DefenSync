import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import {
  ADMIN_CONSOLE_PATH, CLOUD, LINUX, NAV_ITEMS, adminConsoleLink, adminConsoleRedirect, isAdminUser,
  environmentEntryPath, isEnvironment, isRouteAllowed, navForEnvironment, postAuthPath, routeEnvironment,
  switchTargetPath, withEnvironmentParam, workspaceRedirect, workspaceResources,
} from '../src/environment.js'

const analyst = { username: 'analyst', role: 'ANALYST' }
const admin = { username: 'admin', role: 'ADMIN' }
const paths = (items) => items.map((item) => item.to)

describe('environment selection and onboarding', () => {
  it('L: choosing Linux opens the Linux dashboard, whose empty state offers Add Server', () => {
    assert.equal(environmentEntryPath(LINUX), '/dashboard')
    assert.equal(workspaceResources(LINUX, []).addPath, '/servers/new')
  })

  it('M: Cloud never offers the Linux server form', () => {
    assert.equal(workspaceResources(CLOUD, { sources: [] }).addPath, '/cloud-accounts/new')
    assert.notEqual(workspaceResources(CLOUD, { sources: [{ id: 'c1' }] }).addPath, '/servers/new')
  })

  it('N: choosing Cloud opens the Cloud dashboard', () => {
    assert.equal(environmentEntryPath(CLOUD), '/dashboard')
  })

  it('O: after OTP a user without an environment must choose one', () => {
    assert.equal(postAuthPath(analyst, null), '/environment')
    assert.equal(postAuthPath(analyst, 'HPC'), '/environment')
    assert.equal(postAuthPath(analyst, LINUX), '/dashboard')
    assert.equal(postAuthPath(null, LINUX), '/login')
  })

  it('P: Linux with registered servers goes to the dashboard, not the add-server form', () => {
    assert.equal(workspaceResources(LINUX, [{ id: 's1' }]).empty, false)
    assert.equal(environmentEntryPath(undefined), '/environment')
  })

  it('only LINUX and CLOUD are selectable workspaces', () => {
    assert.ok(isEnvironment(LINUX) && isEnvironment(CLOUD))
    assert.ok(!isEnvironment('HPC') && !isEnvironment('') && !isEnvironment(undefined) && !isEnvironment('linux'))
  })
})

describe('admin post-MFA flow', () => {
  it('admin password + OTP lands on the environment selection, not the admin console', () => {
    assert.equal(postAuthPath(admin, null), '/environment')
    assert.equal(workspaceRedirect(admin, null, '/dashboard'), '/environment')
    assert.notEqual(postAuthPath(admin, null), ADMIN_CONSOLE_PATH)
  })

  it('admin selecting Linux gets the Linux workspace only', () => {
    assert.equal(postAuthPath(admin, LINUX), '/dashboard')
    for (const path of ['/dashboard', '/servers', '/servers/new', '/collection', '/events', '/intelligence']) {
      assert.equal(workspaceRedirect(admin, LINUX, path), null, path)
    }
    assert.equal(workspaceRedirect(admin, LINUX, '/cloud-accounts'), '/dashboard')
    const nav = paths(navForEnvironment(LINUX, { isAdmin: true }))
    assert.deepEqual(nav, ['/dashboard', '/servers', '/events', '/alerts', '/intelligence', '/collection'])
  })

  it('admin selecting Cloud gets the Cloud workspace only', () => {
    assert.equal(postAuthPath(admin, CLOUD), '/dashboard')
    assert.equal(workspaceRedirect(admin, CLOUD, '/cloud-accounts'), null)
    for (const path of ['/servers', '/servers/new', '/collection']) {
      assert.equal(workspaceRedirect(admin, CLOUD, path), '/dashboard', path)
    }
    assert.deepEqual(paths(navForEnvironment(CLOUD, { isAdmin: true })), ['/dashboard', '/cloud-accounts', '/events', '/alerts', '/intelligence'])
  })

  it('admin keeps the admin console; analysts are sent back to their workspace', () => {
    assert.equal(adminConsoleRedirect(admin, null), null)
    assert.equal(adminConsoleRedirect(admin, CLOUD), null)
    assert.equal(adminConsoleLink(admin), ADMIN_CONSOLE_PATH)
    assert.equal(adminConsoleLink(analyst), null)
    assert.equal(adminConsoleRedirect(analyst, null), '/environment')
    assert.equal(adminConsoleRedirect(analyst, LINUX), '/dashboard')
    assert.equal(adminConsoleRedirect(null, LINUX), '/login')
    assert.ok(isAdminUser({ role: 'admin' }) && !isAdminUser(analyst) && !isAdminUser(null))
  })

  it('analysts follow the same workspace guards', () => {
    assert.equal(workspaceRedirect(null, LINUX, '/dashboard'), '/login')
    assert.equal(workspaceRedirect(analyst, CLOUD, '/servers'), '/dashboard')
    assert.equal(workspaceRedirect(analyst, LINUX, '/collection'), null)
  })
})

describe('navigation separation', () => {
  it('Q: Linux navigation shows Linux tools and no cloud entries', () => {
    const nav = paths(navForEnvironment(LINUX))
    assert.deepEqual(nav, ['/dashboard', '/servers', '/events', '/alerts', '/intelligence'])
    assert.ok(!nav.includes('/cloud-accounts'))
    assert.ok(!nav.includes('/detection'))
  })

  it('R: Cloud navigation shows Cloud Accounts and no server management', () => {
    const nav = paths(navForEnvironment(CLOUD, { isAdmin: true }))
    assert.deepEqual(nav, ['/dashboard', '/cloud-accounts', '/events', '/alerts', '/intelligence'])
    for (const linuxOnly of ['/servers', '/collection']) assert.ok(!nav.includes(linuxOnly))
    assert.ok(!nav.includes('/detection'))
    assert.ok(!nav.includes('/cloud-investigation'))
  })

  it('admin-only Linux collection is hidden from analysts', () => {
    assert.ok(!paths(navForEnvironment(LINUX)).includes('/collection'))
    assert.ok(paths(navForEnvironment(LINUX, { isAdmin: true })).includes('/collection'))
  })

  it('every nav item belongs to at least one workspace and terminology differs per workspace', () => {
    for (const item of NAV_ITEMS) assert.ok(item.environments.length > 0, item.to)
    const linuxLabels = navForEnvironment(LINUX).map((item) => item.label)
    const cloudLabels = navForEnvironment(CLOUD).map((item) => item.label)
    assert.ok(linuxLabels.includes('Servers') && !linuxLabels.includes('Cloud Accounts'))
    assert.ok(cloudLabels.includes('Cloud Accounts') && !cloudLabels.includes('Servers'))
  })

  it('S: wrong-environment routes are refused by the route guard', () => {
    for (const path of ['/servers', '/servers/new', '/servers/abc/edit', '/collection']) {
      assert.equal(routeEnvironment(path), LINUX, path)
      assert.ok(!isRouteAllowed(path, CLOUD), path)
      assert.ok(isRouteAllowed(path, LINUX), path)
    }
    assert.ok(!isRouteAllowed('/cloud-accounts', LINUX))
    assert.ok(isRouteAllowed('/cloud-accounts', CLOUD))
    assert.equal(routeEnvironment('/detection'), null)
    assert.ok(isRouteAllowed('/detection', LINUX) && isRouteAllowed('/detection', CLOUD))
    assert.equal(routeEnvironment('/cloud-investigation'), null)
    assert.ok(isRouteAllowed('/cloud-investigation', LINUX) && isRouteAllowed('/cloud-investigation', CLOUD))
    assert.equal(routeEnvironment('/serversX'), null)
    for (const shared of ['/dashboard', '/events', '/alerts', '/intelligence']) {
      assert.ok(isRouteAllowed(shared, LINUX) && isRouteAllowed(shared, CLOUD), shared)
    }
  })

  it('T: switching environment keeps shared pages and leaves environment-only pages', () => {
    assert.equal(switchTargetPath('/events', CLOUD), '/events')
    assert.equal(switchTargetPath('/intelligence', LINUX), '/intelligence')
    assert.equal(switchTargetPath('/servers/abc', CLOUD), '/dashboard')
    assert.equal(switchTargetPath('/cloud-accounts', LINUX), '/dashboard')
    assert.equal(switchTargetPath('/cloud-investigation', LINUX), '/cloud-investigation')
  })

  it('environment params are only attached for a valid workspace', () => {
    assert.deepEqual(withEnvironmentParam({ limit: 5 }, CLOUD), { limit: 5, environment: CLOUD })
    assert.deepEqual(withEnvironmentParam({ limit: 5 }, null), { limit: 5 })
    assert.deepEqual(withEnvironmentParam({ limit: 5 }, 'HPC'), { limit: 5 })
  })
})

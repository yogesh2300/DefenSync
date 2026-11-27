// Single source of truth for the Linux / Cloud workspace split. Pure functions only,
// so routing and navigation rules can be tested without a browser.

export const LINUX = 'LINUX'
export const CLOUD = 'CLOUD'
export const ENVIRONMENTS = [LINUX, CLOUD]
export const ENVIRONMENT_LABELS = { [LINUX]: 'Linux', [CLOUD]: 'Cloud' }
export const ENVIRONMENT_STORAGE_KEY = 'defensync_environment'

export const NAV_ITEMS = [
  { to: '/dashboard', key: 'dashboard', label: 'Dashboard', environments: [LINUX, CLOUD] },
  { to: '/servers', key: 'servers', label: 'Servers', environments: [LINUX] },
  { to: '/cloud-accounts', key: 'cloud-accounts', label: 'Cloud Accounts', environments: [CLOUD] },
  { to: '/events', key: 'events', label: 'Events', environments: [LINUX, CLOUD] },
  { to: '/alerts', key: 'alerts', label: 'Alerts', environments: [LINUX, CLOUD] },
  { to: '/intelligence', key: 'intelligence', label: 'DefenSync Intelligence', environments: [LINUX, CLOUD] },
  { to: '/collection', key: 'collection', label: 'Collection', environments: [LINUX], adminOnly: true },
]

const LINUX_ONLY_PREFIXES = ['/servers', '/collection']
const CLOUD_ONLY_PREFIXES = ['/cloud-accounts']

export function isEnvironment(value) {
  return ENVIRONMENTS.includes(value)
}

export function navForEnvironment(environment, { isAdmin = false } = {}) {
  return NAV_ITEMS.filter((item) => item.environments.includes(environment) && (!item.adminOnly || isAdmin))
}

function matchesPrefix(pathname, prefix) {
  return pathname === prefix || pathname.startsWith(`${prefix}/`)
}

export function routeEnvironment(pathname) {
  if (LINUX_ONLY_PREFIXES.some((prefix) => matchesPrefix(pathname, prefix))) return LINUX
  if (CLOUD_ONLY_PREFIXES.some((prefix) => matchesPrefix(pathname, prefix))) return CLOUD
  return null
}

export function isRouteAllowed(pathname, environment) {
  const owner = routeEnvironment(pathname)
  return owner === null || owner === environment
}

export const ADMIN_CONSOLE_PATH = '/admin/dashboard'

export function isAdminUser(user) {
  return (user?.role || '').toUpperCase() === 'ADMIN'
}

// Every role, ADMIN included, enters through the environment selection after OTP.
export function postAuthPath(user, environment) {
  if (!user) return '/login'
  return isEnvironment(environment) ? '/dashboard' : '/environment'
}

// Redirect target for the Linux/Cloud workspace routes, or null when the route may render.
export function workspaceRedirect(user, environment, pathname) {
  if (!user) return '/login'
  if (!isEnvironment(environment)) return '/environment'
  if (!isRouteAllowed(pathname, environment)) return '/dashboard'
  return null
}

// UX guard only: every /api/v1/admin endpoint still requires an ADMIN token server-side.
export function adminConsoleRedirect(user, environment) {
  if (!user) return '/login'
  if (!isAdminUser(user)) return postAuthPath(user, environment)
  return null
}

export function adminConsoleLink(user) {
  return isAdminUser(user) ? ADMIN_CONSOLE_PATH : null
}

export const ENVIRONMENT_SELECT_PATH = '/environment'
export const DASHBOARD_PATH = '/dashboard'
export const ADD_SERVER_PATH = '/servers/new'
export const ADD_CLOUD_SOURCE_PATH = '/cloud-accounts/new'

// Choosing an environment always opens its dashboard; the dashboard shows the empty state and Add action.
export function environmentEntryPath(environment) {
  return isEnvironment(environment) ? DASHBOARD_PATH : ENVIRONMENT_SELECT_PATH
}

export function countOf(listing) {
  if (Array.isArray(listing)) return listing.length
  if (Array.isArray(listing?.sources)) return listing.sources.length
  return 0
}

const WORKSPACE_RESOURCES = {
  [LINUX]: { resourceLabel: 'Servers', addLabel: 'Add Server', addPath: ADD_SERVER_PATH, emptyTitle: 'No Linux servers configured' },
  [CLOUD]: { resourceLabel: 'Cloud Accounts', addLabel: 'Add Cloud Account', addPath: ADD_CLOUD_SOURCE_PATH, emptyTitle: 'No Cloud Accounts configured' },
}

// Dashboard resource summary from the user's own account-scoped listing (servers / cloud sources).
export function workspaceResources(environment, listing) {
  if (!isEnvironment(environment)) return null
  const count = countOf(listing)
  return { environment, label: ENVIRONMENT_LABELS[environment], ...WORKSPACE_RESOURCES[environment], count, empty: count === 0 }
}

export function isAddScreen(pathname) {
  return pathname === ADD_SERVER_PATH || pathname === ADD_CLOUD_SOURCE_PATH
}

// Cancel/Back from an Add screen returns to Environment Selection; a successful creation opens the dashboard.
export function addScreenExitPath(outcome) {
  return outcome === 'created' ? DASHBOARD_PATH : ENVIRONMENT_SELECT_PATH
}

export function switchTargetPath(pathname, nextEnvironment) {
  return isRouteAllowed(pathname, nextEnvironment) ? pathname : '/dashboard'
}

export function withEnvironmentParam(params, environment) {
  return isEnvironment(environment) ? { ...params, environment } : { ...params }
}

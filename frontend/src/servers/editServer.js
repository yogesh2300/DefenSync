// Edit Server: what "Test Connection" may test and what "Save" may send.
// Testing never saves: new credentials go to the test-before-save endpoint.

export const CONNECTION_FIELDS = ['host', 'port', 'username', 'authentication_type']
export const USERNAME_NEEDS_SECRET =
  'Changing the SSH username requires a new password or private key for that account.'
export const CHANGED_SETTINGS_NEED_SECRET =
  'Enter the password or private key to test the changed connection settings.'

const text = (value) => String(value ?? '').trim()

/** The new secret for the selected authentication type, or null when none was entered. */
export function secretFor(form, { password = '', privateKey = '' } = {}) {
  if (form.authentication_type === 'ssh_key') return privateKey.trim() ? { private_key: privateKey } : null
  return password ? { password } : null
}

export function connectionChanged(original, form) {
  return CONNECTION_FIELDS.some((field) => text(original[field]) !== text(form[field]))
}

/**
 * { mode: 'preview', request } tests the entered credentials without saving them;
 * { mode: 'stored' } tests the saved server; { mode: 'blocked', reason } cannot be tested honestly.
 */
export function planConnectionTest(original, form, secrets) {
  const secret = secretFor(form, secrets)
  if (secret) {
    return {
      mode: 'preview',
      request: {
        host: text(form.host),
        port: Number(form.port),
        username: text(form.username),
        authentication_type: form.authentication_type,
        ...secret,
      },
    }
  }
  if (connectionChanged(original, form)) return { mode: 'blocked', reason: CHANGED_SETTINGS_NEED_SECRET }
  return { mode: 'stored' }
}

/** Backend errors arrive as { error: "..." }; request validation errors carry a list instead. */
export function apiErrorMessage(err, fallback) {
  const data = err?.response?.data || {}
  if (typeof data.error === 'string' && data.error) return data.error
  if (typeof data.detail === 'string' && data.detail) return data.detail
  return fallback
}

/** { payload } for PUT /servers/:id, or { error } when the change cannot work. */
export function buildUpdatePayload(original, form, secrets) {
  const secret = secretFor(form, secrets)
  if (text(form.username) !== text(original.username) && !secret) return { error: USERNAME_NEEDS_SECRET }
  return { payload: { ...form, username: text(form.username), ...(secret || {}) } }
}

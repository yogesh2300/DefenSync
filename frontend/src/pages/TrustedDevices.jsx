import { useCallback, useEffect, useState } from 'react'
import { Fingerprint, RefreshCw, ShieldAlert, ShieldCheck } from 'lucide-react'
import {
  beginTrustedDeviceEnroll,
  beginTrustedDeviceVerify,
  completeTrustedDeviceEnroll,
  completeTrustedDeviceVerify,
  listTrustedDevices,
  renameTrustedDevice,
  revokeTrustedDevice,
} from '../api/client'
import {
  clearLocalDeviceMaterial,
  cryptoAvailable,
  formatDeviceTime,
  generateDeviceKeyPair,
  getStoredDeviceId,
  loadStoredPrivateKey,
  setStoredDeviceId,
  signDeviceChallenge,
  slotsLabel,
  slotsRatio,
} from '../auth/trustedDevice'
import AlertBanner from '../components/ui/AlertBanner'
import Badge from '../components/ui/Badge'
import Button from '../components/ui/Button'
import Card from '../components/ui/Card'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import PageHeader from '../components/ui/PageHeader'

function statusVariant(status) {
  if (status === 'VERIFIED') return 'normal'
  if (status === 'PENDING') return 'medium'
  if (status === 'REVOKED') return 'error'
  return 'info'
}

const REVOKE_CONFIRM = (
  'Revoke this trusted device?\n\n'
  + '• Access tokens bound to this device will fail on the next protected API request.\n'
  + '• Other verified devices keep working.\n'
  + '• MFA-only sessions without a device binding are not selectively ended by this action.\n'
  + '• This frees a slot so another browser can enroll after MFA.'
)

export default function TrustedDevices() {
  const [summary, setSummary] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [busy, setBusy] = useState(false)
  const [displayName, setDisplayName] = useState('')
  const [renameId, setRenameId] = useState(null)
  const [renameValue, setRenameValue] = useState('')
  const [localDeviceId, setLocalDeviceId] = useState(() => getStoredDeviceId())

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      setSummary(await listTrustedDevices())
      setLocalDeviceId(getStoredDeviceId())
    } catch (err) {
      setSummary(null)
      setError(err.response?.data?.error || err.message || 'Failed to load trusted devices.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const enrollThisBrowser = async () => {
    setBusy(true)
    setError('')
    setSuccess('')
    try {
      if (!cryptoAvailable()) {
        throw new Error('This browser cannot store a device key. Continue using MFA on each sign-in.')
      }
      if ((summary?.available_slots ?? 0) <= 0) {
        throw new Error(
          `Trusted device limit reached (${slotsLabel(summary?.active_count, summary?.device_limit)}). `
          + 'Revoke an existing active device before enrolling another.',
        )
      }
      const { publicKeyJwk, privateKey } = await generateDeviceKeyPair()
      const begin = await beginTrustedDeviceEnroll(publicKeyJwk, displayName.trim() || null)
      const signature = await signDeviceChallenge(begin.challenge_id, begin.challenge, privateKey)
      const enrolled = await completeTrustedDeviceEnroll({
        deviceId: begin.device_id,
        challengeId: begin.challenge_id,
        nonce: begin.challenge,
        signature,
      })
      setStoredDeviceId(enrolled.id)
      setLocalDeviceId(enrolled.id)
      const bound = Boolean(enrolled.access_token)
      setSuccess(
        bound
          ? `Enrolled “${enrolled.display_name}”. This browser now uses a device-bound session token for revoke enforcement.`
          : `Enrolled “${enrolled.display_name}”. Re-verify this browser if you need a device-bound session token.`,
      )
      setDisplayName('')
      await load()
    } catch (err) {
      const code = err.response?.data?.code
      const message = err.response?.data?.error || err.message || 'Enrollment failed.'
      setError(code === 'TRUSTED_DEVICE_LIMIT_EXCEEDED'
        ? `${message} Revoke an existing active device first. A security alert was recorded for this attempt.`
        : message)
    } finally {
      setBusy(false)
    }
  }

  const rebindThisBrowser = async () => {
    setBusy(true)
    setError('')
    setSuccess('')
    try {
      const deviceId = getStoredDeviceId()
      if (!deviceId) throw new Error('No local device enrollment was found in this browser.')
      const privateKey = await loadStoredPrivateKey()
      if (!privateKey) throw new Error('No device private key is available in this browser. Enroll again after MFA.')
      const begin = await beginTrustedDeviceVerify(deviceId)
      const signature = await signDeviceChallenge(begin.challenge_id, begin.challenge, privateKey)
      const verified = await completeTrustedDeviceVerify({
        deviceId,
        challengeId: begin.challenge_id,
        nonce: begin.challenge,
        signature,
      })
      setLocalDeviceId(deviceId)
      setSuccess(
        verified.access_token
          ? `Verified “${verified.display_name || 'this device'}”. Device-bound session token refreshed for revoke enforcement.`
          : `Verified “${verified.display_name || 'this device'}”.`,
      )
      await load()
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Device verification failed.')
    } finally {
      setBusy(false)
    }
  }

  const revoke = async (device) => {
    if (!window.confirm(REVOKE_CONFIRM)) return
    setBusy(true)
    setError('')
    setSuccess('')
    try {
      const result = await revokeTrustedDevice(device.id)
      if (getStoredDeviceId() === device.id) {
        await clearLocalDeviceMaterial()
        setLocalDeviceId(null)
      }
      setSuccess(
        `Revoked “${result.display_name || device.display_name}” (${result.status || 'REVOKED'}). `
        + 'Requests that still use a token bound to this device should receive an authentication error on the next protected API call. '
        + 'Other verified devices are unaffected. MFA-only sessions without a device binding are not selectively ended.',
      )
      await load()
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Revoke failed.')
    } finally {
      setBusy(false)
    }
  }

  const saveRename = async (deviceId) => {
    setBusy(true)
    setError('')
    try {
      await renameTrustedDevice(deviceId, renameValue)
      setRenameId(null)
      setSuccess('Device name updated.')
      await load()
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Rename failed.')
    } finally {
      setBusy(false)
    }
  }

  const devices = summary?.devices || []
  const active = summary?.active_count ?? 0
  const limit = summary?.device_limit ?? 3
  const atLimit = active >= limit
  const localDevice = devices.find((device) => device.id === localDeviceId)
  const canRebind = Boolean(localDevice && localDevice.status === 'VERIFIED' && cryptoAvailable())

  return (
    <div className="page-shell space-y-4">
      <PageHeader
        title="Trusted Devices"
        subtitle="Manage browser devices enrolled for your user after MFA. Linux servers are not login devices."
        action={(
          <Button variant="secondary" onClick={load} disabled={loading || busy}>
            <RefreshCw className="h-4 w-4" /> Refresh
          </Button>
        )}
      />

      {error && <AlertBanner type="error" message={error} onDismiss={() => setError('')} />}
      {success && <AlertBanner type="success" message={success} onDismiss={() => setSuccess('')} />}

      {loading && <LoadingSpinner label="Loading trusted devices..." />}

      {!loading && summary && (
        <>
          <section className="grid gap-3 sm:grid-cols-3">
            <Card>
              <p className="text-[11px] font-semibold uppercase tracking-wide muted-text">Trusted devices</p>
              <p className="mt-2 text-2xl font-bold cyber-text" data-trusted-device-slots>
                {slotsRatio(active, limit)}
              </p>
              <p className="mt-1 text-xs muted-text">{slotsLabel(active, limit)} · {summary.available_slots} slot{summary.available_slots === 1 ? '' : 's'} free</p>
            </Card>
            <Card>
              <p className="text-[11px] font-semibold uppercase tracking-wide muted-text">Device limit</p>
              <p className="mt-2 text-2xl font-bold cyber-text">{limit}</p>
              <p className="mt-1 text-xs muted-text">Per-user limit. Only an administrator can change another user's limit.</p>
            </Card>
            <Card>
              <p className="text-[11px] font-semibold uppercase tracking-wide muted-text">Assurance</p>
              <p className="mt-2 text-sm cyber-text">ECDSA P-256 key stays in this browser. IP and user-agent are supporting evidence only.</p>
            </Card>
          </section>

          <Card title="Session revocation" subtitle="How revoke interacts with access tokens">
            <div className="flex gap-3 text-sm cyber-text" data-session-revocation-notice>
              <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-[#9F5F68]" aria-hidden="true" />
              <ul className="list-disc space-y-1.5 pl-4 muted-text">
                <li>Revoking a device invalidates access tokens bound to that device on subsequent authenticated requests.</li>
                <li>Other verified devices remain unaffected.</li>
                <li>Existing MFA-only sessions without a device binding are not selectively revoked by this feature.</li>
                <li>Use the access token returned by device enrollment or verification so device-bound session enforcement applies. Revoke does not claim to end every session immediately in every circumstance.</li>
              </ul>
            </div>
          </Card>

          <Card
            title="Enroll this browser"
            subtitle="Requires your current MFA session. Devices are never registered automatically on login."
          >
            {atLimit ? (
              <AlertBanner
                type="warning"
                message={`Limit reached (Trusted devices: ${slotsRatio(active, limit)}). Revoke an existing active device before enrolling another. A further enrollment attempt is denied and generates a security alert.`}
              />
            ) : (
              <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
                <label className="block flex-1 text-xs font-semibold muted-text">
                  Display name
                  <input
                    className="mt-1 w-full rounded-full border border-[var(--panel-border)] bg-white px-3 py-2 text-sm font-semibold cyber-text"
                    value={displayName}
                    onChange={(event) => setDisplayName(event.target.value)}
                    placeholder="e.g. Work laptop"
                    maxLength={120}
                    disabled={busy}
                  />
                </label>
                <Button onClick={enrollThisBrowser} disabled={busy || !cryptoAvailable()}>
                  <Fingerprint className="h-4 w-4" />
                  {busy ? 'Working…' : 'Trust this browser'}
                </Button>
              </div>
            )}
            {canRebind && (
              <div className="mt-3">
                <Button variant="secondary" disabled={busy} onClick={rebindThisBrowser}>
                  Refresh device-bound session
                </Button>
                <p className="mt-2 text-xs muted-text">
                  Re-proves this already enrolled browser and stores the returned device-bound access token.
                </p>
              </div>
            )}
            {!cryptoAvailable() && (
              <p className="mt-3 text-sm muted-text">Web Crypto / IndexedDB is unavailable. Use MFA on each sign-in instead of trusting a device.</p>
            )}
          </Card>

          <Card title="Your devices" subtitle="Only devices registered to your user are listed.">
            {!devices.length && (
              <p className="text-sm muted-text" data-trusted-devices-empty>
                No trusted devices yet. Enroll this browser after MFA if you want a remembered device key.
              </p>
            )}
            <div className="space-y-3">
              {devices.map((device) => (
                <div
                  key={device.id}
                  data-trusted-device={device.id}
                  data-trusted-device-status={device.status}
                  className="rounded-2xl border border-[var(--panel-border)] bg-[var(--panel-strong)] px-4 py-3"
                >
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <ShieldCheck className="h-4 w-4 text-[#6EA779]" />
                        {renameId === device.id ? (
                          <input
                            className="rounded-full border border-[var(--panel-border)] bg-white px-3 py-1 text-sm font-semibold cyber-text"
                            value={renameValue}
                            onChange={(event) => setRenameValue(event.target.value)}
                            maxLength={120}
                          />
                        ) : (
                          <p className="text-sm font-semibold cyber-text">{device.display_name}</p>
                        )}
                        <Badge variant={statusVariant(device.status)}>{device.verification_status || device.status}</Badge>
                        {localDeviceId === device.id && device.status === 'VERIFIED' && (
                          <span className="text-[11px] font-semibold muted-text">This browser</span>
                        )}
                      </div>
                      <p className="mt-1 font-mono text-[11px] muted-text">ref {String(device.device_ref || '').slice(0, 16)}…</p>
                      <p className="mt-1 text-xs muted-text">Created {formatDeviceTime(device.created_at)}</p>
                      <p className="mt-1 text-xs muted-text">Last seen {formatDeviceTime(device.last_seen_at)}</p>
                      {device.revoked_at && (
                        <p className="mt-1 text-xs muted-text">Revoked {formatDeviceTime(device.revoked_at)}</p>
                      )}
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {renameId === device.id ? (
                        <>
                          <Button variant="secondary" disabled={busy} onClick={() => saveRename(device.id)}>Save</Button>
                          <Button variant="secondary" disabled={busy} onClick={() => setRenameId(null)}>Cancel</Button>
                        </>
                      ) : (
                        <Button
                          variant="secondary"
                          disabled={busy || device.status === 'REVOKED'}
                          onClick={() => { setRenameId(device.id); setRenameValue(device.display_name || '') }}
                        >
                          Rename
                        </Button>
                      )}
                      {device.status !== 'REVOKED' && (
                        <Button variant="secondary" disabled={busy} onClick={() => revoke(device)}>Revoke</Button>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </>
      )}
    </div>
  )
}

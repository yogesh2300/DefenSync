/**
 * Browser trusted-device helpers using Web Crypto ECDSA P-256.
 * Private keys stay on the device (non-extractable). The server stores only the public JWK.
 * Browser fingerprints and IP/UA are never treated as device identity proof.
 */

const DB_NAME = 'defensync-trusted-device'
const STORE = 'keys'
const DEVICE_ID_KEY = 'defensync_trusted_device_id'

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1)
    req.onupgradeneeded = () => {
      const db = req.result
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE)
    }
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error || new Error('IndexedDB unavailable'))
  })
}

async function idbGet(key) {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readonly')
    const req = tx.objectStore(STORE).get(key)
    req.onsuccess = () => resolve(req.result ?? null)
    req.onerror = () => reject(req.error)
  })
}

async function idbSet(key, value) {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite')
    tx.objectStore(STORE).put(value, key)
    tx.oncomplete = () => resolve()
    tx.onerror = () => reject(tx.error)
  })
}

async function idbDelete(key) {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite')
    tx.objectStore(STORE).delete(key)
    tx.oncomplete = () => resolve()
    tx.onerror = () => reject(tx.error)
  })
}

export function cryptoAvailable() {
  return typeof crypto !== 'undefined' && !!crypto.subtle && typeof indexedDB !== 'undefined'
}

export async function generateDeviceKeyPair() {
  if (!cryptoAvailable()) {
    throw new Error('This browser cannot hold a device key. Re-verify with MFA instead of trusting the device.')
  }
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign', 'verify'],
  )
  const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey)
  delete publicKeyJwk.d
  await idbSet('privateKey', keyPair.privateKey)
  await idbSet('publicKeyJwk', publicKeyJwk)
  return { publicKeyJwk, privateKey: keyPair.privateKey }
}

export async function loadStoredPublicKeyJwk() {
  return idbGet('publicKeyJwk')
}

export async function loadStoredPrivateKey() {
  return idbGet('privateKey')
}

export function getStoredDeviceId() {
  try {
    return localStorage.getItem(DEVICE_ID_KEY)
  } catch {
    return null
  }
}

export function setStoredDeviceId(deviceId) {
  try {
    if (deviceId) localStorage.setItem(DEVICE_ID_KEY, deviceId)
    else localStorage.removeItem(DEVICE_ID_KEY)
  } catch {
    /* ignore quota / private mode */
  }
}

export async function clearLocalDeviceMaterial() {
  setStoredDeviceId(null)
  try {
    await idbDelete('privateKey')
    await idbDelete('publicKeyJwk')
  } catch {
    /* ignore */
  }
}

function b64url(buffer) {
  const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer
  let binary = ''
  bytes.forEach((b) => { binary += String.fromCharCode(b) })
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

/** Sign "{challenge_id}.{nonce}" with the device private key; returns raw IEEE-P1363 ES256 signature (b64url). */
export async function signDeviceChallenge(challengeId, nonce, privateKey) {
  if (!privateKey) throw new Error('No device private key is available on this browser.')
  const message = new TextEncoder().encode(`${challengeId}.${nonce}`)
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, message)
  return b64url(signature)
}

export function slotsLabel(activeCount, deviceLimit) {
  const active = Number(activeCount) || 0
  const limit = Number(deviceLimit) || 0
  return `${active} of ${limit} trusted devices`
}

/** Compact count for headers, e.g. "Trusted devices: 2 / 3". */
export function slotsRatio(activeCount, deviceLimit) {
  const active = Number(activeCount) || 0
  const limit = Number(deviceLimit) || 0
  return `${active} / ${limit}`
}

export function formatDeviceTime(value) {
  if (!value) return 'Never'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleString()
}

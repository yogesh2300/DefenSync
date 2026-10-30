import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { beforeEach, describe, it } from 'node:test'
import {
  CLOUD_INVESTIGATION_PATH,
  EMPTY_FINDINGS_MESSAGE,
  EVENTS_PATH,
  NO_AUTHORIZED_RELATED_EVENTS_MESSAGE,
  apiErrorMessage,
  eventRefIds,
  eventsPathForIds,
  identityLabel,
  parseEventIdsParam,
  relatedEventsAction,
  truncatedMessage,
  validateInvestigationWindow,
  windowFromLookbackMinutes,
} from '../src/cloud/cloudInvestigation.js'
import { CLOUD, LINUX, isRouteAllowed, navForEnvironment, routeEnvironment, switchTargetPath } from '../src/environment.js'

const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), 'utf8')

const store = new Map()
globalThis.localStorage = {
  getItem: (key) => (store.has(key) ? store.get(key) : null),
  setItem: (key, value) => store.set(key, String(value)),
  removeItem: (key) => store.delete(key),
}
globalThis.window = { dispatchEvent: () => {} }
if (typeof globalThis.CustomEvent === 'undefined') {
  globalThis.CustomEvent = class CustomEvent extends Event {}
}

const client = await import('../src/api/client.js')
const api = client.default
let calls = []
let reply = () => ({})
api.defaults.adapter = async (config) => {
  calls.push(config)
  const data = reply(config)
  if (data && data.__error) {
    const error = new Error(data.message || 'fail')
    error.response = { data: data.body, status: data.status || 422 }
    throw error
  }
  return { data, status: 200, statusText: 'OK', headers: {}, config }
}

beforeEach(() => {
  calls = []
  reply = () => ({})
  store.clear()
})

describe('cloud investigation helpers', () => {
  it('builds a bounded lookback window and rejects invalid spans', () => {
    const now = new Date('2026-10-28T12:00:00.000Z')
    const window = windowFromLookbackMinutes(60, now)
    assert.equal(window.start_time, '2026-10-28T11:00:00.000Z')
    assert.equal(window.end_time, '2026-10-28T12:00:00.000Z')
    assert.equal(windowFromLookbackMinutes(0, now).error, 'Choose a lookback window of at least 1 minute.')
    assert.equal(
      validateInvestigationWindow({
        start_time: '2026-10-28T12:00:00.000Z',
        end_time: '2026-10-28T11:00:00.000Z',
        sequence_minutes: 60,
      }),
      'end_time must be after start_time.',
    )
  })

  it('labels identities without inventing fields', () => {
    assert.equal(identityLabel({ actor_id: 'a1', cloud_identity: { user_principal_name: 'a@contoso.test' } }), 'a@contoso.test')
    assert.equal(identityLabel({ actor_id: 'a1' }), 'a1')
    assert.equal(identityLabel({}), 'Unknown identity')
  })

  it('related-event action navigates with explicit event_ids filter only', () => {
    const action = relatedEventsAction({
      event_refs: [
        { event_id: 'evt-1', event_type: 'CLOUD_LOGIN_SUCCESS' },
        { event_id: 'evt-2', event_type: 'CLOUD_LOGIN_FAILURE' },
        { event_id: '  ', event_type: 'x' },
        { event_type: 'no-id' },
      ],
    })
    assert.equal(action.deepLinkSupported, true)
    assert.deepEqual(action.eventIds, ['evt-1', 'evt-2'])
    assert.equal(action.path, `${EVENTS_PATH}?event_ids=evt-1%2Cevt-2`)
    assert.ok(!action.path.includes('raw_log'))
    assert.equal(relatedEventsAction({ event_refs: [] }).emptyMessage, NO_AUTHORIZED_RELATED_EVENTS_MESSAGE)
    assert.deepEqual(eventRefIds({ event_refs: null }), [])
    assert.deepEqual(parseEventIdsParam('a,b,,a'), ['a', 'b'])
    assert.equal(eventsPathForIds([]), EVENTS_PATH)
  })

  it('formats empty and truncated states without claiming zero risk', () => {
    assert.match(EMPTY_FINDINGS_MESSAGE, /not proof of zero risk/i)
    assert.equal(truncatedMessage({ summary: { truncated: false, finding_count: 2 } }), null)
    assert.match(truncatedMessage({ summary: { truncated: true, finding_count: 100 } }), /capped/i)
    assert.equal(apiErrorMessage({ response: { data: { error: 'Time window is too short.' } } }), 'Time window is too short.')
  })
})

describe('cloud investigation API client', () => {
  it('loads baselines and sequence findings through the authenticated client', async () => {
    store.set('defensync_token', 'jwt-value')
    reply = (config) => (
      config.url.includes('sequence')
        ? { findings: [], summary: { finding_count: 0, truncated: false } }
        : { identities: [], summary: { identity_count: 0, event_count: 0 } }
    )
    const params = {
      start_time: '2026-10-28T11:00:00.000Z',
      end_time: '2026-10-28T12:00:00.000Z',
      sequence_minutes: 60,
    }
    await client.getCloudIdentityBaselines({ start_time: params.start_time, end_time: params.end_time })
    await client.getCloudSequenceFindings(params)
    assert.deepEqual(calls.map((call) => `${call.method} ${call.url}`), [
      'get /api/v1/cloud/identity-baselines',
      'get /api/v1/cloud/sequence-findings',
    ])
    assert.equal(calls[0].headers.Authorization, 'Bearer jwt-value')
    assert.equal(calls[1].headers.Authorization, 'Bearer jwt-value')
    assert.deepEqual(calls[1].params, params)
  })

  it('passes event_ids through the ordinary events client', async () => {
    store.set('defensync_token', 'jwt-value')
    await client.getEvents({ environment: 'CLOUD', event_ids: 'evt-1,evt-2', limit: 1000 })
    assert.equal(calls[0].url, '/api/v1/events')
    assert.equal(calls[0].params.event_ids, 'evt-1,evt-2')
    assert.equal(calls[0].params.environment, 'CLOUD')
    assert.equal(calls[0].headers.Authorization, 'Bearer jwt-value')
  })

  it('surfaces API errors from the investigation endpoints', async () => {
    reply = () => ({ __error: true, body: { error: 'Unsupported data_origins for cloud sequence detection: LIVE_LINUX.' } })
    await assert.rejects(
      () => client.getCloudSequenceFindings({ start_time: 'a', end_time: 'b', sequence_minutes: 60 }),
      (err) => {
        assert.equal(apiErrorMessage(err), 'Unsupported data_origins for cloud sequence detection: LIVE_LINUX.')
        return true
      },
    )
  })
})

describe('cloud investigation presentation removal', () => {
  it('is removed from navigation; legacy path redirects to the Cloud dashboard', () => {
    assert.equal(CLOUD_INVESTIGATION_PATH, '/cloud-investigation')
    const cloudNav = navForEnvironment(CLOUD).map((item) => item.to)
    assert.ok(!cloudNav.includes(CLOUD_INVESTIGATION_PATH))
    assert.ok(!navForEnvironment(LINUX).map((item) => item.to).includes(CLOUD_INVESTIGATION_PATH))
    assert.equal(routeEnvironment(CLOUD_INVESTIGATION_PATH), null)
    assert.ok(isRouteAllowed(CLOUD_INVESTIGATION_PATH, CLOUD))
    assert.ok(isRouteAllowed(CLOUD_INVESTIGATION_PATH, LINUX))
    assert.equal(switchTargetPath(CLOUD_INVESTIGATION_PATH, LINUX), CLOUD_INVESTIGATION_PATH)

    const app = source('App.jsx')
    const layout = source('components/Layout.jsx')
    assert.match(app, /path="cloud-investigation"/)
    assert.match(app, /Navigate to="\/dashboard"/)
    assert.doesNotMatch(app, /CloudInvestigation/)
    assert.doesNotMatch(layout, /cloud-investigation/)
    assert.doesNotMatch(layout, /ScanSearch/)
  })

  it('Events page reads event_ids and keeps ordinary listing when absent', () => {
    const page = source('pages/Events.jsx')
    assert.match(page, /useSearchParams/)
    assert.match(page, /parseEventIdsParam/)
    assert.match(page, /buildEventsListParams/)
    assert.match(page, /No authorized events matched/)
    assert.match(page, /data-clear-event-ids/)
    assert.match(page, /Clear ID filter/)
    assert.doesNotMatch(page, /raw_log=/)
    assert.doesNotMatch(page, /cloud-investigation/)
    assert.doesNotMatch(page, /Cloud Investigation/)
  })
})

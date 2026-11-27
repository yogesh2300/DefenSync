import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { beforeEach, describe, it } from 'node:test'
import {
  eventsPathForIds,
  parseEventIdsParam,
  relatedEventsAction,
} from '../src/cloud/cloudInvestigation.js'
import { AZURE_LOG_ANALYTICS_ORIGIN, buildEventsListParams, emptyAuthorizedEventsMessage } from '../src/events/eventsQuery.js'
import { CLOUD, LINUX } from '../src/environment.js'

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
api.defaults.adapter = async (config) => {
  calls.push(config)
  return { data: [], status: 200, statusText: 'OK', headers: {}, config }
}

beforeEach(() => {
  calls = []
  store.clear()
  store.set('defensync_token', 'jwt-value')
})

describe('Events related-event integration', () => {
  it('navigates with event_ids and Events builds CLOUD+Azure API params', async () => {
    const finding = {
      event_refs: [
        { event_id: 'evt-azure-1', event_type: 'CLOUD_LOGIN_FAILURE' },
        { event_id: 'evt-azure-2', event_type: 'CLOUD_LOGIN_SUCCESS' },
      ],
    }
    const action = relatedEventsAction(finding)
    assert.equal(action.deepLinkSupported, true)
    assert.equal(action.path, eventsPathForIds(['evt-azure-1', 'evt-azure-2']))
    assert.match(action.path, /^\/events\?event_ids=/)
    assert.ok(!action.path.includes('raw_log'))

    const search = new URLSearchParams(action.path.split('?')[1] || '')
    const parsedIds = parseEventIdsParam(search.get('event_ids'))
    assert.deepEqual(parsedIds, ['evt-azure-1', 'evt-azure-2'])

    const params = buildEventsListParams({
      environment: CLOUD,
      eventIds: parsedIds,
    })
    assert.equal(params.environment, CLOUD)
    assert.equal(params.event_ids, 'evt-azure-1,evt-azure-2')
    assert.equal(params.data_origin, AZURE_LOG_ANALYTICS_ORIGIN)

    await client.getEvents(params)
    assert.equal(calls[0].url, '/api/v1/events')
    assert.equal(calls[0].params.environment, CLOUD)
    assert.equal(calls[0].params.event_ids, 'evt-azure-1,evt-azure-2')
    assert.equal(calls[0].params.data_origin, AZURE_LOG_ANALYTICS_ORIGIN)
    assert.equal(calls[0].headers.Authorization, 'Bearer jwt-value')
  })

  it('empty/no-authorized-match messaging and clearing ID filter restore ordinary listing params', () => {
    assert.equal(emptyAuthorizedEventsMessage(true), 'No authorized events matched')
    assert.equal(emptyAuthorizedEventsMessage(false), null)

    const cleared = buildEventsListParams({ environment: CLOUD, eventIds: [] })
    assert.equal(cleared.event_ids, undefined)
    assert.equal(cleared.data_origin, undefined)
    assert.equal(cleared.environment, CLOUD)

    const linuxIds = buildEventsListParams({ environment: LINUX, eventIds: ['linux-1'] })
    assert.equal(linuxIds.event_ids, 'linux-1')
    assert.equal(linuxIds.data_origin, undefined)
  })

  it('Events page wires search params, Azure origin builder, empty state, and clear filter', () => {
    const page = source('pages/Events.jsx')
    assert.match(page, /useSearchParams/)
    assert.match(page, /parseEventIdsParam/)
    assert.match(page, /buildEventsListParams/)
    assert.match(page, /No authorized events matched/)
    assert.match(page, /data-clear-event-ids/)
    assert.match(page, /Clear ID filter/)
    assert.match(page, /EVENT_IDS_FILTER_HINT/)
    assert.doesNotMatch(page, /raw_log=/)
    assert.doesNotMatch(page, /cloud-investigation/)
  })
})

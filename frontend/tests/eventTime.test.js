import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import {
  RECORD_KIND_FILTERS, clockNote, collectionTime, formatInstant, primaryTime, primaryTimeLabel, timelineTimeText,
} from '../src/eventTime.js'

const login = {
  time_label: 'EVENT_TIME',
  event_time: '2026-10-06T07:47:12Z',
  collection_time: '2026-10-06T07:46:59.972796Z',
  collection_delay_seconds: -12.027,
  timestamp: '2026-10-06T13:17:12',
  collection_timestamp: '2026-10-06T13:16:59.972796',
}
const snapshot = {
  time_label: 'OBSERVED_AT',
  event_time: '2026-10-06T07:46:59.972796Z',
  collection_time: '2026-10-06T07:46:59.972796Z',
  collection_delay_seconds: null,
}
const opts = { locale: 'en-GB', timeZone: 'Asia/Kolkata' }

describe('event explorer timestamp semantics', () => {
  it('record kind controls the primary label', () => {
    assert.equal(primaryTimeLabel(login), 'Event Time')
    assert.equal(primaryTimeLabel({ ...login, time_label: 'EVENT_TIME', record_kind: 'SYSTEM_EVENT' }), 'Event Time')
    assert.equal(primaryTimeLabel(snapshot), 'Observed At')
    assert.equal(primaryTimeLabel({ time_label: 'COLLECTED_AT' }), 'Collected At (no source time)')
  })

  it('uses the explicit UTC fields and never swaps event and collection time', () => {
    assert.equal(primaryTime(login), login.event_time)
    assert.equal(collectionTime(login), login.collection_time)
    assert.notEqual(primaryTime(login), collectionTime(login))
  })

  it('renders both instants with the same zone and labels it', () => {
    assert.match(formatInstant(primaryTime(login), opts), /13:17:12/)
    assert.match(formatInstant(collectionTime(login), opts), /13:16:59/)
    assert.match(formatInstant(primaryTime(login), opts), /IST|GMT\+5:30/)
    assert.match(formatInstant(primaryTime(login), { locale: 'en-GB', timeZone: 'UTC' }), /\b0?7:47:12\b.*UTC/)
    assert.equal(formatInstant(null), '-')
    assert.equal(formatInstant('not a date'), '-')
  })

  it('historical events collected together keep their own times in the timeline', () => {
    const collected = '2026-10-06T07:30:00Z'
    const history = ['2026-10-04T14:15:21Z', '2026-10-04T14:17:03Z', '2026-10-04T14:20:44Z']
      .map((event_time) => ({ time_label: 'EVENT_TIME', event_time, collection_time: collected }))
    const shown = history.map((event) => timelineTimeText(event, opts))
    assert.equal(new Set(shown).size, 3)
    assert.ok(shown.every((text) => /04\/10\/2026/.test(text) && !text.startsWith('Observed')))
    assert.ok(history.every((event) => formatInstant(collectionTime(event), opts) === formatInstant(collected, opts)))
    assert.match(timelineTimeText(snapshot, opts), /^Observed At 06\/10\/2026, 13:16:59/)
  })

  it('offers a filter that hides snapshots', () => {
    assert.deepEqual(RECORD_KIND_FILTERS.map((item) => item.value), ['', 'NOT_SNAPSHOT', 'SECURITY_EVENT', 'SYSTEM_EVENT', 'SYSTEM_SNAPSHOT'])
  })

  it('reports a source time later than collection without correcting it', () => {
    assert.match(clockNote(login), /12\.0s later than collection/)
    assert.match(formatInstant(primaryTime(login), opts), /13:17:12/)
    assert.equal(clockNote(snapshot), '')
    assert.equal(clockNote({ collection_delay_seconds: 30 }), '')
  })
})

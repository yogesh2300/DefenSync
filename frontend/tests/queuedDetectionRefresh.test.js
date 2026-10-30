import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { readFileSync } from 'node:fs'
import {
  QUEUED_DETECTION_FOLLOW_UP_MS,
  QUEUED_DETECTION_REFRESH_NOTE,
  createQueuedDetectionRefreshController,
  isQueuedDetectionRefreshDetail,
} from '../src/detection/queuedDetectionRefresh.js'

const panelSource = () => readFileSync(new URL('../src/components/intelligence/DetectionPanel.jsx', import.meta.url), 'utf8')

function fakeTimers() {
  const pending = new Map()
  let nextId = 1
  let now = 0
  return {
    pending,
    setTimeout(fn, delay) {
      const id = nextId++
      pending.set(id, { fn, due: now + delay })
      return id
    },
    clearTimeout(id) {
      pending.delete(id)
    },
    async flush(ms) {
      now += ms
      const due = [...pending.entries()].filter(([, item]) => item.due <= now)
      for (const [id, item] of due) {
        pending.delete(id)
        await item.fn()
      }
    },
  }
}

describe('queued detection refresh scheduling', () => {
  it('detects queued collection details and keeps an honest non-completion note', () => {
    assert.deepEqual(QUEUED_DETECTION_FOLLOW_UP_MS, [2000, 5000])
    assert.equal(isQueuedDetectionRefreshDetail({ result: { detection: { status: 'queued' } } }), true)
    assert.equal(isQueuedDetectionRefreshDetail({ result: { detection: { status: 'running' } } }), false)
    assert.equal(isQueuedDetectionRefreshDetail({ result: {} }), false)
    assert.equal(isQueuedDetectionRefreshDetail(undefined), false)
    assert.match(QUEUED_DETECTION_REFRESH_NOTE, /do not confirm that detection has finished/i)
    assert.doesNotMatch(QUEUED_DETECTION_REFRESH_NOTE, /detection (has )?completed/i)
  })

  it('queued collection triggers immediate refresh and bounded follow-ups at 2s and 5s', async () => {
    const timers = fakeTimers()
    const loads = []
    const controller = createQueuedDetectionRefreshController({
      setTimeoutFn: timers.setTimeout,
      clearTimeoutFn: timers.clearTimeout,
    })
    const tracked = async () => { loads.push('load') }

    const outcome = controller.handleDataRefresh(
      { result: { detection: { status: 'queued' }, success: true } },
      tracked,
    )
    assert.equal(outcome.queued, true)
    assert.equal(outcome.note, QUEUED_DETECTION_REFRESH_NOTE)
    assert.deepEqual(outcome.followUpMs, [2000, 5000])
    await Promise.resolve()
    assert.equal(loads.length, 1)
    assert.equal(controller.getPendingTimerCount(), 2)

    await timers.flush(2000)
    assert.equal(loads.length, 2)
    await timers.flush(3000)
    assert.equal(loads.length, 3)
    assert.equal(controller.getPendingTimerCount(), 0)
  })

  it('ordinary refresh events do not start extra polling', async () => {
    const timers = fakeTimers()
    const loads = []
    const controller = createQueuedDetectionRefreshController({
      setTimeoutFn: timers.setTimeout,
      clearTimeoutFn: timers.clearTimeout,
    })
    const tracked = async () => { loads.push('load') }

    const outcome = controller.handleDataRefresh({ result: { success: true } }, tracked)
    assert.equal(outcome.queued, false)
    assert.equal(outcome.note, null)
    assert.deepEqual(outcome.followUpMs, [])
    await Promise.resolve()
    assert.equal(loads.length, 1)
    assert.equal(controller.getPendingTimerCount(), 0)
    await timers.flush(5000)
    assert.equal(loads.length, 1)
  })

  it('a newer event cancels and replaces pending polls', async () => {
    const timers = fakeTimers()
    const loads = []
    const controller = createQueuedDetectionRefreshController({
      setTimeoutFn: timers.setTimeout,
      clearTimeoutFn: timers.clearTimeout,
    })
    const tracked = async () => { loads.push('load') }

    controller.handleDataRefresh({ result: { detection: { status: 'queued' } } }, tracked)
    await Promise.resolve()
    assert.equal(controller.getPendingTimerCount(), 2)
    const genAfterFirst = controller.getGeneration()

    controller.handleDataRefresh({ result: { detection: { status: 'queued' } } }, tracked)
    await Promise.resolve()
    assert.ok(controller.getGeneration() > genAfterFirst)
    assert.equal(controller.getPendingTimerCount(), 2)
    assert.equal(loads.length, 2)

    await timers.flush(5000)
    // Only the second schedule's follow-ups should run (2 more), not 4 from both schedules.
    assert.equal(loads.length, 4)
  })

  it('clear/unmount cleans up pending timers', async () => {
    const timers = fakeTimers()
    const loads = []
    const controller = createQueuedDetectionRefreshController({
      setTimeoutFn: timers.setTimeout,
      clearTimeoutFn: timers.clearTimeout,
    })
    const tracked = async () => { loads.push('load') }

    controller.handleDataRefresh({ result: { detection: { status: 'queued' } } }, tracked)
    await Promise.resolve()
    assert.equal(controller.getPendingTimerCount(), 2)
    controller.clear()
    assert.equal(controller.getPendingTimerCount(), 0)
    await timers.flush(5000)
    assert.equal(loads.length, 1)
  })

  it('polling does not overlap in-flight requests', async () => {
    const timers = fakeTimers()
    let release
    const gate = new Promise((resolve) => { release = resolve })
    let started = 0
    let finished = 0
    const controller = createQueuedDetectionRefreshController({
      setTimeoutFn: timers.setTimeout,
      clearTimeoutFn: timers.clearTimeout,
    })
    const slowLoad = async () => {
      started += 1
      await gate
      finished += 1
    }

    const first = controller.runLoad(slowLoad)
    const second = await controller.runLoad(slowLoad)
    assert.deepEqual(second, { skipped: true, reason: 'in_flight' })
    assert.equal(started, 1)
    release()
    await first
    assert.equal(finished, 1)
    assert.equal(controller.isInFlight(), false)
  })

  it('elapsed polling never claims detection completed', () => {
    assert.doesNotMatch(QUEUED_DETECTION_REFRESH_NOTE, /completed successfully|detection complete/i)
    const panel = panelSource()
    assert.match(panel, /createQueuedDetectionRefreshController/)
    assert.match(panel, /handleDataRefresh/)
    assert.match(panel, /data-queued-detection-refresh-note/)
    assert.doesNotMatch(panel, /detection has completed|Detection completed/)
  })
})

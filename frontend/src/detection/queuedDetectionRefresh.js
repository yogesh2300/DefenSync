// Bounded follow-up refreshes after Linux collection queues background detection.
// Timers never claim that detection completed — they only re-fetch API status.

export const QUEUED_DETECTION_FOLLOW_UP_MS = Object.freeze([2000, 5000])

export const QUEUED_DETECTION_REFRESH_NOTE =
  'Detection status was refreshed after collection queued a background run. These refreshes do not confirm that detection has finished; they show whatever the API reports now.'

export function isQueuedDetectionRefreshDetail(detail) {
  return detail?.result?.detection?.status === 'queued'
}

/**
 * Serializes loads and manages cancellable follow-up timers for queued detection.
 * Pure scheduling logic; callers inject timers for tests.
 */
export function createQueuedDetectionRefreshController({
  delays = QUEUED_DETECTION_FOLLOW_UP_MS,
  setTimeoutFn = globalThis.setTimeout.bind(globalThis),
  clearTimeoutFn = globalThis.clearTimeout.bind(globalThis),
} = {}) {
  let timers = []
  let generation = 0
  let inFlight = false

  function clearTimersAndBumpGeneration() {
    for (const id of timers) clearTimeoutFn(id)
    timers = []
    generation += 1
  }

  async function runLoad(loadFn) {
    if (inFlight) return { skipped: true, reason: 'in_flight' }
    inFlight = true
    try {
      await loadFn()
      return { skipped: false }
    } finally {
      inFlight = false
    }
  }

  function handleDataRefresh(detail, loadFn) {
    clearTimersAndBumpGeneration()
    const gen = generation
    void runLoad(loadFn)

    if (!isQueuedDetectionRefreshDetail(detail)) {
      return { queued: false, note: null, followUpMs: [] }
    }

    for (const delay of delays) {
      const id = setTimeoutFn(() => {
        timers = timers.filter((t) => t !== id)
        if (gen !== generation) return
        void runLoad(loadFn)
      }, delay)
      timers.push(id)
    }
    return {
      queued: true,
      note: QUEUED_DETECTION_REFRESH_NOTE,
      followUpMs: [...delays],
    }
  }

  function clear() {
    clearTimersAndBumpGeneration()
  }

  return {
    runLoad,
    handleDataRefresh,
    clear,
    /** Test helpers */
    getPendingTimerCount: () => timers.length,
    getGeneration: () => generation,
    isInFlight: () => inFlight,
  }
}

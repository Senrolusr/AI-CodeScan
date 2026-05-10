import { onUnmounted } from 'vue'

/**
 * @param {object} options
 * @param {import('vue').Ref} options.statusRef - reactive ref holding the task status
 * @param {(tick: number) => Promise<void>} options.fetchFn - data loader called each tick
 * @param {object} [options.intervals] - custom intervals per status
 * @param {(status: string) => void} [options.onComplete] - called once when task finishes
 */
export function usePolling({ statusRef, fetchFn, intervals, onComplete }) {
  let timer = null
  let tick = 0
  let completedFired = false

  const _intervals = { running: 2000, pending: 5000, ...intervals }
  const activeStatuses = ['running', 'pending']
  const doneStatuses = ['completed', 'failed', 'cancelled']

  const _getInterval = () => _intervals[statusRef.value] || 0

  const stop = () => {
    if (timer !== null) {
      clearTimeout(timer)
      clearInterval(timer)
      timer = null
    }
  }

  const _scheduleNext = () => {
    const ms = _getInterval()
    if (!ms) return
    timer = setTimeout(async () => {
      const prevStatus = statusRef.value
      try {
        await fetchFn(tick)
        tick += 1
      } catch { /* polling errors are silently swallowed */ }

      if (doneStatuses.includes(statusRef.value)) {
        if (!completedFired && prevStatus !== statusRef.value) {
          completedFired = true
          onComplete?.(statusRef.value)
        }
        timer = null
        return
      }
      _scheduleNext()
    }, ms)
  }

  const start = () => {
    stop()
    completedFired = false
    tick = 0
    if (!activeStatuses.includes(statusRef.value)) return
    _scheduleNext()
  }

  onUnmounted(stop)

  return { start, stop }
}

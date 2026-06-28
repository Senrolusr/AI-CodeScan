import { ref, onUnmounted } from 'vue'
import { useAuthStore } from '../stores/auth'

const TERMINAL_STATUSES = new Set(['completed', 'failed', 'cancelled'])
// 连续 error 达此阈值视为致命（原生 EventSource 的瞬断由其自身重连兜底）。
const MAX_CONSECUTIVE_ERRORS = 5

/**
 * SSE 事件流组合式（原生 EventSource，§11.3）。
 *
 * 运行态实时接收审计事件；EventSource 原生自动重连处理瞬断；
 * 连接彻底关闭（readyState=CLOSED）或连续 error 超阈值时回调 ``onFallback``，
 * 由调用方降级到轮询。
 *
 * 设计要点：
 * - 鉴权：原生 EventSource 无法发送 Authorization 头，token 经 ``?token=`` 传递。
 * - 帧格式：后端每帧带 ``id:`` 但不带 ``event:``，故统一走 ``onmessage`` 接收
 *   （不必逐事件类型 addEventListener）。
 * - 去重：事件追加/去重由调用方负责（与轮询双源时按 id 去重，互不重复）。
 *
 * @param {number|string} taskId - 审计任务 id（生命周期内不变）
 * @param {import('vue').Ref<string>} statusRef - 任务状态 ref
 * @param {object} options
 * @param {(event: object) => void} options.onEvent - 每条事件回调（收到即代表 SSE 在线）
 * @param {() => void} [options.onFallback] - SSE 致命失败时的降级回调
 */
export function useAuditEventStream(taskId, statusRef, { onEvent, onFallback } = {}) {
  const isActive = ref(false)
  let es = null
  let errorCount = 0

  function buildUrl() {
    const token = useAuthStore().token
    const base = `/api/audits/${taskId}/events/stream`
    return token ? `${base}?token=${encodeURIComponent(token)}` : base
  }

  function teardownFallback() {
    isActive.value = false
    if (es) {
      es.close()
      es = null
    }
    onFallback?.()
  }

  function start() {
    stop()
    // 终态任务无需开流；无 token 无法鉴权，交给轮询兜底。
    if (TERMINAL_STATUSES.has(statusRef.value)) return
    if (!useAuthStore().token) return

    isActive.value = true
    errorCount = 0
    try {
      es = new EventSource(buildUrl())
    } catch {
      teardownFallback()
      return
    }

    es.onmessage = (ev) => {
      // 成功收到帧 → SSE 在线，清零连续错误计数。
      errorCount = 0
      let data
      try {
        data = JSON.parse(ev.data)
      } catch {
        return
      }
      onEvent?.(data)
    }

    es.onerror = () => {
      // 原生 EventSource 对瞬断会自动重连，仅在彻底关闭或连续失败时降级。
      if (!es || es.readyState === EventSource.CLOSED) {
        teardownFallback()
        return
      }
      errorCount += 1
      if (errorCount >= MAX_CONSECUTIVE_ERRORS) {
        teardownFallback()
      }
    }
  }

  function stop() {
    isActive.value = false
    if (es) {
      es.close()
      es = null
    }
  }

  onUnmounted(stop)

  return { start, stop, isActive }
}

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { defineComponent, h, ref } from 'vue'

import { useAuthStore } from '../stores/auth'
import { useAuditEventStream } from './useAuditEventStream'

// ── Mock EventSource（jsdom 无原生实现）──────────────────────────────────────
// 记录 URL、暴露派发 message/error 的手段；readyState 语义对齐原生：
// CONNECTING=0（瞬断重连中）、CLOSED=2（彻底关闭）。
class MockEventSource {
  constructor(url) {
    this.url = url
    this.readyState = MockEventSource.CONNECTING
    this.closed = false
    this.onmessage = null
    this.onerror = null
    MockEventSource.instances.push(this)
  }
  close() {
    this.closed = true
    this.readyState = MockEventSource.CLOSED
  }
  _dispatchMessage(obj) {
    if (this.onmessage) this.onmessage({ data: JSON.stringify(obj) })
  }
  _dispatchError() {
    if (this.onerror) this.onerror({ type: 'error' })
  }
}
MockEventSource.CONNECTING = 0
MockEventSource.OPEN = 1
MockEventSource.CLOSED = 2
MockEventSource.instances = []

const _origEventSource = globalThis.EventSource

/** 在组件 setup 内调用组合式（让 onUnmounted 生效），返回 { wrapper, api }。 */
function mountWith(taskId, status, opts) {
  const statusRef = ref(status)
  let api
  const Comp = defineComponent({
    setup() {
      api = useAuditEventStream(taskId, statusRef, opts)
      return () => h('div')
    },
  })
  const wrapper = mount(Comp)
  return { wrapper, api: () => api, statusRef }
}

describe('useAuditEventStream', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    MockEventSource.instances = []
    globalThis.EventSource = MockEventSource
    useAuthStore().setToken('test-token')
  })

  afterEach(() => {
    globalThis.EventSource = _origEventSource
  })

  it('start() 用带 ?token= 的 URL 打开 EventSource', () => {
    const { api } = mountWith(42, 'running', {})
    api().start()
    expect(MockEventSource.instances).toHaveLength(1)
    expect(MockEventSource.instances[0].url).toContain('/api/audits/42/events/stream')
    expect(MockEventSource.instances[0].url).toContain('?token=test-token')
    expect(api().isActive.value).toBe(true)
  })

  it('onmessage 解析 data 并回调 onEvent', () => {
    const onEvent = vi.fn()
    const { api } = mountWith(1, 'running', { onEvent })
    api().start()
    const es = MockEventSource.instances[0]
    es._dispatchMessage({ id: 7, event_type: 'stage.completed', payload: { a: 1 } })
    expect(onEvent).toHaveBeenCalledWith({ id: 7, event_type: 'stage.completed', payload: { a: 1 } })
  })

  it('终态任务不打开流', () => {
    const { api } = mountWith(1, 'completed', {})
    api().start()
    expect(MockEventSource.instances).toHaveLength(0)
    expect(api().isActive.value).toBe(false)
  })

  it('无 token 不打开流（交给轮询兜底）', () => {
    useAuthStore().setToken('')
    const { api } = mountWith(1, 'running', {})
    api().start()
    expect(MockEventSource.instances).toHaveLength(0)
  })

  it('连接彻底关闭（CLOSED）→ 立即 onFallback', () => {
    const onFallback = vi.fn()
    const { api } = mountWith(1, 'running', { onFallback })
    api().start()
    const es = MockEventSource.instances[0]
    es.readyState = MockEventSource.CLOSED
    es._dispatchError()
    expect(onFallback).toHaveBeenCalledTimes(1)
    expect(api().isActive.value).toBe(false)
    expect(es.closed).toBe(true)
  })

  it('连续瞬断 error 达阈值 → onFallback', () => {
    const onFallback = vi.fn()
    const { api } = mountWith(1, 'running', { onFallback })
    api().start()
    const es = MockEventSource.instances[0]
    // readyState 保持 CONNECTING（瞬断重连中），连续 5 次后才降级。
    for (let i = 0; i < 4; i++) es._dispatchError()
    expect(onFallback).not.toHaveBeenCalled()
    es._dispatchError()
    expect(onFallback).toHaveBeenCalledTimes(1)
    expect(api().isActive.value).toBe(false)
  })

  it('收到消息会清零连续错误计数', () => {
    const onFallback = vi.fn()
    const { api } = mountWith(1, 'running', { onFallback })
    api().start()
    const es = MockEventSource.instances[0]
    for (let i = 0; i < 4; i++) es._dispatchError()
    es._dispatchMessage({ id: 1, event_type: 'x' }) // 清零
    for (let i = 0; i < 4; i++) es._dispatchError()
    expect(onFallback).not.toHaveBeenCalled() // 计数被中途清零，未达阈值
  })

  it('stop() 关闭 EventSource', () => {
    const { api } = mountWith(1, 'running', {})
    api().start()
    const es = MockEventSource.instances[0]
    api().stop()
    expect(es.closed).toBe(true)
    expect(api().isActive.value).toBe(false)
  })

  it('组件卸载时自动关闭 EventSource', () => {
    const { wrapper, api } = mountWith(1, 'running', {})
    api().start()
    const es = MockEventSource.instances[0]
    wrapper.unmount()
    expect(es.closed).toBe(true)
  })
})

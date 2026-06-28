import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import ElementPlus from 'element-plus'

// 用 hoisted 共享对象承接 composable 返回的 start/stop，以便在用例里断言调用次数。
const mocks = vi.hoisted(() => ({
  polling: { start: vi.fn(), stop: vi.fn() },
  stream: { start: vi.fn(), stop: vi.fn() },
}))

vi.mock('../../composables/usePolling', () => ({
  // 忽略入参，返回共享 spy 对象（避免真实 setTimeout / onUnmounted 定时器）。
  usePolling: vi.fn(() => mocks.polling),
}))
vi.mock('../../composables/useAuditEventStream', () => ({
  useAuditEventStream: vi.fn(() => mocks.stream),
}))
vi.mock('../../api', () => ({
  getAuditEvents: vi.fn(() => Promise.resolve({ data: { events: [] } })),
}))

import RunActivityStream from './RunActivityStream.vue'

// status prop 在「活跃 ↔ 停止」之间的切换必须驱动 startAll / stopAll。
// 关键回归点：paused 必须停（GAP3 集成遗漏曾导致 SSE 在暂停态空挂到服务端 600s 超时）。
describe('RunActivityStream — 生命周期随 status 切换', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    mocks.polling.start.mockClear()
    mocks.polling.stop.mockClear()
    mocks.stream.start.mockClear()
    mocks.stream.stop.mockClear()
  })

  const mountWith = (status) => mount(RunActivityStream, {
    props: { taskId: 1, status, initialEvents: [] },
    global: { plugins: [ElementPlus] },
  })

  it('挂载（running）后 startAll：轮询 + SSE 各启动一次', async () => {
    mountWith('running')
    await flushPromises() // onMounted 内 fetchEvents 解析后才 startAll
    expect(mocks.polling.start).toHaveBeenCalledTimes(1)
    expect(mocks.stream.start).toHaveBeenCalledTimes(1)
  })

  it('running → paused 触发 stopAll（SSE 不应空挂）', async () => {
    const wrapper = mountWith('running')
    await flushPromises()
    await wrapper.setProps({ status: 'paused' })
    expect(mocks.polling.stop).toHaveBeenCalledTimes(1)
    expect(mocks.stream.stop).toHaveBeenCalledTimes(1)
  })

  it('paused → pending 重新 startAll；→ completed 再次 stopAll', async () => {
    const wrapper = mountWith('running')
    await flushPromises()
    await wrapper.setProps({ status: 'paused' })
    await wrapper.setProps({ status: 'pending' })
    expect(mocks.polling.start).toHaveBeenCalledTimes(2) // 挂载 + resume
    expect(mocks.stream.start).toHaveBeenCalledTimes(2)
    await wrapper.setProps({ status: 'completed' })
    expect(mocks.polling.stop).toHaveBeenCalledTimes(2) // paused + completed
    expect(mocks.stream.stop).toHaveBeenCalledTimes(2)
  })
})

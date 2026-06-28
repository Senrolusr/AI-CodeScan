import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import ElementPlus, { ElSelect } from 'element-plus'

// 拦截 api：filter 变更会触发 store.loadVulns → loadSnapshot → getAuditSnapshot，
// 不 mock 会真发 /audits/null/snapshot 产生未捕获拒绝。
vi.mock('../../api', () => ({
  getAuditSnapshot: vi.fn(),
  getAuditStageArtifact: vi.fn(),
  getProjectRuleHits: vi.fn(),
}))

import { getAuditSnapshot } from '../../api'
import FindingList from './FindingList.vue'
import VulnCard from '../VulnCard.vue'
import { useAuditDetailStore } from '../../stores/auditDetail'

// FindingList 直接消费 auditDetail store（filter/列表同源）；这里用真实 store + $patch 灌数据，
// 验证 storeToRefs 解构在组件里的响应式绑定（render + filter 变更触发重拉）。
describe('FindingList', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    getAuditSnapshot.mockResolvedValue({ data: { task: null, stages: [], vulnerabilities: [], reports: [], review_summary: {} } })
  })

  it('renders the vuln count and one VulnCard per store vuln', () => {
    const store = useAuditDetailStore()
    store.$patch({
      vulns: [
        { id: 1, title: 'a', severity: 'High' },
        { id: 2, title: 'b', severity: 'Low' },
      ],
    })
    const wrapper = mount(FindingList, { global: { plugins: [ElementPlus] } })
    expect(wrapper.text()).toContain('(2)') // 标题里的计数
    expect(wrapper.findAllComponents(VulnCard)).toHaveLength(2)
  })

  it('emits select with the vuln id when a VulnCard is clicked', async () => {
    const store = useAuditDetailStore()
    store.$patch({ vulns: [{ id: 42, title: 'x', severity: 'High' }] })
    const wrapper = mount(FindingList, { global: { plugins: [ElementPlus] } })
    await wrapper.findComponent(VulnCard).vm.$emit('click')
    expect(wrapper.emitted('select')).toBeTruthy()
    expect(wrapper.emitted('select')[0]).toEqual([42])
  })

  it('triggers store.loadVulns when a filter select changes', async () => {
    const store = useAuditDetailStore()
    const spy = vi.spyOn(store, 'loadVulns')
    const wrapper = mount(FindingList, { global: { plugins: [ElementPlus] } })
    await wrapper.findComponent(ElSelect).vm.$emit('change')
    expect(spy).toHaveBeenCalled()
  })
})

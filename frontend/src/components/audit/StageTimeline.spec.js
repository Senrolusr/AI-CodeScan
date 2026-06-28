import { describe, it, expect, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import ElementPlus, { ElButton } from 'element-plus'

import StageTimeline from './StageTimeline.vue'
import { useAuditDetailStore } from '../../stores/auditDetail'

// StageTimeline 直接消费 auditDetail store：用真实 store + $patch 灌一份四阶��快照，
// 验证派生（planStage/auditStages/reviewStage/archStage）与 helper（vulnCountForStage 等）
// 在组件里的响应式绑定。断言用数据驱动的 stage_name / 漏洞计数，避免耦合 i18n 文案。
describe('StageTimeline', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  function seedStages(overrides = {}) {
    const store = useAuditDetailStore()
    const stages = [
      {
        id: 1, stage_num: 1, status: 'completed', stage_name: '架构分析', agent_role: 'supervisor',
        findings: { architecture_info: { tech_stack: 'Flask', _route_count: 5 } },
        started_at: null, completed_at: null,
      },
      {
        id: -1, stage_num: -1, status: 'completed', stage_name: 'Supervisor 规划', agent_role: 'supervisor',
        findings: { selected_agents: [{ stage_num: 2, focus_guidance: '盯紧用户输入' }] },
      },
      {
        id: 2, stage_num: 2, status: 'completed', stage_name: '注入审计', agent_role: 'sub_agent',
        findings: { _formal_vulnerability_count: 7 },
      },
      {
        id: -2, stage_num: -2, status: 'completed', stage_name: 'Supervisor 审核', agent_role: 'supervisor',
        findings: { review_summary: '通过', rerun_execution: { executed_stage_nums: [2] } },
      },
      ...(overrides.extraStages || []),
    ]
    store.$patch({ stages, ...(overrides.patch || {}) })
    return store
  }

  it('renders the four phases from seeded stages', () => {
    seedStages()
    const wrapper = mount(StageTimeline, { global: { plugins: [ElementPlus] } })
    const text = wrapper.text()
    // 各阶段 stage_name 来自灌入数据（不依赖 i18n 文案）
    expect(text).toContain('架构分析') // 第一阶段
    expect(text).toContain('注入审计') // 第三阶段子 Agent
    expect(text).toContain('Supervisor 审核') // 第四阶段
  })

  it('shows the formal vuln count tag for a sub_agent stage', () => {
    seedStages()
    const wrapper = mount(StageTimeline, { global: { plugins: [ElementPlus] } })
    // vulnCountForStage(2) = stageQualityStats(stage2).formal = 7；选个不易与别处冲突的数字
    expect(wrapper.text()).toContain('7')
  })

  it('emits view-stage-one when the stage-one detail button is clicked', async () => {
    seedStages()
    const wrapper = mount(StageTimeline, { global: { plugins: [ElementPlus] } })
    // 组件里只有一个 el-button（阶段一「查看详情」），不直接耦合 router
    const buttons = wrapper.findAllComponents(ElButton)
    expect(buttons).toHaveLength(1)
    await buttons[0].trigger('click')
    expect(wrapper.emitted('view-stage-one')).toBeTruthy()
    expect(wrapper.emitted('view-stage-one').length).toBe(1)
  })

  it('mounts without error when there are no stages yet', () => {
    const store = useAuditDetailStore()
    store.$patch({ stages: [] })
    const wrapper = mount(StageTimeline, { global: { plugins: [ElementPlus] } })
    // 空阶段：架构/规划/审核缺位，时间线仍渲染（各阶段占位的等待提示）
    expect(wrapper.find('.el-timeline').exists()).toBe(true)
  })
})

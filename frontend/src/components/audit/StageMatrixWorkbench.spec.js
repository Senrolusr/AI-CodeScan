import { describe, expect, it, beforeEach } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import ElementPlus from 'element-plus'

import { setLocale } from '../../i18n'
import StageMatrixWorkbench from './StageMatrixWorkbench.vue'

const mountMatrix = (props = {}) => mount(StageMatrixWorkbench, {
  props: {
    stages: [
      { id: 1, stage_num: 1, stage_name: 'Architecture', status: 'completed', agent_role: 'architecture' },
      { id: 2, stage_num: 2, stage_name: 'Injection', status: 'completed', agent_role: 'sub_agent', findings: { _formal_vulnerability_count: 2 } },
      { id: 7, stage_num: 7, stage_name: 'FileOp', status: 'failed', agent_role: 'sub_agent', llm_response: 'forced failure' },
      { id: -2, stage_num: -2, stage_name: 'Review', status: 'pending', agent_role: 'supervisor_review' },
    ],
    agentRuns: [
      { id: 10, stage_num: 7, agent_role: 'sub_agent', status: 'failed', error_message: 'stage7 forced failure' },
      { id: 9, stage_num: 2, agent_role: 'sub_agent', status: 'completed' },
    ],
    diagnostics: {
      orchestration_guard: {
        status: 'blocked',
        planned_stage_nums: [2, 7],
        completed_stage_nums: [2],
        failed_stage_nums: [7],
        missing_stage_nums: [],
        unresolved_stage_nums: [7],
        message: '阶段三并行审计未收敛，已阻止进入复核：Stage 7。',
      },
    },
    routeCoverage: {
      stage_coverage: [
        { stage_num: 2, attested_route_count: 3, missing_focus_route_count: 1 },
      ],
    },
    vulnerabilities: [{ id: 1, stage_id: 2 }],
    ...props,
  },
  global: { plugins: [ElementPlus] },
})

describe('StageMatrixWorkbench', () => {
  beforeEach(() => {
    setLocale('zh')
  })

  it('renders convergence summary and failed stage diagnostics', async () => {
    const wrapper = mountMatrix()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('阶段矩阵')
    expect(text).toContain('Stage 7')
    expect(text).toContain('stage7 forced failure')
    expect(text).toContain('计划阶段')
    expect(text).toContain('未收敛阶段')
    expect(text).toContain('3/1')
  })
})

import { beforeEach, describe, expect, it } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import ElementPlus from 'element-plus'

import { setLocale } from '../../i18n'
import RunDiagnosticsPanel from './RunDiagnosticsPanel.vue'

const mountPanel = (props = {}) => mount(RunDiagnosticsPanel, {
  props: {
    diagnostics: {
      focus_status: 'running',
      focus_reason: '审计正在执行',
      current_stage_num: 3,
      current_role: 'sub_agent',
      active_agent_run_id: 7,
      latest_event_type: 'stage.started',
      latest_event_at: '2026-06-27T10:00:00Z',
      last_progress_at: '2026-06-27T10:00:00Z',
      silence_seconds: 42,
      run_id: 2,
      ...props.diagnostics,
    },
    currentRun: { id: 2, mode: 'full', status: 'running', ...props.currentRun },
    agentRuns: props.agentRuns || [
      {
        id: 7,
        agent_role: 'sub_agent',
        stage_num: 3,
        status: 'running',
        prompt_tokens: 100,
        completion_tokens: 50,
        latency_ms: 1200,
        started_at: '2026-06-27T10:00:00Z',
      },
    ],
  },
  global: { plugins: [ElementPlus] },
})

describe('RunDiagnosticsPanel', () => {
  beforeEach(() => {
    setLocale('zh')
  })

  it('renders the current focus and active agent attempt', async () => {
    const wrapper = mountPanel()
    await flushPromises()

    expect(wrapper.text()).toContain('执行中')
    expect(wrapper.text()).toContain('Stage 3')
    expect(wrapper.text()).toContain('sub_agent')
    expect(wrapper.text()).toContain('stage.started')
    expect(wrapper.text()).toContain('150')
  })

  it('marks stalled silence as danger text', async () => {
    const wrapper = mountPanel({
      diagnostics: {
        focus_status: 'stalled',
        stalled: true,
        silence_seconds: 960,
      },
    })
    await flushPromises()

    expect(wrapper.text()).toContain('疑似卡住')
    expect(wrapper.find('.is-danger').exists()).toBe(true)
    expect(wrapper.find('.is-danger').text()).toContain('16 分钟')
  })

  it('renders orchestration guard convergence details', async () => {
    const wrapper = mountPanel({
      diagnostics: {
        focus_status: 'blocked',
        blocked_reason: '阶段三并行审计未收敛，已阻止进入复核：Stage 7。',
        orchestration_guard: {
          status: 'blocked',
          planned_stage_nums: [2, 3, 7, 9],
          completed_stage_nums: [2, 3, 9],
          missing_stage_nums: [],
          unresolved_stage_nums: [7],
          message: '阶段三并行审计未收敛，已阻止进入复核：Stage 7。',
        },
      },
    })
    await flushPromises()

    expect(wrapper.text()).toContain('编排守卫')
    expect(wrapper.text()).toContain('已阻塞')
    expect(wrapper.text()).toContain('S2, S3, S7, S9')
    expect(wrapper.text()).toContain('S7')
  })
})

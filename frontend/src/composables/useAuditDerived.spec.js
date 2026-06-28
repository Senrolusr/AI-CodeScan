import { describe, it, expect, beforeEach, vi } from 'vitest'
import { ref } from 'vue'
import { createPinia, setActivePinia } from 'pinia'

// 拦截 api：store import 会拉 api 模块；这里不触发任何抓取（只 $patch + 读 computed）。
vi.mock('../api', () => ({
  getAuditSnapshot: vi.fn(),
  getAuditStageArtifact: vi.fn(),
  getProjectRuleHits: vi.fn(),
}))

import { useAuditDetailStore } from '../stores/auditDetail'
import { useAuditDerived } from './useAuditDerived'

// t 仅被 stageOneCoverageNote 的 fallback 用到；key-as-value 足以断言回退路径。
const t = (k) => k

describe('useAuditDerived — 从 auditDetail store 派生 view model', () => {
  let store
  beforeEach(() => {
    setActivePinia(createPinia())
    store = useAuditDetailStore()
  })

  const derive = () => useAuditDerived(store, { t, locale: ref('zh') })

  it('displayCurrentStage：优先 summary.current_phase 与阶段状态，不信任并发 current_stage', () => {
    store.$patch({
      task: { status: 'running', current_stage: 9, total_stages: 9, summary: { current_phase: 3 } },
      stages: [
        { stage_num: 2, status: 'completed' },
        { stage_num: 3, status: 'running' },
        { stage_num: 4, status: 'pending' },
      ],
    })
    expect(derive().displayCurrentStage.value).toBe(3)

    store.$patch({ task: { status: 'running', current_stage: 7, total_stages: 9, summary: { current_phase: 2 } }, stages: [] })
    expect(derive().displayCurrentStage.value).toBe(-1)

    store.$patch({ task: { status: 'running', current_stage: 7, total_stages: 9, summary: { current_phase: 4 } }, stages: [] })
    expect(derive().displayCurrentStage.value).toBe(-2)

    store.$patch({ task: { status: 'completed', current_stage: 0, total_stages: 9, summary: { current_phase: 4 } } })
    expect(derive().displayCurrentStage.value).toBe(9)
  })

  it('阶段一覆盖比例 + 路由数（读 stage_one_detail）', () => {
    store.$patch({
      stageOneDetail: {
        compressed_summary: { coverage: { audit_scope_chunk_count: 10, scanned_chunk_count: 5 } },
        findings: { architecture_info: { _route_count: 7 } },
      },
    })
    const d = derive()
    expect(d.stageOneCoverageRatio.value).toBeCloseTo(0.5)
    expect(d.stageOneRouteCount.value).toBe(7)
    // 缺 audit_scope_note 时回退到 t(key)
    expect(d.stageOneCoverageNote.value).toBe('auditScopeCoverageNote')
  })

  it('routeCoverage 派生：百分比取整 + 钳制、has_route_gaps、missing 截断 8', () => {
    store.$patch({
      routeCoverage: {
        coverage_ratio: 0.5,
        has_route_gaps: true,
        missing_routes: Array.from({ length: 12 }, (_, i) => ({ method: 'GET', path: `/r${i}` })),
      },
    })
    const d = derive()
    expect(d.routeCoveragePercentValue.value).toBe(50) // round(0.5*100)
    expect(d.hasRouteCoverageGaps.value).toBe(true)
    expect(d.routeCoverageMissingRoutes.value).toHaveLength(8)
    // 钳制：>1 的 ratio 不超过 100
    store.$patch({ routeCoverage: { coverage_ratio: 1.25 } })
    expect(derive().routeCoveragePercentValue.value).toBe(100)
  })

  it('reviewOutcome / reviewNoticeClass / isCompletedWithGaps', () => {
    store.$patch({
      task: { status: 'completed', summary: { review_outcome: { status: 'manual_followup_required', next_action: 'manual_review' } } },
    })
    const d = derive()
    expect(d.reviewOutcome.value).toMatchObject({ status: 'manual_followup_required' })
    expect(d.reviewNoticeClass.value).toBe('danger-surface') // next_action manual_review → danger
    expect(d.isCompletedWithGaps.value).toBe(true)
  })

  it('isCompletedWithGaps：非 completed 恒为 false', () => {
    store.$patch({ task: { status: 'running', summary: {} } })
    expect(derive().isCompletedWithGaps.value).toBe(false)
  })

  it('scanStats 走 fallback：route_count/rule_hit_count 用 gap 摘要 + 规则命中', () => {
    store.$patch({
      task: { status: 'completed', summary: {} },
      stageOneArtifact: { payload: { route_gap_summary: { static_route_count: 5 } } },
      projectRuleHits: Array.from({ length: 25 }, () => ({})), // ruleHitsPreview 截断到 20
    })
    const d = derive()
    expect(d.ruleHitsPreview.value).toHaveLength(20)
    expect(d.scanStats.value.route_count).toBe(5) // routeCountFallback = static_route_count
    expect(d.scanStats.value.rule_hit_count).toBe(20) // ruleHitFallback = 20
  })

  it('phasePillStyle / isPhaseDone / isPhaseRunning（读 task + currentPhase）', () => {
    store.$patch({ task: { status: 'running', summary: { current_phase: 3 } } })
    const d = derive()
    expect(d.currentPhase.value).toBe(3)
    expect(d.phasePillStyle(3).background).toBe('var(--bg-info)') // running 当前阶段
    expect(d.phasePillStyle(1).background).toBe('var(--bg-success)') // 已完成阶段
    expect(d.isPhaseDone(1)).toBe(true)
    expect(d.isPhaseDone(3)).toBe(false)
    expect(d.isPhaseRunning(3)).toBe(true)
    expect(d.isPhaseRunning(1)).toBe(false)
  })

  it('reviewStageNumsText：列表→逗号拼接；空/undefined→占位', () => {
    const d = derive()
    expect(d.reviewStageNumsText([2, 7])).toBe('Stage 2, Stage 7')
    expect(d.reviewStageNumsText([])).toBe('--')
    expect(d.reviewStageNumsText(undefined)).toBe('--')
  })

  it('preDiscovery 三件套', () => {
    store.$patch({
      task: { summary: { pre_discovery: { tech_profile: { language: ['Python'], framework: ['Flask'] }, security_files: { total_critical_count: 4 } } } },
    })
    const d = derive()
    expect(d.preDiscoveryTech.value.language).toEqual(['Python'])
    expect(d.preDiscoverySecurityCount.value).toBe(4)
    expect(d.preDiscovery.value).toBeTruthy()
  })
})

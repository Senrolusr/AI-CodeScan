import { computed } from 'vue'
import { storeToRefs } from 'pinia'
import { buildTaskRescanRecommendations } from '../utils/auditRecommendations'
import { normalizeScanStats } from '../utils/scanStats'
import {
  coverageNoteOf,
  coverageRatioOf,
  deriveCoverage,
  routeCountOf,
  routeGapSummaryOf,
} from '../utils/stageOne'

// 四阶段文案键（phase pill / 完成态文案用）。
const PHASE_KEY_MAP = { 1: 'phaseArch', 2: 'phasePlan', 3: 'phaseAudit', 4: 'phaseReview' }

/**
 * AuditDetail 视图的纯派生 view-model 集合。
 *
 * 从 ``auditDetail`` store 的快照 state 派生 ~25 个展示用 computed + 几个纯 helper
 * （phase pill 样式、阶段文本），把 ``AuditDetail.vue`` 的 ``<script setup>`` 从
 * 「派生逻辑 + 编排」收敛回「编排 + UI 反馈」。**仅读 store refs + 入参 t/locale，
 * 无 router / api / 副作用**，故可脱离组件单测（见 useAuditDerived.spec.js）。
 *
 * 计算属性互有依赖（如 hasQualityNotice 依赖 reviewOutcome/workerFailure/...），
 * 但 getter 惰性求值，定义顺序不影响正确性——沿用原视图内的相对顺序。
 *
 * @param {import('../stores/auditDetail').useAuditDetailStore} store
 * @param {{ t: (key: string, params?: object) => string, locale: import('vue').Ref<string> }} i18n
 */
export function useAuditDerived(store, { t, locale }) {
  const {
    task,
    stages,
    stageMap,
    stageOneStage,
    stageOneArtifact,
    routeCoverage,
    vulns,
    projectRuleHits,
  } = storeToRefs(store)

  // ── 基础投影 ──
  const taskSummary = computed(() => {
    const summary = task.value?.summary
    return summary && typeof summary === 'object' ? summary : {}
  })
  const reviewStage = computed(() => stageMap.value[-2])
  const ruleHitsPreview = computed(() => projectRuleHits.value.slice(0, 20))

  // ── 进度 / 阶段 ──
  const displayCurrentStage = computed(() => {
    const total = Number(task.value?.total_stages || 9)
    if (task.value?.status === 'completed') return total

    const phase = Number(currentPhase.value || 1)
    if (phase <= 1) return 1
    if (phase === 2) return -1
    if (phase >= 4) return -2

    const auditStages = stages.value
      .filter(stage => stage && Number(stage.stage_num) >= 2 && Number(stage.stage_num) <= 9)
      .sort((a, b) => Number(a.stage_num) - Number(b.stage_num))
    const running = auditStages.find(stage => stage.status === 'running')
    if (running) return Number(running.stage_num)
    const firstPending = auditStages.find(stage => stage.status === 'pending')
    if (firstPending) return Number(firstPending.stage_num)
    const lastAudit = auditStages.at(-1)
    return lastAudit ? Number(lastAudit.stage_num) : Math.min(total, 2)
  })
  const currentPhase = computed(() => {
    if (!task.value) return 1
    const summary = taskSummary.value
    return (summary && typeof summary === 'object' && summary.current_phase) ? summary.current_phase : 1
  })
  const isMultiAgentPhaseMode = computed(() => {
    if (!task.value) return false
    const summary = taskSummary.value
    return !!(summary && typeof summary === 'object' && summary.multi_agent_phase_mode)
  })

  // ── 阶段一覆盖 / gap（公式收敛到 utils/stageOne，与 StageOneDetail/StageTimeline 共用）──
  const stageOneCoverage = computed(() => deriveCoverage(stageOneStage.value))
  const stageOneCoverageRatio = computed(() => coverageRatioOf(stageOneCoverage.value))
  const stageOneCoverageNote = computed(() => coverageNoteOf(stageOneCoverage.value, t('auditScopeCoverageNote')))
  const stageOneRouteCount = computed(() => routeCountOf(stageOneStage.value))
  const stageOneGapSummary = computed(() => routeGapSummaryOf(stageOneArtifact.value))

  // ── 扫描统计 / token / 重扫建议 ──
  const scanStats = computed(() => {
    const value = taskSummary.value.scan_stats
    const routeCountFallback = stageOneGapSummary.value.static_route_count || stageOneRouteCount.value || 0
    return normalizeScanStats(value, {
      routeCountFallback,
      ruleHitFallback: ruleHitsPreview.value.length || 0,
    })
  })
  const tokenStats = computed(() => {
    const ts = taskSummary.value.token_stats
    return ts && typeof ts === 'object' && ts.llm_call_count > 0 ? ts : null
  })
  const rescanRecommendations = computed(() => {
    const summaryValue = taskSummary.value.rescan_recommendations
    if (Array.isArray(summaryValue) && summaryValue.length) return summaryValue
    return buildTaskRescanRecommendations({
      vulns: vulns.value || [],
      scanStats: scanStats.value || {},
      locale: locale.value,
    })
  })

  // ── 路由覆盖 ──
  const hasRouteCoverageGaps = computed(() => !!routeCoverage.value?.has_route_gaps)
  const routeCoveragePercentValue = computed(() => {
    const ratio = Number(routeCoverage.value?.coverage_ratio || 0)
    return Math.max(0, Math.min(100, Math.round(ratio * 100)))
  })
  const routeCoverageMissingRoutes = computed(() => {
    const routes = routeCoverage.value?.missing_routes
    return Array.isArray(routes) ? routes.slice(0, 8) : []
  })
  const routeCoverageStageRows = computed(() => {
    const rows = routeCoverage.value?.stage_coverage
    if (!Array.isArray(rows)) return []
    return rows
      .filter(row => row && typeof row === 'object' && (row.focus_route_count || row.attested_route_count || row.missing_focus_route_count))
      .slice(0, 8)
  })

  // ── 复核结论 / 质量提示 ──
  const reviewOutcome = computed(() => {
    const summaryOutcome = taskSummary.value.review_outcome
    if (summaryOutcome && typeof summaryOutcome === 'object') return summaryOutcome
    const stageOutcome = reviewStage.value?.findings?.review_closure
    return stageOutcome && typeof stageOutcome === 'object' ? stageOutcome : null
  })
  const isCompletedWithGaps = computed(() => {
    if (task.value?.status !== 'completed') return false
    const outcome = reviewOutcome.value
    const status = String(outcome?.status || '')
    const nextAction = String(outcome?.next_action || '')
    return hasRouteCoverageGaps.value || status === 'manual_followup_required' || nextAction === 'manual_review'
  })
  const degradationNotes = computed(() => {
    const notes = taskSummary.value.degradation_notes
    if (!Array.isArray(notes)) return []
    return notes
      .filter(note => note && typeof note === 'object' && note.message)
      .slice(-5)
  })
  const workerFailure = computed(() => {
    const value = taskSummary.value.worker_failure
    return value && typeof value === 'object' ? value : null
  })
  const hasQualityNotice = computed(() => !!reviewOutcome.value || !!workerFailure.value || degradationNotes.value.length > 0 || hasRouteCoverageGaps.value)
  const reviewNoticeClass = computed(() => {
    const outcome = reviewOutcome.value
    if (!outcome) return 'info-surface'
    const status = String(outcome.status || '')
    const nextAction = String(outcome.next_action || '')
    const unresolved = Array.isArray(outcome.unresolved_stage_nums) ? outcome.unresolved_stage_nums : []
    if (status.includes('failed') || nextAction === 'manual_review' || unresolved.length > 0) return 'danger-surface'
    if (nextAction === 'rerun' || nextAction === 'monitor' || status.includes('notes') || status.includes('recommended')) return 'warning-surface'
    return 'success-surface'
  })

  // ── 阶段文本 helper ──
  const reviewRerunStageText = (nums) => nums.map(num => `Stage ${num}`).join(', ')
  const reviewStageNumsText = (nums) => Array.isArray(nums) && nums.length ? reviewRerunStageText(nums) : '--'

  // ── 预扫描概况 ──
  const preDiscovery = computed(() => {
    const pd = taskSummary.value.pre_discovery
    return pd && typeof pd === 'object' ? pd : null
  })
  const preDiscoveryTech = computed(() => {
    const tp = preDiscovery.value?.tech_profile
    return tp && typeof tp === 'object' ? tp : {}
  })
  const preDiscoverySecurityCount = computed(() => preDiscovery.value?.security_files?.total_critical_count || 0)

  // ── phase pill（读 task + currentPhase）──
  const phasePillStyle = (p) => {
    const done = task.value?.status === 'completed' || p < currentPhase.value
    const active = task.value?.status !== 'completed' && p === currentPhase.value
    const running = active && task.value?.status === 'running'
    return {
      display: 'flex', alignItems: 'center', gap: '6px',
      padding: '6px 14px', borderRadius: '20px', fontSize: '13px', fontWeight: 500,
      background: done ? 'var(--bg-success)' : running ? 'var(--bg-info)' : active ? 'var(--bg-warning)' : 'var(--bg-page)',
      color: done ? 'var(--text-success)' : running ? '#409EFF' : active ? 'var(--text-warning)' : 'var(--text-muted)',
      border: active ? '2px solid currentColor' : '1px solid var(--border-default)',
    }
  }
  const isPhaseDone = (phaseNum) => task.value?.status === 'completed' || phaseNum < currentPhase.value
  const isPhaseRunning = (phaseNum) => task.value?.status === 'running' && phaseNum === currentPhase.value

  return {
    PHASE_KEY_MAP,
    // 基础投影
    taskSummary, reviewStage, ruleHitsPreview,
    // 进度 / 阶段
    displayCurrentStage, currentPhase, isMultiAgentPhaseMode,
    // 阶段一
    stageOneCoverage, stageOneCoverageRatio, stageOneCoverageNote,
    stageOneRouteCount, stageOneGapSummary,
    // 扫描统计 / token / 重扫建议
    scanStats, tokenStats, rescanRecommendations,
    // 路由覆盖
    hasRouteCoverageGaps, routeCoveragePercentValue, routeCoverageMissingRoutes, routeCoverageStageRows,
    // 复核 / 质量
    reviewOutcome, isCompletedWithGaps, degradationNotes, workerFailure,
    hasQualityNotice, reviewNoticeClass,
    // 阶段文本
    reviewRerunStageText, reviewStageNumsText,
    // 预扫描
    preDiscovery, preDiscoveryTech, preDiscoverySecurityCount,
    // phase pill
    phasePillStyle, isPhaseDone, isPhaseRunning,
  }
}

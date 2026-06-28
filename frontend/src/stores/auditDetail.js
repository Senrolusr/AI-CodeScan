import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import {
  getAuditSnapshot,
  getAuditStageArtifact,
  getProjectRuleHits,
} from '../api'
import { collectRiskHints } from '../utils/riskHints'

/**
 * AuditDetail 视图状态（文档 §17.3：前端拿稳定 view model）。
 *
 * 集中持有快照派生数据 + 抓取编排，消除散落在视图组件里的十几个 ref：
 * - 单一数据源：task/stages/vulns/reports/run/events 等都从快照一次性落地。
 * - artifact 去重：阶段一 artifact 只在 stage-1 状态变化（或强制刷新）时重新拉取，
 *   不再随轮询每 tick 重拉（旧实现 loadSnapshot 内无条件 await loadStageOneArtifact）。
 *
 * 轮询生命周期仍由视图组件持有——usePolling 内部依赖 onUnmounted 清理定时器，
 * 而 Pinia store 是 app 级单例没有卸载钩子；组件用本 store 暴露的 loadSnapshot 作 fetchFn。
 *
 * store 是单例，跨任务复用前必须 init() 重置，避免上一条任务的残留状态串显。
 */
export const useAuditDetailStore = defineStore('auditDetail', () => {
  // ── 快照数据 ──
  const taskId = ref(null)
  const task = ref(null)
  const stages = ref([])
  const vulns = ref([])
  const reports = ref([])
  const reviewSummary = ref({})
  const routeCoverage = ref({})  // §12.3 顶层稳定 view model（不再从 task.summary 解析，§17.3）
  const stageOneDetail = ref(null)
  const stageOneArtifact = ref(null)
  const stageOneArtifactLoading = ref(false)
  const projectRuleHits = ref([])
  const recentEvents = ref([])
  const currentRun = ref(null)
  const agentRuns = ref([])
  const diagnostics = ref(null)

  // ── UI / 加载态 ──
  const loading = ref(true)
  const exporting = ref(false)
  const actionLoading = ref(false)
  const filter = ref({ severity: '', review_status: '' })

  // ── 派生（store 内部抓取 + 子组件共用）──
  const stageMap = computed(() => {
    const m = {}
    for (const s of stages.value) m[s.stage_num] = s
    return m
  })
  // 阶段一阶段对象：优先用快照单独下发的 stage_one_detail，回退到 stages 里的 stage_num=1。
  const stageOneStage = computed(() => stageOneDetail.value || stageMap.value[1] || null)
  const archStage = computed(() => stageOneStage.value)
  // 阶段一风险提示：时间线（StageTimeline）与覆盖摘要卡片共用，集中到 store 避免重复派生。
  const stageOneRiskHints = computed(() => collectRiskHints(
    stageOneStage.value?.findings,
    stageOneStage.value?.compressed_summary,
  ))

  // artifact 去重游标（非响应式闭包变量，跨 tick 复用；init 时清空）。
  let _lastStageOneArtifactStatus = ''

  function _reset() {
    task.value = null
    stages.value = []
    vulns.value = []
    reports.value = []
    reviewSummary.value = {}
    routeCoverage.value = {}
    stageOneDetail.value = null
    stageOneArtifact.value = null
    projectRuleHits.value = []
    recentEvents.value = []
    currentRun.value = null
    agentRuns.value = []
    diagnostics.value = null
    _lastStageOneArtifactStatus = ''
  }

  function _applySnapshot(payload, { includeVulnerabilities = true } = {}) {
    task.value = payload?.task || null
    stages.value = payload?.stages || []
    stageOneDetail.value = payload?.stage_one_detail || null
    reports.value = payload?.reports || []
    recentEvents.value = payload?.recent_events || []
    currentRun.value = payload?.current_run || null
    agentRuns.value = payload?.agent_runs || []
    diagnostics.value = payload?.diagnostics || null
    if (includeVulnerabilities) {
      vulns.value = payload?.vulnerabilities || []
    }
    reviewSummary.value = payload?.review_summary || {}
    routeCoverage.value = payload?.route_coverage || {}
  }

  async function loadStageOneArtifact({ force = false } = {}) {
    const id = taskId.value
    const stageOne = stageOneStage.value || stages.value.find(s => s.stage_num === 1)
    if (!stageOne?.artifact_path) {
      stageOneArtifact.value = null
      _lastStageOneArtifactStatus = ''
      return
    }
    const status = stageOne?.status || ''
    // 状态未变且已有 artifact：复用，跳过请求（轮询热路径上的主要去重点）。
    if (!force && stageOneArtifact.value && _lastStageOneArtifactStatus === status) {
      return
    }
    _lastStageOneArtifactStatus = status
    stageOneArtifactLoading.value = true
    try {
      const res = await getAuditStageArtifact(id, 1)
      stageOneArtifact.value = res.data
    } catch {
      stageOneArtifact.value = null
    } finally {
      stageOneArtifactLoading.value = false
    }
  }

  async function loadSnapshot({ includeVulnerabilities = true } = {}) {
    const res = await getAuditSnapshot(taskId.value, filter.value)
    _applySnapshot(res.data, { includeVulnerabilities })
    await loadStageOneArtifact()
  }

  async function loadProjectRuleHits() {
    const projectId = task.value?.project_id
    if (!projectId) {
      projectRuleHits.value = []
      return
    }
    try {
      const res = await getProjectRuleHits(projectId)
      projectRuleHits.value = Array.isArray(res.data) ? res.data : []
    } catch {
      projectRuleHits.value = []
    }
  }

  // 筛选条件变更后重拉（含漏洞）。
  async function loadVulns() {
    await loadSnapshot()
  }

  // 报告导出/删除后只刷新 reports（不重拉漏洞）。
  async function loadReports() {
    try {
      await loadSnapshot({ includeVulnerabilities: false })
    } catch {
      /* 报告刷新失败静默，不打断用户操作 */
    }
  }

  // 进入详情页：绑定 taskId、重置残留状态、首拉快照 + 规则命中。失败向上抛，由视图提示。
  async function init(id) {
    taskId.value = id
    _reset()
    filter.value = { severity: '', review_status: '' }
    loading.value = true
    try {
      await loadSnapshot()
      await loadProjectRuleHits()
    } finally {
      loading.value = false
    }
  }

  return {
    // state
    taskId, task, stages, vulns, reports, reviewSummary, routeCoverage,
    stageOneDetail, stageOneArtifact, stageOneArtifactLoading,
    projectRuleHits, recentEvents, currentRun, agentRuns, diagnostics,
    loading, exporting, actionLoading, filter,
    // computed
    stageMap, stageOneStage, archStage, stageOneRiskHints,
    // actions
    init, loadSnapshot, loadStageOneArtifact, loadProjectRuleHits,
    loadVulns, loadReports,
  }
})

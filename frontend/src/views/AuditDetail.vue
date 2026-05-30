<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  cancelAudit,
  deleteReport,
  exportReport,
  getAudit,
  getAuditStage,
  getAuditStageArtifact,
  getAuditStages,
  getAuditVulns,
  getReports,
  retryAudit,
} from '../api'
import StageProgress from '../components/StageProgress.vue'
import VulnCard from '../components/VulnCard.vue'
import { useI18n } from '../i18n'
import { buildSeverityStats, buildTaskRescanRecommendations } from '../utils/auditRecommendations'
import { isAuditRetryBlocked } from '../utils/auditTaskState'
import { usePolling } from '../composables/usePolling'

const props = defineProps({ id: [String, Number] })
const router = useRouter()
const {
  locale,
  t,
  statusLabel,
  severityLabel,
  statusType,
  formatPercent,
  formatDateTime,
  formatTimeOnly,
} = useI18n()

const task = ref(null)
const stages = ref([])
const vulns = ref([])
const reports = ref([])
const loading = ref(true)
const exporting = ref(false)
const actionLoading = ref(false)
const filter = ref({ severity: '' })
const stageOneArtifact = ref(null)
const stageOneArtifactLoading = ref(false)
const expandedRuleHits = ref([])
const ruleHitsExpanded = ref(false)
const stageOneDetail = ref(null)

const taskStatus = computed(() => task.value?.status || '')
const polling = usePolling({
  statusRef: taskStatus,
  fetchFn: async (tick) => {
    await loadTaskAndStages()
    if (tick % 3 === 0) await loadVulns()
  },
  onComplete: () => {
    Promise.all([loadVulns(), loadReports()])
    _notifyCompletion(task.value)
  },
})

const stageMap = computed(() => {
  const m = {}
  for (const s of stages.value) m[s.stage_num] = s
  return m
})

const archStage = computed(() => stageOneDetail.value || stageMap.value[1] || null)
const planStage = computed(() => stageMap.value[-1])
const auditStages = computed(() => stages.value.filter(s => s.stage_num >= 2 && s.stage_num <= 9))
const reviewStage = computed(() => stageMap.value[-2])
const taskSummary = computed(() => {
  const summary = task.value?.summary
  return summary && typeof summary === 'object' ? summary : {}
})
const displayCurrentStage = computed(() => {
  const total = Number(task.value?.total_stages || 9)
  const current = Number(task.value?.current_stage || 0)
  return task.value?.status === 'completed' && current <= 0 ? total : current
})

const PHASE_KEY_MAP = { 1: 'phaseArch', 2: 'phasePlan', 3: 'phaseAudit', 4: 'phaseReview' }
const currentPhase = computed(() => {
  if (!task.value) return 1
  const summary = taskSummary.value
  return (summary && typeof summary === 'object' && summary.current_phase) ? summary.current_phase : 1
})
const isMultiAgentPhaseMode = computed(() => {
  if (!task.value) return false
  const summary = taskSummary.value
  return summary && typeof summary === 'object' && summary.multi_agent_phase_mode
})

const stageOneStage = computed(() => stageOneDetail.value || stageMap.value[1] || null)
const stageOneCoverage = computed(() => {
  const coverage = stageOneStage.value?.compressed_summary?.coverage
  return coverage && typeof coverage === 'object' ? coverage : {}
})
const stageOneCoverageRatio = computed(() => {
  const total = Number(stageOneCoverage.value.audit_scope_chunk_count || stageOneCoverage.value.total_chunk_count || 0)
  const scanned = Number(stageOneCoverage.value.scanned_chunk_count || 0)
  return scanned / Math.max(total || 1, 1)
})
const stageOneCoverageNote = computed(() => stageOneCoverage.value.audit_scope_note || t('auditScopeCoverageNote'))
const stageOneRouteCount = computed(() => {
  const arch = stageOneStage.value?.findings?.architecture_info
  if (!arch || typeof arch !== 'object') return 0
  if (Number.isFinite(Number(arch._route_count))) return Number(arch._route_count)
  return Array.isArray(arch.routes) ? arch.routes.length : 0
})
const stageOneGapSummary = computed(() => {
  const gapSummary = stageOneArtifact.value?.payload?.route_gap_summary
  return gapSummary && typeof gapSummary === 'object'
    ? gapSummary
    : { static_route_count: 0, confirmed_route_count: 0, missing_route_count: 0 }
})
const scanStats = computed(() => {
  const value = taskSummary.value.scan_stats
  return value && typeof value === 'object'
    ? value
    : {
        source_files_detected: 0,
        source_files_indexed: 0,
        oversized_files_skipped: 0,
        oversized_files_compacted: 0,
        files_selected_for_audit: 0,
        files_skipped_by_audit_file_budget: 0,
        files_considered_for_chunks: 0,
        files_with_content: 0,
        chunk_count: 0,
        rule_hit_count: 0,
        truncated_by_audit_file_count: false,
        truncated_by_code_chunks: false,
        truncated_by_total_chars: false,
        route_count: 0,
        route_source_files: 0,
        partial_audit: false,
      }
})
const ruleHitsPreview = computed(() => Array.isArray(taskSummary.value.rule_hits_preview) ? taskSummary.value.rule_hits_preview : [])
const tokenStats = computed(() => {
  const ts = taskSummary.value.token_stats
  return ts && typeof ts === 'object' && ts.llm_call_count > 0 ? ts : null
})
const severityStats = computed(() => {
  const summaryValue = taskSummary.value.severity_stats
  if (summaryValue && typeof summaryValue === 'object') {
    return {
      Critical: Number(summaryValue.Critical || 0),
      High: Number(summaryValue.High || 0),
      Medium: Number(summaryValue.Medium || 0),
      Low: Number(summaryValue.Low || 0),
      Info: Number(summaryValue.Info || 0),
    }
  }
  return buildSeverityStats(vulns.value || [])
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
const reviewOutcome = computed(() => {
  const summaryOutcome = taskSummary.value.review_outcome
  if (summaryOutcome && typeof summaryOutcome === 'object') return summaryOutcome
  const stageOutcome = reviewStage.value?.findings?.review_closure
  return stageOutcome && typeof stageOutcome === 'object' ? stageOutcome : null
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
const hasQualityNotice = computed(() => !!reviewOutcome.value || !!workerFailure.value || degradationNotes.value.length > 0)
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
const reviewStageNumsText = (nums) => Array.isArray(nums) && nums.length ? reviewRerunStageText(nums) : '--'

// 阶段列表默认走轻量接口，阶段一详情单独拉取，避免轮询时携带完整 payload。
const archInfo = computed(() => {
  const ai = archStage.value?.findings?.architecture_info
  return ai && typeof ai === 'object' ? ai : {}
})
const middlewareChain = computed(() => Array.isArray(archInfo.value.middleware_chain) ? archInfo.value.middleware_chain : [])
const databaseModels = computed(() => Array.isArray(archInfo.value.database_models) ? archInfo.value.database_models : [])
const securityBoundaries = computed(() => archInfo.value.security_boundaries && typeof archInfo.value.security_boundaries === 'object' ? archInfo.value.security_boundaries : null)
const externalIntegrations = computed(() => Array.isArray(archInfo.value.external_integrations) ? archInfo.value.external_integrations : [])
const gapAnalysis = computed(() => archInfo.value._gap_analysis && typeof archInfo.value._gap_analysis === 'object' ? archInfo.value._gap_analysis : null)

// 预扫描概况
const preDiscovery = computed(() => {
  const pd = taskSummary.value.pre_discovery
  return pd && typeof pd === 'object' ? pd : null
})
const preDiscoveryTech = computed(() => {
  const tp = preDiscovery.value?.tech_profile
  return tp && typeof tp === 'object' ? tp : {}
})
const preDiscoverySecurityCount = computed(() => preDiscovery.value?.security_files?.total_critical_count || 0)

const loadTaskAndStages = async () => {
  const [taskRes, stagesRes, stageOneRes] = await Promise.all([
    getAudit(props.id),
    getAuditStages(props.id),
    getAuditStage(props.id, 1).catch(() => null),
  ])
  task.value = taskRes.data
  stages.value = stagesRes.data
  stageOneDetail.value = stageOneRes?.data || null
  await loadStageOneArtifact()
}

const loadVulns = async () => {
  const vulnsRes = await getAuditVulns(props.id, filter.value)
  vulns.value = vulnsRes.data
}

const loadData = async () => {
  try {
    await Promise.all([loadTaskAndStages(), loadVulns()])
  } catch {
    ElMessage.error(t('auditTaskNotFound'))
  } finally {
    loading.value = false
  }
}

const loadReports = async () => {
  try {
    const res = await getReports(props.id)
    reports.value = res.data || []
  } catch {}
}

const loadStageOneArtifact = async () => {
  const stageOne = stageOneStage.value || stages.value.find(stage => stage.stage_num === 1)
  if (!stageOne?.artifact_path) {
    stageOneArtifact.value = null
    return
  }
  stageOneArtifactLoading.value = true
  try {
    const res = await getAuditStageArtifact(props.id, 1)
    stageOneArtifact.value = res.data
  } catch {
    stageOneArtifact.value = null
  } finally {
    stageOneArtifactLoading.value = false
  }
}

const _notifyCompletion = (taskObj) => {
  if (!taskObj || typeof Notification === 'undefined') return
  if (Notification.permission === 'default') Notification.requestPermission()
  if (Notification.permission !== 'granted') return
  const isOk = taskObj.status === 'completed'
  new Notification('CodeScan', {
    body: isOk ? `${t('completed')}: ${t('auditNotification')} #${taskObj.id}` : `${t('failed')}: ${t('auditNotification')} #${taskObj.id}`,
    icon: '/favicon.svg',
  })
}

onMounted(async () => {
  await loadData()
  await loadReports()
  polling.start()
})

const handleExport = async (format) => {
  exporting.value = true
  try {
    const res = await exportReport(parseInt(props.id, 10), format)
    window.open(res.data.download_url, '_blank')
    ElMessage.success(t('reportGenerated'))
    loadReports()
  } catch {
    ElMessage.error(t('exportFailed'))
  } finally {
    exporting.value = false
  }
}

const handleDeleteReport = async (report) => {
  try {
    await ElMessageBox.confirm(t('deleteReportConfirm', { name: report.filename }), t('confirm'), { type: 'warning' })
    await deleteReport(parseInt(props.id, 10), report.filename)
    ElMessage.success(t('reportDeleted'))
    await loadReports()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error(e.friendlyMessage || t('deleteReportFailed'))
  }
}

const handleCancel = async () => {
  actionLoading.value = true
  try {
    await cancelAudit(props.id)
    ElMessage.success(t('auditCancelled'))
    polling.stop()
    await loadTaskAndStages()
  } catch (e) {
    ElMessage.error(e.friendlyMessage || t('cancelFailed'))
  } finally {
    actionLoading.value = false
  }
}

const handleRetry = async () => {
  if (isAuditRetryBlocked(task.value)) return
  actionLoading.value = true
  try {
    await retryAudit(props.id)
    ElMessage.success(t('retryStarted'))
    await loadTaskAndStages()
    polling.start()
  } catch (e) {
    ElMessage.error(e.friendlyMessage || t('retryFailed'))
  } finally {
    actionLoading.value = false
  }
}

const handleFilter = () => loadVulns()
const stageSummary = (stage) => {
  if (stage.status === 'failed') {
    return stage.findings?._debug?.error || stage.llm_response || task.value?.error_message || '-'
  }
  if (stage.findings?.stage_summary) {
    return stage.findings.stage_summary
  }
  const arch = stage.findings?.architecture_info
  if (arch && typeof arch === 'object' && (arch.tech_stack || arch.framework || arch.database || arch.auth_mechanism)) {
    const parts = []
    if (arch.tech_stack) parts.push(`${t('techStack')}：${arch.tech_stack}`)
    if (arch.framework) parts.push(`${t('framework')}：${arch.framework}`)
    if (arch.database) parts.push(`${t('database')}：${arch.database}`)
    if (arch.auth_mechanism) parts.push(`${t('authMechanism')}：${arch.auth_mechanism}`)
    const routeCount = Number.isFinite(Number(arch._route_count))
      ? Number(arch._route_count)
      : (Array.isArray(arch.routes) ? arch.routes.length : 0)
    if (routeCount) parts.push(t('routesIdentified', { count: routeCount }))
    if (parts.length) return parts.join('；') + '。'
  }
  if (stage.findings?.parse_error) {
    return `${t('responseParseFailed')}：${stage.findings.parse_error}`
  }
  if (stage.findings?.raw_response) {
    const raw = String(stage.findings.raw_response)
    if (raw.length > 500) return raw.slice(0, 500) + t('responseTruncated')
    return raw
  }
  return ''
}
const supervisorSummary = (stage) => {
  if (!stage?.findings || typeof stage.findings !== 'object') return ''
  const findings = stage.findings
  if (findings.selected_agents) {
    const agents = findings.selected_agents
    if (Array.isArray(agents)) {
      const names = agents.map(a => `Stage ${a.stage_num}`).join(', ')
      return `${t('selectedAgents', { count: agents.length })}：${names}`
    }
  }
  if (findings.review_summary) return findings.review_summary
  if (findings.raw_response) return String(findings.raw_response).slice(0, 300)
  return stageSummary(stage)
}
const cleanRuleHitText = (value) => String(value || '').replace(/\uFFFD+/g, '').replace(/\s+/g, ' ').trim()
const stageRecoveryNote = (stage) => {
  if (!stage?.findings || typeof stage.findings !== 'object' || !stage.findings._salvaged) return ''
  return stage.findings.parse_error || t('stageRecoveryFallback')
}
const formatRuleHitTitle = (hit) => cleanRuleHitText(hit?.title || hit?.label || t('noRuleHit')) || t('noRuleHit')
const formatRuleHitEvidence = (hit) => {
  const text = cleanRuleHitText(hit?.evidence || '')
  if (!text) return '--'
  return text.length > 280 ? `${text.slice(0, 280)}...` : text
}
const hitStageLabels = (hit) => {
  const nums = hit?.stage_nums
  if (!Array.isArray(nums) || !nums.length) return ''
  return nums.map(n => `S${n}`).join(', ')
}
const stageStyle = (status) => {
  const m = {
    completed: { bg: 'var(--bg-success)', border: 'var(--border-success)' },
    running: { bg: 'var(--bg-info)', border: 'var(--border-info)' },
    failed: { bg: 'var(--bg-danger)', border: 'var(--border-danger)' },
    skipped: { bg: 'var(--bg-alt)', border: 'var(--border-default)' },
  }
  const s = m[status] || { bg: 'var(--bg-card)', border: 'var(--border-default)' }
  return {
    padding: '10px 14px',
    borderRadius: '8px',
    border: '1px solid',
    borderColor: s.border,
    background: s.bg,
    opacity: status === 'skipped' ? 0.6 : 1,
  }
}
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
const debugSummary = (stage) => {
  const debug = stage?.findings?._debug || {}
  return t('debugSummary', {
    prompt: debug.user_prompt_length || debug.prompt_length || 0,
    chunks: debug.selected_chunk_count || 0,
    code: debug.code_text_length || 0,
    routes: debug.static_route_count || 0,
    context: debug.prev_context_length || 0,
  })
}
const goToStageOneDetail = () => router.push(`/audits/${props.id}/stage-one`)

const agentFocusGuidance = (stageNum) => {
  const plan = planStage.value?.findings
  if (!plan || typeof plan !== 'object') return ''
  const selected = plan.selected_agents || []
  const spec = selected.find(a => a.stage_num === stageNum)
  if (!spec) return ''
  const parts = []
  if (spec.focus_guidance) parts.push(spec.focus_guidance)
  if (spec.focus_files?.length) parts.push(`${t('focusFiles')}: ${spec.focus_files.slice(0, 5).join(', ')}`)
  if (spec.focus_routes?.length) parts.push(`${t('focusRoutes')}: ${spec.focus_routes.slice(0, 3).join(', ')}`)
  return parts.join(' | ')
}
const vulnCountForStage = (stageNum) => {
  const s = stageMap.value[stageNum]
  if (!s?.findings || typeof s.findings !== 'object') return 0
  if (Number.isFinite(Number(s.findings._vulnerability_count))) return Number(s.findings._vulnerability_count)
  return Array.isArray(s.findings.vulnerabilities) ? s.findings.vulnerabilities.length : 0
}
const reviewRerunExecution = computed(() => {
  const value = reviewStage.value?.findings?.rerun_execution
  return value && typeof value === 'object' ? value : null
})
const reviewRequestedStageNums = computed(() => {
  const nums = reviewStage.value?.findings?.rerun_agents
  if (!Array.isArray(nums)) return []
  return nums
    .map(item => (item && typeof item === 'object' ? item.stage_num : item))
    .filter(item => Number.isFinite(Number(item)))
    .map(item => Number(item))
})
const reviewRerunStageText = (nums) => nums.map(num => `Stage ${num}`).join(', ')
</script>

<template>
  <div v-loading="loading">
    <div v-if="task">
      <div class="page-header">
        <div>
          <h2 style="margin: 0 0 4px">{{ task.name || t('auditDetailTitle', { id: task.id }) }}</h2>
          <el-tag :type="statusType(task.status)" effect="dark">{{ statusLabel(task.status) }}</el-tag>
          <span style="margin-left: 12px" class="text-muted">
            {{ t('projectWithDate', { projectId: task.project_id, createdAt: formatDateTime(task.created_at) }) }}
          </span>
        </div>
        <div style="display: flex; gap: 8px; flex-wrap: wrap">
          <el-button v-if="task.status === 'pending' || task.status === 'running' || task.status === 'paused'" type="warning" plain :loading="actionLoading" @click="handleCancel">{{ t('cancel') }}</el-button>
          <el-button v-if="task.status === 'completed' || task.status === 'failed' || task.status === 'cancelled'" :disabled="isAuditRetryBlocked(task)" :loading="actionLoading" @click="handleRetry">{{ t('retry') }}</el-button>
          <el-button @click="handleExport('md')" :loading="exporting">{{ t('exportMd') }}</el-button>
          <el-button type="primary" @click="handleExport('pdf')" :loading="exporting">{{ t('exportPdf') }}</el-button>
        </div>
      </div>

      <!-- 进度概览 -->
      <el-card style="margin-bottom: 20px">
        <template #header><span class="card-title">{{ t('auditProgress') }}</span></template>
        <StageProgress :stages="stages" :current="displayCurrentStage" />
      </el-card>

      <!-- 质量提示 -->
      <el-card v-if="hasQualityNotice" style="margin-bottom: 20px">
        <template #header><span class="card-title">{{ t('qualityNotice') }}</span></template>
        <div style="display: grid; gap: 10px">
          <div v-if="workerFailure" class="danger-surface" style="padding: 10px 12px; line-height: 1.6">
            <strong>{{ t('workerFailureNotice') }}：</strong>{{ workerFailure.message || task.error_message || '--' }}
            <div v-if="workerFailure.failed_at" style="margin-top: 4px; font-size: 12px; opacity: 0.85">
              {{ t('failedAt') }}：{{ formatDateTime(workerFailure.failed_at) }}
            </div>
          </div>

          <div v-if="degradationNotes.length" class="warning-surface" style="padding: 10px 12px; line-height: 1.6">
            <strong>{{ t('degradedAuditNotice') }}</strong>
            <div
              v-for="(note, index) in degradationNotes"
              :key="`${note.code || 'degradation'}-${index}`"
              style="margin-top: 4px"
            >
              {{ note.message }}
              <span style="font-size: 12px; opacity: 0.8">
                ({{ note.phase || '--' }} · {{ formatDateTime(note.created_at) }})
              </span>
            </div>
          </div>

          <div v-if="reviewOutcome" :class="reviewNoticeClass" style="padding: 10px 12px; line-height: 1.6">
            <div>
              <strong>{{ t('reviewConclusion') }}：</strong>{{ reviewOutcome.status_summary || t('notAvailable') }}
            </div>
            <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-top: 8px">
              <el-tag size="small" effect="plain">{{ t('reviewStatus') }}：{{ reviewOutcome.status || '--' }}</el-tag>
              <el-tag size="small" effect="plain">{{ t('nextAction') }}：{{ reviewOutcome.next_action || '--' }}</el-tag>
              <el-tag v-if="Number.isFinite(Number(reviewOutcome.questionable_count))" size="small" effect="plain">
                {{ t('questionableFindings') }}：{{ reviewOutcome.questionable_count || 0 }}
              </el-tag>
              <el-tag v-if="Number.isFinite(Number(reviewOutcome.coverage_gap_count))" size="small" effect="plain">
                {{ t('coverageGaps') }}：{{ reviewOutcome.coverage_gap_count || 0 }}
              </el-tag>
            </div>
            <div v-if="reviewOutcome.unresolved_stage_nums?.length" style="margin-top: 6px">
              <strong>{{ t('unresolvedStages') }}：</strong>{{ reviewStageNumsText(reviewOutcome.unresolved_stage_nums) }}
            </div>
            <div v-if="reviewOutcome.failed_stage_nums?.length" style="margin-top: 6px">
              <strong>{{ t('failedStages') }}：</strong>{{ reviewStageNumsText(reviewOutcome.failed_stage_nums) }}
            </div>
          </div>
        </div>
      </el-card>

      <!-- 多阶段控制 -->
      <el-card v-if="isMultiAgentPhaseMode" style="margin-bottom: 20px">
        <template #header><span class="card-title">{{ t('phaseProgress') }}</span></template>
        <div style="display: flex; align-items: center; gap: 16px; flex-wrap: wrap; margin-bottom: 16px">
          <div
            v-for="p in 4"
            :key="p"
            :style="phasePillStyle(p)"
          >
            <span v-if="isPhaseDone(p)">&#10003;</span>
            <span v-else-if="isPhaseRunning(p)" style="display: inline-block; width: 12px; height: 12px; border: 2px solid currentColor; border-top-color: transparent; border-radius: 50%; animation: spin 1s linear infinite"></span>
            <span v-else style="display: inline-block; width: 12px; height: 12px; border-radius: 50%; background: currentColor; opacity: 0.3"></span>
            {{ t(PHASE_KEY_MAP[p]) }}
          </div>
        </div>
        <!-- 预扫描概况 -->
        <div v-if="preDiscovery" style="margin-bottom: 12px; padding: 10px 14px; border-radius: 8px; background: var(--bg-info); border: 1px solid var(--border-info); font-size: 13px; color: var(--text-primary); line-height: 1.7">
          <span style="font-weight: 600; color: #409EFF">{{ t('projectProfile') }}：</span>
          <span v-if="preDiscoveryTech.language?.length">{{ t('techStack') }} {{ preDiscoveryTech.language.join(', ') }}</span>
          <span v-if="preDiscoveryTech.framework?.length"> / {{ preDiscoveryTech.framework.join(', ') }}</span>
          <span v-if="preDiscoveryTech.database?.length"> / {{ preDiscoveryTech.database.join(', ') }}</span>
          <span v-if="preDiscoveryTech.orm?.length"> / {{ preDiscoveryTech.orm.join(', ') }}</span>
          <span style="margin-left: 12px; color: var(--text-muted)">{{ t('routeCount') }}: {{ scanStats.route_count || 0 }} / {{ t('securityBoundaries') }}: {{ preDiscoverySecurityCount }}</span>
        </div>
        <div v-if="task.status === 'pending'" class="text-muted">
          {{ statusLabel(task.status) }}...
        </div>
        <div v-else-if="task.status === 'running'" class="text-muted">
          {{ t(PHASE_KEY_MAP[currentPhase]) }} {{ t('running') }}...
        </div>
        <div v-else-if="task.status === 'completed'" style="color: #67C23A; font-size: 13px; font-weight: bold">
          &#10003; {{ t('completed') }}
        </div>
        <div v-else-if="task.status === 'failed' || task.status === 'cancelled' || task.status === 'paused'" class="text-muted">
          {{ statusLabel(task.status) }}
        </div>
      </el-card>

      <!-- 扫描概览 -->
      <el-card style="margin-bottom: 20px">
        <template #header><span class="card-title">{{ t('scanOverview') }}</span></template>
        <el-descriptions :column="4" border size="small">
          <el-descriptions-item :label="t('sourceFilesDetected')">{{ scanStats.source_files_detected || 0 }}</el-descriptions-item>
          <el-descriptions-item :label="t('sourceFilesIndexed')">{{ scanStats.source_files_indexed || scanStats.source_files_detected || 0 }}</el-descriptions-item>
          <el-descriptions-item :label="t('auditFilesSelected')">{{ scanStats.files_selected_for_audit || scanStats.files_considered_for_chunks || 0 }}</el-descriptions-item>
          <el-descriptions-item :label="t('chunkCandidateFiles')">{{ scanStats.files_considered_for_chunks || 0 }}</el-descriptions-item>
          <el-descriptions-item :label="t('effectiveContentFiles')">{{ scanStats.files_with_content || 0 }}</el-descriptions-item>
          <el-descriptions-item :label="t('chunkCount')">{{ scanStats.chunk_count || 0 }}</el-descriptions-item>
          <el-descriptions-item :label="t('routeCount')">{{ scanStats.route_count || 0 }}</el-descriptions-item>
          <el-descriptions-item :label="t('routeSourceFiles')">{{ scanStats.route_source_files || 0 }}</el-descriptions-item>
          <el-descriptions-item :label="t('oversizedFilesSkipped')">{{ scanStats.oversized_files_skipped || 0 }}</el-descriptions-item>
          <el-descriptions-item :label="t('oversizedFilesCompacted')">{{ scanStats.oversized_files_compacted || 0 }}</el-descriptions-item>
          <el-descriptions-item :label="t('ruleHitCount')">{{ scanStats.rule_hit_count || 0 }}</el-descriptions-item>
          <el-descriptions-item v-if="tokenStats" :label="t('tokenUsage')">
            <span>{{ t('promptTokens') }}: {{ tokenStats.prompt_tokens?.toLocaleString() || 0 }} / {{ t('completionTokens') }}: {{ tokenStats.completion_tokens?.toLocaleString() || 0 }}</span>
            <span style="margin-left: 12px; color: var(--el-color-info)">({{ tokenStats.llm_call_count || 0 }} {{ t('llmCalls') }})</span>
          </el-descriptions-item>
        </el-descriptions>
        <div
          v-if="scanStats.partial_audit || scanStats.truncated_by_audit_file_count || scanStats.truncated_by_code_chunks || scanStats.truncated_by_total_chars"
          class="warning-notice"
        >
          <div>{{ t('scanTruncatedNotice') }}</div>
          <div v-if="scanStats.oversized_files_skipped">{{ t('oversizedFilesSkippedNotice', { count: scanStats.oversized_files_skipped }) }}</div>
          <div v-if="scanStats.truncated_by_audit_file_count">{{ t('auditFilesTruncatedNotice', { selected: scanStats.files_selected_for_audit || 0, skipped: scanStats.files_skipped_by_audit_file_budget || 0 }) }}</div>
          <div v-if="scanStats.truncated_by_code_chunks">{{ t('codeChunksTruncatedNotice') }}</div>
          <div v-if="scanStats.truncated_by_total_chars">{{ t('totalCharsTruncatedNotice') }}</div>
        </div>
      </el-card>

      <el-card v-if="ruleHitsPreview.length" style="margin-bottom: 20px">
        <template #header>
          <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; cursor: pointer" @click="ruleHitsExpanded = !ruleHitsExpanded">
            <div style="display: flex; align-items: center; gap: 8px">
              <span class="card-title">{{ t('ruleHitPreview') }}</span>
              <el-tag type="warning" size="small">Top {{ ruleHitsPreview.length }}</el-tag>
            </div>
            <el-button size="small" text :icon="ruleHitsExpanded ? 'ArrowUp' : 'ArrowDown'" @click.stop="ruleHitsExpanded = !ruleHitsExpanded">
              {{ ruleHitsExpanded ? t('collapse') : t('expand') }}
            </el-button>
          </div>
        </template>
        <div v-show="ruleHitsExpanded" style="display: grid; gap: 10px">
          <el-collapse v-model="expandedRuleHits">
            <el-collapse-item
              v-for="(hit, index) in ruleHitsPreview"
              :key="`${hit.file_path || 'rule'}-${hit.label || 'hit'}-${index}`"
              :name="index"
            >
              <template #title>
                <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap">
                  <strong>{{ formatRuleHitTitle(hit) }}</strong>
                  <el-tag size="small" type="danger">{{ hit.label || 'rule' }}</el-tag>
                  <el-tag size="small" type="info">score {{ hit.risk_score || 0 }}</el-tag>
                  <el-tag size="small" type="warning">hits {{ hit.keyword_hit_count || 0 }}</el-tag>
                  <el-tag v-if="hit.chunk_type && hit.chunk_type !== 'full'" size="small" type="" effect="plain">{{ hit.chunk_type }}</el-tag>
                  <span v-if="hitStageLabels(hit)" style="color: var(--text-muted); font-size: 12px">{{ t('relatedStages') }}: {{ hitStageLabels(hit) }}</span>
                </div>
              </template>
              <div style="color: var(--text-secondary); font-size: 13px; line-height: 1.8; word-break: break-all; padding: 4px 0">
                <div><strong>{{ t('hitFile') }}:</strong> {{ hit.file_path || '--' }}</div>
                <div><strong>{{ t('hitChunk') }}:</strong> {{ hit.chunk_path || '--' }}</div>
                <div><strong>{{ t('hitEvidence') }}:</strong> {{ formatRuleHitEvidence(hit) }}</div>
              </div>
            </el-collapse-item>
          </el-collapse>
        </div>
      </el-card>

      <el-card style="margin-bottom: 20px">
        <template #header>
          <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap">
            <span class="card-title">{{ t('rescanRecommendations') }}</span>
            <el-tag size="small" type="success">{{ t('recommendationCount', { count: rescanRecommendations.length }) }}</el-tag>
          </div>
        </template>
        <div style="display: grid; gap: 10px">
          <div
            v-for="(item, index) in rescanRecommendations"
            :key="`recommendation-${index}`"
            class="recommendation-item"
          >
            <strong style="margin-right: 8px">{{ index + 1 }}.</strong>{{ item }}
          </div>
        </div>
      </el-card>

      <!-- 分阶段时间线 -->
      <el-card style="margin-bottom: 20px">
        <template #header><span class="card-title">{{ t('stageDetails') }}</span></template>
        <el-timeline>
          <!-- 第一阶段：架构分析 -->
          <el-timeline-item
            type="primary"
            :hollow="!archStage || archStage.status === 'pending'"
          >
            <div style="margin-bottom: 4px; color: #409EFF; font-weight: bold; font-size: 13px">{{ t('phaseArch') }}</div>
            <div v-if="archStage" style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap">
              <div>
                <strong>{{ archStage.stage_num }}. {{ archStage.stage_name }}</strong>
                <el-tag :type="statusType(archStage.status)" size="small" style="margin-left: 8px">{{ statusLabel(archStage.status) }}</el-tag>
              </div>
              <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap">
                <span style="color: var(--text-muted); font-size: 12px">{{ formatTimeOnly(archStage.started_at) }} ~ {{ formatTimeOnly(archStage.completed_at) }}</span>
                <el-button size="small" text type="primary" @click="goToStageOneDetail">{{ t('viewStageOneDetail') }}</el-button>
              </div>
            </div>
            <div v-if="archStage && stageSummary(archStage)" style="margin-top: 8px; color: var(--text-secondary); line-height: 1.6; white-space: pre-wrap">{{ stageSummary(archStage) }}</div>
            <el-collapse v-if="archStage?.findings?._debug" style="margin-top: 6px; border: none">
              <el-collapse-item :title="t('debugInfo')" name="debug-arch">
                <div style="color: var(--text-muted); font-size: 12px; white-space: pre-wrap">{{ debugSummary(archStage) }}</div>
              </el-collapse-item>
            </el-collapse>

            <!-- 扩展架构信息 -->
            <div v-if="archStage?.status === 'completed' && (middlewareChain.length || databaseModels.length || securityBoundaries || externalIntegrations.length)" style="margin-top: 12px">
              <el-descriptions :column="3" border size="small">
                <el-descriptions-item v-if="middlewareChain.length" :label="t('middlewareChain')">
                  <div style="display: flex; gap: 6px; flex-wrap: wrap">
                    <el-tag v-for="mw in middlewareChain.slice(0, 8)" :key="mw.name" size="small" type="info">{{ mw.name }}</el-tag>
                    <span v-if="middlewareChain.length > 8" style="color: var(--text-muted); font-size: 12px">+{{ middlewareChain.length - 8 }}</span>
                  </div>
                </el-descriptions-item>
                <el-descriptions-item v-if="databaseModels.length" :label="t('databaseModels')">
                  <div style="display: flex; gap: 6px; flex-wrap: wrap">
                    <el-tag v-for="dm in databaseModels.slice(0, 6)" :key="dm.model" size="small" type="warning">{{ dm.model }}{{ dm.table ? ` (${dm.table})` : '' }}</el-tag>
                    <span v-if="databaseModels.length > 6" style="color: var(--text-muted); font-size: 12px">+{{ databaseModels.length - 6 }}</span>
                  </div>
                </el-descriptions-item>
                <el-descriptions-item v-if="externalIntegrations.length" :label="t('externalIntegrations')">
                  <div style="display: flex; gap: 6px; flex-wrap: wrap">
                    <el-tag v-for="ei in externalIntegrations.slice(0, 6)" :key="ei.type" size="small">{{ ei.type }}</el-tag>
                    <span v-if="externalIntegrations.length > 6" style="color: var(--text-muted); font-size: 12px">+{{ externalIntegrations.length - 6 }}</span>
                  </div>
                </el-descriptions-item>
              </el-descriptions>
              <div v-if="securityBoundaries" style="margin-top: 8px; display: flex; gap: 12px; flex-wrap: wrap; font-size: 13px">
                <span v-if="securityBoundaries.public_routes?.length" style="color: #e6a23c">Public: {{ securityBoundaries.public_routes.length }}</span>
                <span v-if="securityBoundaries.authenticated_routes?.length" style="color: #409eff">Auth: {{ securityBoundaries.authenticated_routes.length }}</span>
                <span v-if="securityBoundaries.admin_routes?.length" style="color: #f56c6c">Admin: {{ securityBoundaries.admin_routes.length }}</span>
                <span v-if="securityBoundaries.unclassified_routes?.length" class="text-muted">Unknown: {{ securityBoundaries.unclassified_routes.length }}</span>
              </div>
            </div>

            <!-- 覆盖缺口分析 -->
            <div v-if="gapAnalysis && gapAnalysis.overall_health !== 'ok'" style="margin-top: 10px; padding: 8px 12px; border-radius: 8px; background: var(--bg-danger); border: 1px solid var(--border-danger); font-size: 12px; color: var(--text-danger); line-height: 1.6">
              <span style="font-weight: 600">{{ t('gapAnalysis') }}：</span>
              <span v-if="gapAnalysis.missing_routes?.length">{{ t('missingRoutes') }}: {{ gapAnalysis.missing_routes.length }}</span>
              <span v-if="gapAnalysis.missing_fields?.length" style="margin-left: 8px">{{ t('missingFields') }}: {{ gapAnalysis.missing_fields.join(', ') }}</span>
              <span v-if="gapAnalysis.missing_must_cover?.length" style="margin-left: 8px">{{ t('missingMustCover') }}: {{ gapAnalysis.missing_must_cover.length }}</span>
            </div>
          </el-timeline-item>

          <!-- 第二阶段：Supervisor 规划 -->
          <el-timeline-item
            color="#9b59b6"
            :hollow="!planStage || planStage.status === 'pending'"
          >
            <div style="margin-bottom: 4px; color: #9b59b6; font-weight: bold; font-size: 13px">{{ t('phasePlan') }}</div>
            <div v-if="planStage" style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap">
              <div>
                <strong>{{ planStage.stage_name }}</strong>
                <el-tag :type="statusType(planStage.status)" size="small" style="margin-left: 8px">{{ statusLabel(planStage.status) }}</el-tag>
              </div>
              <span style="color: var(--text-muted); font-size: 12px">{{ formatTimeOnly(planStage.started_at) }} ~ {{ formatTimeOnly(planStage.completed_at) }}</span>
            </div>
            <div v-if="planStage && supervisorSummary(planStage)" style="margin-top: 8px; color: var(--text-secondary); line-height: 1.6; white-space: pre-wrap">{{ supervisorSummary(planStage) }}</div>
            <div v-if="!planStage" class="text-muted">{{ t('waitPhase1Complete') }}</div>
          </el-timeline-item>

          <!-- 第三阶段：子 Agent 审计 -->
          <el-timeline-item
            color="#e6a23c"
            :hollow="auditStages.every(s => s.status === 'pending')"
          >
            <div style="margin-bottom: 8px; color: #e6a23c; font-weight: bold; font-size: 13px">{{ t('phaseAudit') }}</div>
            <div style="display: grid; gap: 12px">
              <div
                v-for="stage in auditStages"
                :key="stage.id"
                :style="stageStyle(stage.status)"
              >
                <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap">
                  <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap">
                    <strong :style="{ textDecoration: stage.status === 'skipped' ? 'line-through' : 'none' }">{{ stage.stage_num }}. {{ stage.stage_name }}</strong>
                    <el-tag :type="statusType(stage.status)" size="small">{{ statusLabel(stage.status) }}</el-tag>
                    <el-tag v-if="stage.agent_role === 'sub_agent'" size="small" type="warning" effect="plain">Agent</el-tag>
                    <el-tag v-if="vulnCountForStage(stage.stage_num) > 0" size="small" type="danger" effect="plain">{{ vulnCountForStage(stage.stage_num) }} {{ t('vulnerabilities') }}</el-tag>
                  </div>
                  <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap">
                    <span style="color: var(--text-muted); font-size: 12px">{{ formatTimeOnly(stage.started_at) }} ~ {{ formatTimeOnly(stage.completed_at) }}</span>
                  </div>
                </div>
                <div v-if="stage.agent_role === 'sub_agent' && agentFocusGuidance(stage.stage_num)" style="margin-top: 4px; padding: 5px 10px; border-radius: 6px; background: var(--bg-warning); color: var(--text-warning); font-size: 12px; line-height: 1.5">
                  {{ agentFocusGuidance(stage.stage_num) }}
                </div>
                <div v-if="stage.status === 'skipped' && stage.findings?.skip_reason" style="margin-top: 4px; color: var(--text-muted); font-size: 12px">
                  {{ stage.findings.skip_reason }}
                </div>
                <div v-if="stageSummary(stage) && stage.status !== 'skipped'" style="margin-top: 6px; color: var(--text-secondary); line-height: 1.6; white-space: pre-wrap; font-size: 13px">{{ stageSummary(stage) }}</div>
                <el-collapse v-if="stageRecoveryNote(stage) || (stage.findings?._debug && stage.status !== 'skipped')" style="margin-top: 6px; border: none">
                  <el-collapse-item :title="t('debugInfo')" :name="`debug-${stage.stage_num}`">
                    <div v-if="stageRecoveryNote(stage)" style="padding: 6px 8px; border-radius: 6px; background: var(--bg-warning); color: var(--text-warning); font-size: 12px; line-height: 1.5; margin-bottom: 6px">
                      {{ stageRecoveryNote(stage) }}
                    </div>
                    <div v-if="stage.findings?._debug && stage.status !== 'skipped'" style="color: var(--text-muted); font-size: 12px; white-space: pre-wrap">{{ debugSummary(stage) }}</div>
                  </el-collapse-item>
                </el-collapse>
              </div>
            </div>
          </el-timeline-item>

          <!-- 第四阶段：Supervisor 审核 -->
          <el-timeline-item
            color="#9b59b6"
            :hollow="!reviewStage || reviewStage.status === 'pending'"
          >
            <div style="margin-bottom: 4px; color: #9b59b6; font-weight: bold; font-size: 13px">{{ t('phaseReview') }}</div>
            <div v-if="reviewStage" style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap">
              <div>
                <strong>{{ reviewStage.stage_name }}</strong>
                <el-tag :type="statusType(reviewStage.status)" size="small" style="margin-left: 8px">{{ statusLabel(reviewStage.status) }}</el-tag>
              </div>
              <span style="color: var(--text-muted); font-size: 12px">{{ formatTimeOnly(reviewStage.started_at) }} ~ {{ formatTimeOnly(reviewStage.completed_at) }}</span>
            </div>
            <div v-if="reviewStage && supervisorSummary(reviewStage)" style="margin-top: 8px; color: var(--text-secondary); line-height: 1.6; white-space: pre-wrap">{{ supervisorSummary(reviewStage) }}</div>
            <div v-if="reviewRerunExecution" style="margin-top: 8px; padding: 8px 12px; border-radius: 8px; background: var(--bg-info); border: 1px solid var(--border-info); color: var(--text-info); line-height: 1.6; font-size: 13px">
              <div>
                <strong>{{ t('reviewRerunExecuted') }}：</strong>{{ reviewRerunStageText(reviewRerunExecution.executed_stage_nums || []) || '--' }}
              </div>
              <div v-if="reviewRerunExecution.requested_stage_nums?.length" style="margin-top: 4px">
                <strong>{{ t('reviewRerunRequested') }}：</strong>{{ reviewRerunStageText(reviewRerunExecution.requested_stage_nums) }}
              </div>
            </div>
            <div v-else-if="reviewStage?.findings?.request_rerun && reviewRequestedStageNums.length" style="margin-top: 8px; padding: 8px 12px; border-radius: 8px; background: var(--bg-warning); border: 1px solid var(--border-warning); color: var(--text-warning); line-height: 1.6; font-size: 13px">
              <strong>{{ t('reviewRerunPending') }}：</strong>{{ reviewRerunStageText(reviewRequestedStageNums) }}
            </div>
            <div v-if="reviewStage?.findings?.additional_guidance" style="margin-top: 8px; color: var(--text-muted); line-height: 1.6; white-space: pre-wrap; font-size: 13px">
              <strong>{{ t('reviewAdditionalGuidance') }}：</strong>{{ reviewStage.findings.additional_guidance }}
            </div>
            <div v-if="!reviewStage" class="text-muted">{{ t('waitSubAgentComplete') }}</div>
          </el-timeline-item>
        </el-timeline>
      </el-card>

      <!-- 阶段一覆盖摘要 -->
      <el-card v-if="stageOneStage" style="margin-bottom: 20px">
        <template #header>
          <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap">
            <span class="card-title">{{ t('stageOneCoverageSummary') }}</span>
            <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap">
              <span v-if="stageOneArtifact?.artifact_path" style="color: var(--text-muted); font-size: 12px">{{ t('artifactPath') }}={{ stageOneArtifact.artifact_path }}</span>
              <el-button size="small" text type="primary" :loading="stageOneArtifactLoading" @click="loadStageOneArtifact">{{ t('refreshArtifact') }}</el-button>
              <el-button size="small" type="primary" plain @click="goToStageOneDetail">{{ t('viewStageOneDetail') }}</el-button>
            </div>
          </div>
        </template>
        <el-descriptions :column="4" border size="small">
          <el-descriptions-item :label="t('batchCount')">
            {{ stageOneArtifact?.payload?.pass_count || 0 }}/{{ stageOneStage.findings?._debug?.planned_batch_count || stageOneArtifact?.payload?.pass_count || 0 }}
          </el-descriptions-item>
          <el-descriptions-item :label="t('identifiedRouteCount')">{{ stageOneRouteCount }}</el-descriptions-item>
          <el-descriptions-item :label="t('staticRoutes')">{{ stageOneGapSummary.static_route_count || 0 }}</el-descriptions-item>
          <el-descriptions-item :label="t('missingRoutes')">{{ stageOneGapSummary.missing_route_count || 0 }}</el-descriptions-item>
          <el-descriptions-item :label="t('auditScopeCoverage')">
            {{ formatPercent(stageOneCoverageRatio) }}
          </el-descriptions-item>
          <el-descriptions-item :label="t('coveredPathCount')">{{ stageOneCoverage.covered_paths?.length || 0 }}</el-descriptions-item>
          <el-descriptions-item :label="t('compactedChunks')">{{ stageOneCoverage.compacted_chunk_count || 0 }}</el-descriptions-item>
          <el-descriptions-item :label="t('signalWindowChunks')">{{ stageOneCoverage.signal_window_chunk_count || 0 }}</el-descriptions-item>
        </el-descriptions>
        <div style="margin-top: 10px; color: var(--text-muted); font-size: 12px; line-height: 1.6">
          {{ stageOneCoverageNote }}
        </div>
      </el-card>

      <!-- 漏洞列表 -->
      <el-card>
        <template #header>
          <div style="display: flex; justify-content: space-between; align-items: center">
            <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap">
              <span class="card-title">{{ t('vulnerabilities') }} ({{ vulns.length }})</span>
              <el-tag size="small" type="danger">{{ severityLabel('Critical') }} {{ severityStats.Critical }}</el-tag>
              <el-tag size="small" type="warning">{{ severityLabel('High') }} {{ severityStats.High }}</el-tag>
            </div>
            <div style="display: flex; gap: 8px">
              <el-select v-model="filter.severity" :placeholder="t('severity')" clearable size="small" style="width: 120px" @change="handleFilter">
                <el-option :label="severityLabel('Critical')" value="Critical" />
                <el-option :label="severityLabel('High')" value="High" />
                <el-option :label="severityLabel('Medium')" value="Medium" />
                <el-option :label="severityLabel('Low')" value="Low" />
              </el-select>
            </div>
          </div>
        </template>
        <div v-if="vulns.length">
          <VulnCard v-for="v in vulns" :key="v.id" :vuln="v" @click="router.push(`/vulns/${v.id}`)" />
        </div>
        <el-empty v-else :description="t('noVulnsInAudit')" :image-size="60" />
      </el-card>

      <el-card v-if="reports.length" style="margin-top: 20px">
        <template #header><span class="card-title">{{ t('generatedReports') }}</span></template>
        <el-table :data="reports" size="small">
          <el-table-column prop="filename" :label="t('file')" />
          <el-table-column :label="t('size')" width="100">
            <template #default="{ row }">{{ (row.size / 1024).toFixed(1) }} KB</template>
          </el-table-column>
          <el-table-column :label="t('action')" width="150">
            <template #default="{ row }">
              <el-button size="small" text type="primary" @click="window.open(row.download_url)">{{ t('download') }}</el-button>
              <el-button size="small" text type="danger" @click="handleDeleteReport(row)">{{ t('delete') }}</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-card>
    </div>
  </div>
</template>

<style scoped>
@keyframes spin {
  from { transform: rotate(0deg) }
  to { transform: rotate(360deg) }
}
</style>

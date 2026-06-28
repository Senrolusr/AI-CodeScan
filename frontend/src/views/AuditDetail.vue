<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { storeToRefs } from 'pinia'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  cancelAudit,
  deleteReport,
  downloadByUrl,
  exportReport,
  pauseAudit,
  resumeAudit,
  retryAudit,
} from '../api'
import StageProgress from '../components/StageProgress.vue'
import ScanOverview from '../components/ScanOverview.vue'
import RunDiagnosticsPanel from '../components/audit/RunDiagnosticsPanel.vue'
import RunActivityStream from '../components/audit/RunActivityStream.vue'
import FindingList from '../components/audit/FindingList.vue'
import RuleHitsPreviewCard from '../components/audit/RuleHitsPreviewCard.vue'
import StageTimeline from '../components/audit/StageTimeline.vue'
import StageMatrixWorkbench from '../components/audit/StageMatrixWorkbench.vue'
import { useAuditDetailStore } from '../stores/auditDetail'
import { useI18n } from '../i18n'
import { isAuditRetryBlocked } from '../utils/auditTaskState'
import { usePolling } from '../composables/usePolling'
import { useAuditDerived } from '../composables/useAuditDerived'

const props = defineProps({ id: [String, Number] })
const router = useRouter()
const {
  locale,
  t,
  statusLabel,
  statusType,
  formatPercent,
  formatDateTime,
  formatTimeOnly,
} = useI18n()

const store = useAuditDetailStore()
const {
  task,
  stages,
  reports,
  stageOneArtifact,
  stageOneArtifactLoading,
  recentEvents,
  currentRun,
  agentRuns,
  diagnostics,
  loading,
  exporting,
  actionLoading,
  stageOneStage,
  stageOneRiskHints,
  routeCoverage,
} = storeToRefs(store)

const taskStatus = computed(() => task.value?.status || '')
const polling = usePolling({
  statusRef: taskStatus,
  fetchFn: async () => { await store.loadSnapshot() },
  onComplete: () => {
    store.loadSnapshot().finally(() => _notifyCompletion(task.value))
  },
})

// 派生 view-model（进度/覆盖/复核/质量/重扫建议等 ~25 computed + phase pill helper）
// 集中到 composable，便于单测；组件仅保留编排与 UI 反馈。
const {
  PHASE_KEY_MAP,
  currentPhase,
  isMultiAgentPhaseMode,
  stageOneCoverage,
  stageOneCoverageRatio,
  stageOneCoverageNote,
  stageOneRouteCount,
  stageOneGapSummary,
  scanStats,
  tokenStats,
  rescanRecommendations,
  hasRouteCoverageGaps,
  routeCoveragePercentValue,
  routeCoverageMissingRoutes,
  routeCoverageStageRows,
  reviewOutcome,
  isCompletedWithGaps,
  degradationNotes,
  workerFailure,
  hasQualityNotice,
  reviewNoticeClass,
  reviewStageNumsText,
  preDiscovery,
  preDiscoveryTech,
  preDiscoverySecurityCount,
  phasePillStyle,
  isPhaseDone,
  isPhaseRunning,
} = useAuditDerived(store, { t, locale })

// 快照抓取/状态已迁入 useAuditDetailStore；组件只保留轮询生命周期与 UI 反馈。

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
  try {
    await store.init(props.id)
  } catch {
    ElMessage.error(t('auditTaskNotFound'))
  }
  polling.start()
})

// M6：报告下载走鉴权 API（blob），替代无鉴权的 /reports 静态挂载 + window.open
function triggerBlobDownload(blob, filename) {
  const url = window.URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  window.URL.revokeObjectURL(url)
}

function filenameFromUrl(url) {
  const last = String(url || '').split('/').filter(Boolean).pop() || 'report'
  try {
    return decodeURIComponent(last)
  } catch (_e) {
    return last
  }
}

const handleDownloadReport = async (report) => {
  try {
    const { data } = await downloadByUrl(report.download_url)
    triggerBlobDownload(data, report.filename || filenameFromUrl(report.download_url))
  } catch {
    ElMessage.error(t('loadFailed'))
  }
}

const handleExport = async (format) => {
  exporting.value = true
  try {
    const res = await exportReport(parseInt(props.id, 10), format)
    const { data } = await downloadByUrl(res.data.download_url)
    triggerBlobDownload(data, filenameFromUrl(res.data.download_url))
    ElMessage.success(t('reportGenerated'))
    store.loadReports()
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
    await store.loadReports()
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
    await store.loadSnapshot()
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
    await store.loadSnapshot()
    polling.start()
  } catch (e) {
    ElMessage.error(e.friendlyMessage || t('retryFailed'))
  } finally {
    actionLoading.value = false
  }
}

const handlePause = async () => {
  actionLoading.value = true
  try {
    await pauseAudit(props.id)
    ElMessage.success(t('pauseStarted'))
    await store.loadSnapshot()
  } catch (e) {
    ElMessage.error(e.friendlyMessage || t('pauseFailed'))
  } finally {
    actionLoading.value = false
  }
}

const handleResume = async () => {
  actionLoading.value = true
  try {
    await resumeAudit(props.id)
    ElMessage.success(t('resumeStarted'))
    await store.loadSnapshot()
    polling.start()
  } catch (e) {
    ElMessage.error(e.friendlyMessage || t('resumeFailed'))
  } finally {
    actionLoading.value = false
  }
}

// 阶段一 artifact 手动刷新：强制重拉（绕过 store 的状态去重）。
const refreshStageOneArtifact = () => store.loadStageOneArtifact({ force: true })
// 漏洞列表点击跳详情（FindingList 通过 select 事件回传 vuln id）。
const goToVuln = (id) => router.push(`/vulns/${id}`)
const goToStageOneDetail = () => router.push(`/audits/${props.id}/stage-one`)
</script>

<template>
  <div v-loading="loading">
    <div v-if="task">
      <div class="page-header">
        <div>
          <h2 style="margin: 0 0 4px">{{ task.name || t('auditDetailTitle', { id: task.id }) }}</h2>
          <el-tag :type="statusType(task.status)" effect="dark">{{ statusLabel(task.status) }}</el-tag>
          <el-tag v-if="isCompletedWithGaps" type="warning" effect="plain" style="margin-left: 8px">{{ t('completedWithGaps') }}</el-tag>
          <span style="margin-left: 12px" class="text-muted">
            {{ t('projectWithDate', { projectId: task.project_id, createdAt: formatDateTime(task.created_at) }) }}
          </span>
        </div>
        <div style="display: flex; gap: 8px; flex-wrap: wrap">
          <el-button v-if="task.status === 'pending' || task.status === 'running' || task.status === 'paused'" type="warning" plain :loading="actionLoading" @click="handleCancel">{{ t('cancel') }}</el-button>
          <el-button v-if="task.status === 'running'" :loading="actionLoading" @click="handlePause">{{ t('pause') }}</el-button>
          <el-button v-if="task.status === 'paused'" type="primary" :loading="actionLoading" @click="handleResume">{{ t('resume') }}</el-button>
          <el-button v-if="task.status === 'completed' || task.status === 'failed' || task.status === 'cancelled'" :disabled="isAuditRetryBlocked(task)" :loading="actionLoading" @click="handleRetry">{{ t('retry') }}</el-button>
          <el-button type="primary" @click="handleExport('html')" :loading="exporting">{{ t('exportHtml') }}</el-button>
        </div>
      </div>

      <!-- 进度概览 -->
      <el-card style="margin-bottom: 20px">
        <template #header><span class="card-title">{{ t('auditProgress') }}</span></template>
        <StageProgress :stages="stages" />
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

          <div v-if="hasRouteCoverageGaps && routeCoverage" class="warning-surface" style="padding: 10px 12px; line-height: 1.6">
            <strong>{{ t('routeCoverage') }}：</strong>
            {{ t('routeCoverageSummary', {
              ratio: formatPercent(routeCoverage.coverage_ratio),
              missing: routeCoverage.missing_route_count || 0,
              total: routeCoverage.total_routes || 0,
            }) }}
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
        <div v-else-if="task.status === 'completed'" :style="{ color: isCompletedWithGaps ? '#E6A23C' : '#67C23A', fontSize: '13px', fontWeight: 'bold' }">
          <span v-if="isCompletedWithGaps">&#9888; {{ t('completedWithGaps') }}</span>
          <span v-else>&#10003; {{ t('completed') }}</span>
        </div>
        <div v-else-if="task.status === 'failed' || task.status === 'cancelled' || task.status === 'paused'" class="text-muted">
          {{ statusLabel(task.status) }}
        </div>
      </el-card>

      <ScanOverview :stats="scanStats" :token-stats="tokenStats" show-token-usage />

      <el-card style="margin-bottom: 20px">
        <template #header>
          <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap">
            <span class="card-title">{{ t('runActivity') }}</span>
            <div v-if="currentRun" style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap">
              <el-tag size="small" :type="statusType(currentRun.status)" effect="plain">{{ statusLabel(currentRun.status) }}</el-tag>
              <el-tag v-if="currentRun.mode && currentRun.mode !== 'full'" size="small" type="info" effect="plain">
                {{ currentRun.mode === 'rerun' ? t('retry') : currentRun.mode }}
              </el-tag>
              <span v-if="currentRun.started_at" class="text-muted" style="font-size: 12px">{{ formatDateTime(currentRun.started_at) }}</span>
            </div>
          </div>
        </template>
        <RunDiagnosticsPanel
          :diagnostics="diagnostics"
          :agent-runs="agentRuns"
          :current-run="currentRun"
          class="run-diagnostics-block"
        />
        <StageMatrixWorkbench
          :stages="stages"
          :agent-runs="agentRuns"
          :diagnostics="diagnostics"
          :route-coverage="routeCoverage"
          :vulnerabilities="store.vulns"
        />
        <RunActivityStream
          :task-id="props.id"
          :status="taskStatus"
          :initial-events="recentEvents"
        />
      </el-card>

      <el-card v-if="routeCoverage" style="margin-bottom: 20px">
        <template #header>
          <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap">
            <span class="card-title">{{ t('routeCoverage') }}</span>
            <el-tag size="small" :type="hasRouteCoverageGaps ? 'warning' : 'success'">
              {{ hasRouteCoverageGaps ? t('coverageGaps') : t('completed') }}
            </el-tag>
          </div>
        </template>

        <div style="display: grid; gap: 12px">
          <div>
            <div style="display: flex; justify-content: space-between; gap: 12px; font-size: 13px; margin-bottom: 6px">
              <span>{{ t('routeCoverageRatio') }}</span>
              <strong>{{ formatPercent(routeCoverage.coverage_ratio) }}</strong>
            </div>
            <el-progress :percentage="routeCoveragePercentValue" :status="hasRouteCoverageGaps ? 'warning' : 'success'" />
          </div>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px">
            <div style="padding: 10px 12px; border: 1px solid var(--border-default); border-radius: 8px; background: var(--bg-page)">
              <div style="color: var(--text-muted); font-size: 12px">{{ t('routeCount') }}</div>
              <strong>{{ routeCoverage.total_routes || 0 }}</strong>
            </div>
            <div style="padding: 10px 12px; border: 1px solid var(--border-default); border-radius: 8px; background: var(--bg-page)">
              <div style="color: var(--text-muted); font-size: 12px">{{ t('auditedRoutes') }}</div>
              <strong>{{ routeCoverage.audited_route_count || 0 }}</strong>
            </div>
            <div style="padding: 10px 12px; border: 1px solid var(--border-default); border-radius: 8px; background: var(--bg-page)">
              <div style="color: var(--text-muted); font-size: 12px">{{ t('attestedRoutes') }}</div>
              <strong>{{ routeCoverage.attested_route_count || 0 }}</strong>
            </div>
            <div style="padding: 10px 12px; border: 1px solid var(--border-default); border-radius: 8px; background: var(--bg-page)">
              <div style="color: var(--text-muted); font-size: 12px">{{ t('missingRouteCount') }}</div>
              <strong :style="{ color: hasRouteCoverageGaps ? '#E6A23C' : 'inherit' }">{{ routeCoverage.missing_route_count || 0 }}</strong>
            </div>
          </div>

          <div v-if="routeCoverageMissingRoutes.length" style="display: grid; gap: 8px">
            <div style="font-weight: 600; font-size: 13px">{{ t('missingRouteSamples') }}</div>
            <div
              v-for="route in routeCoverageMissingRoutes"
              :key="route.route_id || `${route.method}-${route.path}`"
              style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap; font-size: 13px; padding: 8px 10px; border: 1px solid var(--border-default); border-radius: 8px; background: var(--bg-page)"
            >
              <el-tag size="small" effect="plain">{{ route.method || 'UNKNOWN' }}</el-tag>
              <strong style="word-break: break-all">{{ route.path || '--' }}</strong>
              <span v-if="route.file_path" style="color: var(--text-muted); word-break: break-all">{{ route.file_path }}</span>
            </div>
            <div v-if="routeCoverage.unknown_missing_route_count" style="color: var(--text-muted); font-size: 12px">
              {{ t('unknownRouteGaps', { count: routeCoverage.unknown_missing_route_count }) }}
            </div>
          </div>

          <div v-if="routeCoverageStageRows.length" style="display: grid; gap: 8px">
            <div style="font-weight: 600; font-size: 13px">{{ t('stageRouteCoverage') }}</div>
            <div
              v-for="row in routeCoverageStageRows"
              :key="`route-stage-${row.stage_num}`"
              style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap; font-size: 13px"
            >
              <strong>Stage {{ row.stage_num }}</strong>
              <span v-if="row.stage_name" style="color: var(--text-muted)">{{ row.stage_name }}</span>
              <el-tag size="small" effect="plain">{{ t('attestedRoutes') }}: {{ row.attested_route_count || 0 }}</el-tag>
              <el-tag size="small" :type="row.missing_focus_route_count ? 'warning' : 'success'" effect="plain">
                {{ t('focusRouteGaps') }}: {{ row.missing_focus_route_count || 0 }}
              </el-tag>
            </div>
          </div>
        </div>
      </el-card>

      <RuleHitsPreviewCard />

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
      <StageTimeline @view-stage-one="goToStageOneDetail" />

      <!-- 阶段一覆盖摘要 -->
      <el-card v-if="stageOneStage" style="margin-bottom: 20px">
        <template #header>
          <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap">
            <span class="card-title">{{ t('stageOneCoverageSummary') }}</span>
            <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap">
              <span v-if="stageOneArtifact?.artifact_path" style="color: var(--text-muted); font-size: 12px">{{ t('artifactPath') }}={{ stageOneArtifact.artifact_path }}</span>
              <el-button size="small" text type="primary" :loading="stageOneArtifactLoading" @click="refreshStageOneArtifact">{{ t('refreshArtifact') }}</el-button>
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
          <el-descriptions-item :label="t('riskHints')">{{ stageOneRiskHints.length }}</el-descriptions-item>
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
      <FindingList @select="goToVuln" />

      <el-card v-if="reports.length" style="margin-top: 20px">
        <template #header><span class="card-title">{{ t('generatedReports') }}</span></template>
        <el-table :data="reports" size="small">
          <el-table-column prop="filename" :label="t('file')" />
          <el-table-column :label="t('size')" width="100">
            <template #default="{ row }">{{ (row.size / 1024).toFixed(1) }} KB</template>
          </el-table-column>
          <el-table-column :label="t('action')" width="150">
            <template #default="{ row }">
              <el-button size="small" text type="primary" @click="handleDownloadReport(row)">{{ t('download') }}</el-button>
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

.run-diagnostics-block {
  margin-bottom: 14px;
}
</style>

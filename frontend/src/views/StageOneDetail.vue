<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { getAudit, getAuditStage, getAuditStageArtifact } from '../api'
import { useI18n } from '../i18n'
import { usePolling } from '../composables/usePolling'
import ScanOverview from '../components/ScanOverview.vue'
import { normalizeScanStats } from '../utils/scanStats'

const props = defineProps({ id: [String, Number] })
const router = useRouter()
const { t, statusLabel, boolLabel, formatPercent } = useI18n()

const loading = ref(true)
const task = ref(null)
const stageOneStage = ref(null)
const artifact = ref(null)
const artifactLoading = ref(false)
const routeFilter = ref({ keyword: '', auth: '' })

const taskStatus = computed(() => task.value?.status || '')
const polling = usePolling({
  statusRef: taskStatus,
  intervals: { running: 3000, pending: 3000 },
  fetchFn: async () => { await loadBase(); await loadArtifact() },
})

const stageOneCoverage = computed(() => stageOneStage.value?.compressed_summary?.coverage || {})
const stageOneCoverageRatio = computed(() => {
  const total = Number(stageOneCoverage.value.audit_scope_chunk_count || stageOneCoverage.value.total_chunk_count || 0)
  const scanned = Number(stageOneCoverage.value.scanned_chunk_count || 0)
  return scanned / Math.max(total || 1, 1)
})
const stageOneCoverageNote = computed(() => stageOneCoverage.value.audit_scope_note || t('auditScopeCoverageNote'))
const stageOneArchitecture = computed(() => stageOneStage.value?.findings?.architecture_info || {})
const stageOneSummary = computed(() => stageOneStage.value?.findings?.stage_summary || '')
const stageOneEntryPoints = computed(() => {
  const ep = stageOneArchitecture.value?.entry_points
  return Array.isArray(ep) ? ep : []
})
const stageOneOutputPoints = computed(() => {
  const op = stageOneArchitecture.value?.output_points
  return Array.isArray(op) ? op : []
})
const stageOneModules = computed(() => {
  const mods = stageOneArchitecture.value?.modules
  return Array.isArray(mods) ? mods : []
})
const stageOneDataFlows = computed(() => {
  const df = stageOneArchitecture.value?.data_flows
  return Array.isArray(df) ? df : []
})
const stageOneRoutes = computed(() => Array.isArray(stageOneStage.value?.findings?.architecture_info?.routes) ? stageOneStage.value.findings.architecture_info.routes : [])
const taskSummary = computed(() => {
  const summary = task.value?.summary
  return summary && typeof summary === 'object' ? summary : {}
})
const scanStats = computed(() => {
  const value = taskSummary.value.scan_stats
  return normalizeScanStats(value, {
    routeCountFallback: routeGapSummary.value.static_route_count || stageOneRoutes.value.length || 0,
  })
})
const filteredStageOneRoutes = computed(() => {
  const keyword = routeFilter.value.keyword.trim().toLowerCase()
  const auth = routeFilter.value.auth
  return stageOneRoutes.value.filter((route) => {
    const matchesKeyword = !keyword || [route.method, route.path, route.handler, route.file_path, ...(Array.isArray(route.params) ? route.params : [])]
      .some(value => String(value || '').toLowerCase().includes(keyword))
    const matchesAuth = !auth || route.auth === auth
    return matchesKeyword && matchesAuth
  })
})
const stageOneEarlyStop = computed(() => artifact.value?.payload?.early_stop || { triggered: false, reason: '', after_pass: 0 })
const stageOnePasses = computed(() => Array.isArray(artifact.value?.payload?.passes) ? artifact.value.payload.passes : [])
const showAllPasses = ref(false)
const stageOnePassSummary = computed(() => artifact.value?.payload?.pass_summary || {
  executed_pass_count: stageOnePasses.value.length,
  total_prompt_length: 0,
  total_code_length: 0,
  max_coverage_ratio: 0,
  avg_signal_gain: 0,
  peak_signal_gain: 0,
  new_path_total: 0,
  compacted_chunk_total: 0,
})
const displayedStageOnePasses = computed(() => {
  if (showAllPasses.value || stageOnePasses.value.length <= 3) return stageOnePasses.value
  return stageOnePasses.value.slice(-3)
})
const hiddenStageOnePassCount = computed(() => Math.max(stageOnePasses.value.length - displayedStageOnePasses.value.length, 0))
const routeGapSummary = computed(() => artifact.value?.payload?.route_gap_summary || { static_route_count: 0, confirmed_route_count: 0, missing_route_count: 0, missing_route_samples: [] })
const missingRouteSamples = computed(() => Array.isArray(routeGapSummary.value?.missing_route_samples) ? routeGapSummary.value.missing_route_samples : [])
const projectSummaryClass = computed(() => stageOneSummary.value ? 'stage-one-summary' : 'stage-one-summary is-empty')

const authLabel = (value) => ({
  JWT: t('authJwt'),
  Session: t('authSession'),
  OAuth: t('authOAuth'),
  Unknown: t('authUnknown'),
  None: t('authNone'),
}[value] || value || t('unknown'))

// 阶段一专页直接拉取完整单阶段详情，避免依赖轻量阶段列表。
const loadBase = async () => {
  const [taskRes, stageRes] = await Promise.all([getAudit(props.id), getAuditStage(props.id, 1)])
  task.value = taskRes.data
  stageOneStage.value = stageRes.data
}

const loadArtifact = async () => {
  const stageOne = stageOneStage.value
  if (!stageOne?.artifact_path) {
    artifact.value = null
    return
  }
  artifactLoading.value = true
  try {
    const res = await getAuditStageArtifact(props.id, 1)
    artifact.value = res.data
  } catch {
    artifact.value = null
  } finally {
    artifactLoading.value = false
  }
}

const loadData = async () => {
  try {
    await loadBase()
    await loadArtifact()
  } catch {
    ElMessage.error(t('stageOneLoadFailed'))
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  await loadData()
  polling.start()
})

const togglePassDetails = () => {
  showAllPasses.value = !showAllPasses.value
}

const previewList = (value, limit = 8) => Array.isArray(value) ? value.slice(0, limit) : []
</script>

<template>
  <div v-loading="loading">
    <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 20px; flex-wrap: wrap">
      <div>
        <h2 style="margin: 0 0 4px">{{ t('stageOneTitle') }}</h2>
        <div class="text-muted">
          {{ t('audit') }} #{{ task?.id || props.id }} | {{ t('project') }} #{{ task?.project_id || '-' }} | {{ statusLabel(task?.status || '-') }}
        </div>
      </div>
      <div style="display: flex; gap: 8px; flex-wrap: wrap">
        <el-button @click="router.push(`/audits/${props.id}`)">{{ t('backToAudit') }}</el-button>
        <el-button type="primary" plain :loading="artifactLoading" @click="loadArtifact">{{ t('refreshStageOne') }}</el-button>
      </div>
    </div>

    <!-- 项目概况卡片 -->
    <el-card v-if="stageOneStage" style="margin-bottom: 20px; border-left: 4px solid #409EFF">
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px">
          <span style="font-weight: bold; font-size: 16px">{{ t('projectProfile') }}</span>
          <el-tag v-if="stageOneStage.status === 'completed'" type="success" size="small">{{ statusLabel('completed') }}</el-tag>
          <el-tag v-else-if="stageOneStage.status === 'running'" type="warning" size="small">{{ statusLabel('running') }}</el-tag>
        </div>
      </template>

      <!-- 阶段摘要 -->
      <div :class="projectSummaryClass">
        <div v-if="stageOneSummary" class="stage-one-summary-title">{{ t('projectOverview') }}</div>
        {{ stageOneSummary || t('noProjectSummary') }}
      </div>

      <!-- 技术栈概览 -->
      <el-descriptions :column="4" border size="small" style="margin-bottom: 20px">
        <el-descriptions-item :label="t('techStack')" :span="1">
          <template v-if="stageOneArchitecture.tech_stack">
            <el-tag v-for="tech in String(stageOneArchitecture.tech_stack).split(/[,，、;\s]+/).filter(Boolean).slice(0, 8)" :key="tech" size="small" effect="plain" style="margin: 2px">{{ tech }}</el-tag>
          </template>
          <span v-else class="text-muted">-</span>
        </el-descriptions-item>
        <el-descriptions-item :label="t('framework')">{{ stageOneArchitecture.framework || '-' }}</el-descriptions-item>
        <el-descriptions-item :label="t('database')">{{ stageOneArchitecture.database || '-' }}</el-descriptions-item>
        <el-descriptions-item :label="t('authMechanism')">{{ stageOneArchitecture.auth_mechanism || '-' }}</el-descriptions-item>
      </el-descriptions>

      <!-- 入口点 / 输出点 / 核心模块 / 数据流 -->
      <div style="display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px">
        <!-- 入口点 -->
        <div v-if="stageOneEntryPoints.length" style="padding: 14px 16px; background: var(--bg-success); border-radius: 10px; border: 1px solid var(--border-success)">
          <div style="font-weight: bold; color: #67C23A; margin-bottom: 10px; font-size: 14px">{{ t('entryPoints') }} ({{ stageOneEntryPoints.length }})</div>
          <div style="display: flex; gap: 6px; flex-wrap: wrap">
            <el-tag v-for="(ep, idx) in stageOneEntryPoints.slice(0, 12)" :key="'ep-'+idx" size="small" type="success" effect="plain">{{ typeof ep === 'string' ? ep : ep.path || ep.name || ep.url || JSON.stringify(ep) }}</el-tag>
            <el-tag v-if="stageOneEntryPoints.length > 12" size="small" type="info" effect="plain">+{{ stageOneEntryPoints.length - 12 }}</el-tag>
          </div>
        </div>

        <!-- 输出点 -->
        <div v-if="stageOneOutputPoints.length" style="padding: 14px 16px; background: var(--bg-warning); border-radius: 10px; border: 1px solid var(--border-warning)">
          <div style="font-weight: bold; color: #E6A23C; margin-bottom: 10px; font-size: 14px">{{ t('outputPoints') }} ({{ stageOneOutputPoints.length }})</div>
          <div style="display: flex; gap: 6px; flex-wrap: wrap">
            <el-tag v-for="(op, idx) in stageOneOutputPoints.slice(0, 12)" :key="'op-'+idx" size="small" type="warning" effect="plain">{{ typeof op === 'string' ? op : op.path || op.name || op.type || JSON.stringify(op) }}</el-tag>
            <el-tag v-if="stageOneOutputPoints.length > 12" size="small" type="info" effect="plain">+{{ stageOneOutputPoints.length - 12 }}</el-tag>
          </div>
        </div>

        <!-- 核心模块 -->
        <div v-if="stageOneModules.length" style="padding: 14px 16px; background: var(--bg-alt); border-radius: 10px; border: 1px solid var(--border-default)">
          <div style="font-weight: bold; color: var(--text-muted); margin-bottom: 10px; font-size: 14px">{{ t('coreModules') }} ({{ stageOneModules.length }})</div>
          <div style="display: flex; gap: 6px; flex-wrap: wrap">
            <el-tag v-for="(mod, idx) in stageOneModules.slice(0, 16)" :key="'mod-'+idx" size="small" effect="plain">{{ typeof mod === 'string' ? mod : mod.name || mod.path || JSON.stringify(mod) }}</el-tag>
            <el-tag v-if="stageOneModules.length > 16" size="small" type="info" effect="plain">+{{ stageOneModules.length - 16 }}</el-tag>
          </div>
        </div>

        <!-- 数据流 -->
        <div v-if="stageOneDataFlows.length" style="padding: 14px 16px; background: var(--bg-danger); border-radius: 10px; border: 1px solid var(--border-danger)">
          <div style="font-weight: bold; color: #F56C6C; margin-bottom: 10px; font-size: 14px">{{ t('dataFlows') }} ({{ stageOneDataFlows.length }})</div>
          <div style="display: flex; flex-direction: column; gap: 4px">
            <div v-for="(df, idx) in stageOneDataFlows.slice(0, 8)" :key="'df-'+idx" style="font-size: 13px; color: var(--text-secondary); line-height: 1.6">
              <span style="color: #F56C6C; margin-right: 6px">&#10148;</span>{{ typeof df === 'string' ? df : df.description || df.flow || JSON.stringify(df) }}
            </div>
            <div v-if="stageOneDataFlows.length > 8" style="font-size: 12px; color: var(--text-muted)">+{{ stageOneDataFlows.length - 8 }} {{ t('moreItems') }}</div>
          </div>
        </div>
      </div>

      <!-- 快速统计 -->
      <div style="margin-top: 20px; display: flex; gap: 24px; flex-wrap: wrap; padding: 12px 16px; background: var(--bg-alt); border-radius: 8px; font-size: 13px; color: var(--text-secondary)">
        <span>{{ t('staticRoutes') }}: <strong>{{ stageOneRoutes.length }}</strong></span>
        <span>{{ t('entryPoints') }}: <strong>{{ stageOneEntryPoints.length }}</strong></span>
        <span>{{ t('outputPoints') }}: <strong>{{ stageOneOutputPoints.length }}</strong></span>
        <span>{{ t('coreModules') }}: <strong>{{ stageOneModules.length }}</strong></span>
        <span>{{ t('dataFlows') }}: <strong>{{ stageOneDataFlows.length }}</strong></span>
        <span>{{ t('auditScopeCoverage') }}: <strong>{{ formatPercent(stageOneCoverageRatio) }}</strong></span>
      </div>
      <div style="margin-top: 8px; color: var(--text-muted); font-size: 12px; line-height: 1.6">
        {{ stageOneCoverageNote }}
      </div>
    </el-card>

    <el-card v-if="stageOneStage" style="margin-bottom: 20px">
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap">
          <span class="card-title">{{ t('stageOneOverview') }}</span>
          <span v-if="artifact?.artifact_path" style="color: var(--text-muted); font-size: 12px">{{ t('artifactPath') }}={{ artifact.artifact_path }}</span>
        </div>
      </template>
      <el-descriptions :column="4" border size="small">
        <el-descriptions-item :label="t('passCount')">{{ artifact?.payload?.pass_count || 0 }}/{{ stageOneStage.findings?._debug?.planned_batch_count || artifact?.payload?.pass_count || 0 }}</el-descriptions-item>
        <el-descriptions-item :label="t('auditScopeCoverage')">{{ formatPercent(stageOneCoverageRatio) }}</el-descriptions-item>
        <el-descriptions-item :label="t('coveredFiles')">{{ stageOneCoverage.covered_paths?.length || 0 }}</el-descriptions-item>
        <el-descriptions-item :label="t('compactedFiles')">{{ stageOneCoverage.compacted_paths?.length || 0 }}</el-descriptions-item>
        <el-descriptions-item :label="t('staticRoutes')">{{ routeGapSummary.static_route_count || 0 }}</el-descriptions-item>
        <el-descriptions-item :label="t('confirmedRoutes')">{{ routeGapSummary.confirmed_route_count || 0 }}</el-descriptions-item>
        <el-descriptions-item :label="t('missingRoutes')">{{ routeGapSummary.missing_route_count || 0 }}</el-descriptions-item>
        <el-descriptions-item :label="t('riskWindowCompression')">{{ stageOneCoverage.signal_window_chunk_count || 0 }}</el-descriptions-item>
      </el-descriptions>
      <div style="margin-top: 10px; color: var(--text-muted); font-size: 12px; line-height: 1.6">
        {{ stageOneCoverageNote }}
      </div>
      <div v-if="stageOneEarlyStop.triggered" style="margin-top: 14px; padding: 10px 12px; border-radius: 8px; background: var(--bg-warning); color: var(--text-warning); line-height: 1.6">
        {{ t('earlyStopReason') }}: {{ stageOneEarlyStop.reason || `${t('round')} ${stageOneEarlyStop.after_pass}` }}
      </div>
    </el-card>

    <ScanOverview v-if="stageOneStage" :stats="scanStats" :show-route-source-files="false" />

    <el-card style="margin-bottom: 20px">
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap">
          <span class="card-title">{{ t('roundsDetail') }}</span>
          <el-button
            v-if="stageOnePasses.length > 3"
            size="small"
            text
            type="primary"
            @click="togglePassDetails"
          >
            {{ showAllPasses ? t('hideAllRounds') : t('showAllRounds') }}
          </el-button>
        </div>
      </template>
      <div v-if="stageOnePasses.length" style="margin-bottom: 12px; padding: 12px 14px; border-radius: 8px; background: var(--bg-alt); color: var(--text-secondary); font-size: 13px; line-height: 1.7">
        <div>
          {{ t('executedRounds', { count: stageOnePassSummary.executed_pass_count || stageOnePasses.length }) }}
          <span v-if="hiddenStageOnePassCount > 0 && !showAllPasses" style="margin-left: 8px; color: var(--text-muted)">
            {{ t('latestRoundsOnly', { count: displayedStageOnePasses.length, hidden: hiddenStageOnePassCount }) }}
          </span>
        </div>
        <div style="margin-top: 6px; display: flex; gap: 16px; flex-wrap: wrap">
          <span>{{ t('promptLength') }}: <strong>{{ stageOnePassSummary.total_prompt_length || 0 }}</strong></span>
          <span>{{ t('codeLength') }}: <strong>{{ stageOnePassSummary.total_code_length || 0 }}</strong></span>
          <span>{{ t('signalGain') }}: <strong>{{ stageOnePassSummary.peak_signal_gain || 0 }}</strong></span>
          <span>{{ t('auditScopeCoverage') }}: <strong>{{ formatPercent(stageOnePassSummary.max_coverage_ratio || 0) }}</strong></span>
        </div>
      </div>
      <el-table v-if="stageOnePasses.length" :data="displayedStageOnePasses" size="small" stripe max-height="420">
        <el-table-column type="expand">
          <template #default="{ row }">
            <div style="padding: 8px 12px">
              <div style="margin-bottom: 8px; color: var(--text-secondary); line-height: 1.7">
                <strong>{{ t('scannedFiles') }}</strong>
                <span v-if="!previewList(row.chunk_files).length" class="text-muted">: {{ t('noData') }}</span>
              </div>
              <div v-if="previewList(row.chunk_files).length" style="display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 14px">
                <el-tag v-for="path in previewList(row.chunk_files, 16)" :key="`chunk-${row.pass_index}-${path}`" size="small" effect="plain">{{ path }}</el-tag>
              </div>
              <div style="margin-bottom: 8px; color: var(--text-secondary); line-height: 1.7"><strong>{{ t('summaryDelta') }}</strong></div>
              <div style="display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px 12px; margin-bottom: 12px; color: var(--text-secondary); font-size: 12px">
                <div>{{ t('hasSummary') }}: {{ boolLabel(row.summary_delta?.stage_summary) }}</div>
                <div>{{ t('vulnerabilityHints') }}={{ row.summary_delta?.vulnerability_hints?.length || 0 }}</div>
                <div>{{ t('routeSignals') }}={{ row.progress?.route_signal_count || 0 }}</div>
                <div>{{ t('routeFiles') }}={{ row.progress?.covered_route_file_count || 0 }}/{{ row.progress?.total_route_file_count || 0 }}</div>
                <div>{{ t('moduleSignals') }}={{ row.progress?.module_signal_count || 0 }}</div>
                <div>{{ t('dataFlowSignals') }}={{ row.progress?.data_flow_signal_count || 0 }}</div>
                <div>{{ t('compactedPathCount') }}={{ row.microcompact?.compacted_path_count || 0 }}</div>
              </div>
              <div v-if="row.early_stop_reason" style="padding: 10px 12px; border-radius: 8px; background: var(--bg-warning); color: var(--text-warning)">
                {{ t('currentRoundEarlyStop') }}: {{ row.early_stop_reason }}
              </div>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="pass_index" :label="t('round')" width="70" />
        <el-table-column :label="t('auditScopeCoverage')" width="110"><template #default="{ row }">{{ formatPercent(row.progress?.coverage_ratio) }}</template></el-table-column>
        <el-table-column :label="t('newFiles')" width="90"><template #default="{ row }">{{ row.progress?.new_path_count || 0 }}</template></el-table-column>
        <el-table-column :label="t('signalGain')" width="90"><template #default="{ row }">{{ row.progress?.signal_gain || 0 }}</template></el-table-column>
        <el-table-column :label="t('promptLength')" width="110"><template #default="{ row }">{{ row.user_prompt_length || 0 }}</template></el-table-column>
        <el-table-column :label="t('codeLength')" width="110"><template #default="{ row }">{{ row.code_text_length || 0 }}</template></el-table-column>
        <el-table-column :label="t('compactedChunks')" width="90"><template #default="{ row }">{{ row.microcompact?.compacted_chunk_count || 0 }}</template></el-table-column>
        <el-table-column :label="t('riskWindow')" width="90"><template #default="{ row }">{{ row.microcompact?.signal_window_chunk_count || 0 }}</template></el-table-column>
        <el-table-column :label="t('remarks')" min-width="260" show-overflow-tooltip><template #default="{ row }">{{ row.early_stop_reason || row.progress?.new_paths_preview?.join(', ') || '-' }}</template></el-table-column>
      </el-table>
      <el-empty v-else :description="artifactLoading ? t('loadingStageOneDetails') : t('noStageOneDetails')" :image-size="60" />
    </el-card>

    <el-card style="margin-bottom: 20px">
      <template #header><span class="card-title">{{ t('missingRouteDiff') }} ({{ missingRouteSamples.length }}/{{ routeGapSummary.missing_route_count || 0 }})</span></template>
      <el-table v-if="missingRouteSamples.length" :data="missingRouteSamples" size="small" stripe max-height="360">
        <el-table-column prop="method" :label="t('method')" width="90" />
        <el-table-column prop="path" :label="t('path')" min-width="220" show-overflow-tooltip />
        <el-table-column prop="handler" :label="t('handler')" min-width="180" show-overflow-tooltip />
        <el-table-column prop="file_path" :label="t('file')" min-width="220" show-overflow-tooltip />
        <el-table-column :label="t('auth')" width="120"><template #default="{ row }">{{ authLabel(row.auth) }}</template></el-table-column>
      </el-table>
      <el-empty v-else :description="t('noMissingRouteDiff')" :image-size="60" />
    </el-card>

    <el-card>
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap">
          <span class="card-title">{{ t('stageOneRouteList') }} ({{ filteredStageOneRoutes.length }}/{{ stageOneRoutes.length }})</span>
          <div style="display: flex; gap: 8px; flex-wrap: wrap">
            <el-input v-model="routeFilter.keyword" :placeholder="t('searchRoutes')" clearable size="small" style="width: 240px" />
            <el-select v-model="routeFilter.auth" clearable size="small" style="width: 140px" :placeholder="t('auth')">
              <el-option :label="t('authJwt')" value="JWT" />
              <el-option :label="t('authSession')" value="Session" />
              <el-option :label="t('authOAuth')" value="OAuth" />
              <el-option :label="t('authUnknown')" value="Unknown" />
              <el-option :label="t('authNone')" value="None" />
            </el-select>
          </div>
        </div>
      </template>
      <el-descriptions :column="2" border size="small" style="margin-bottom: 16px">
        <el-descriptions-item :label="t('techStack')">{{ stageOneArchitecture.tech_stack || '-' }}</el-descriptions-item>
        <el-descriptions-item :label="t('framework')">{{ stageOneArchitecture.framework || '-' }}</el-descriptions-item>
        <el-descriptions-item :label="t('database')">{{ stageOneArchitecture.database || '-' }}</el-descriptions-item>
        <el-descriptions-item :label="t('authMechanism')">{{ stageOneArchitecture.auth_mechanism || '-' }}</el-descriptions-item>
      </el-descriptions>
      <el-table v-if="filteredStageOneRoutes.length" :data="filteredStageOneRoutes" size="small" stripe max-height="520">
        <el-table-column prop="method" :label="t('method')" width="90" />
        <el-table-column prop="path" :label="t('path')" min-width="220" show-overflow-tooltip />
        <el-table-column prop="handler" :label="t('handler')" min-width="180" show-overflow-tooltip />
        <el-table-column :label="t('params')" min-width="180" show-overflow-tooltip><template #default="{ row }">{{ Array.isArray(row.params) && row.params.length ? row.params.join(', ') : '-' }}</template></el-table-column>
        <el-table-column prop="file_path" :label="t('file')" min-width="220" show-overflow-tooltip />
        <el-table-column :label="t('auth')" width="120"><template #default="{ row }">{{ authLabel(row.auth) }}</template></el-table-column>
        <el-table-column :label="t('description')" min-width="200" show-overflow-tooltip><template #default="{ row }">{{ row.notes || '-' }}</template></el-table-column>
      </el-table>
      <el-empty v-else :description="t('noRoutesFound')" :image-size="60" />
    </el-card>
  </div>
</template>

<style scoped>
.stage-one-summary {
  margin-bottom: 20px;
  padding: 16px 20px;
  background: var(--bg-info);
  border: 1px solid var(--border-info);
  border-radius: 10px;
  color: var(--text-primary);
  line-height: 1.9;
  font-size: 15px;
}

.stage-one-summary-title {
  margin-bottom: 8px;
  color: var(--text-info);
  font-size: 14px;
  font-weight: bold;
  letter-spacing: 1px;
}

.stage-one-summary.is-empty {
  background: var(--bg-alt);
  border-color: var(--border-default);
  color: var(--text-muted);
  text-align: center;
}

@media (max-width: 760px) {
  .stage-one-summary {
    padding: 14px 16px;
  }
}
</style>

<script setup>
// 分阶段时间线：审计四阶段（架构 → 规划 → 子 Agent 审计 → Supervisor 审核）。
//
// 从 AuditDetail 抽出的最大一块。直接消费 auditDetail store（同 FindingList /
// RuleHitsPreviewCard 的模式：store 持状态，组件自取 storeToRefs），自持阶段派生
// computed 与 helper；与覆盖摘要卡片共用的 stageOneRiskHints 已下沉到 store。
//
// 「查看阶段一详情」按钮不直接跳转——emit view-stage-one，由父页统一路由
// （与 FindingList emit select 同构），保持组件不耦合 router。
import { computed } from 'vue'
import { storeToRefs } from 'pinia'
import { useAuditDetailStore } from '../../stores/auditDetail'
import { useI18n } from '../../i18n'
import { riskHintMeta } from '../../utils/riskHints'
import { routeCountOf } from '../../utils/stageOne'

const emit = defineEmits(['view-stage-one'])

const store = useAuditDetailStore()
const { task, stages, stageMap, archStage, stageOneRiskHints } = storeToRefs(store)
const { t, statusType, statusLabel, formatTimeOnly } = useI18n()

// 各阶段对象：负数 stage_num 是 supervisor（-1 规划 / -2 审核）。
const planStage = computed(() => stageMap.value[-1])
const auditStages = computed(() => stages.value.filter(s => s.stage_num >= 2 && s.stage_num <= 9))
const reviewStage = computed(() => stageMap.value[-2])

// 阶段一架构信息派生（仅时间线第一阶段卡片用）。
const archInfo = computed(() => {
  const ai = archStage.value?.findings?.architecture_info
  return ai && typeof ai === 'object' ? ai : {}
})
const middlewareChain = computed(() => Array.isArray(archInfo.value.middleware_chain) ? archInfo.value.middleware_chain : [])
const databaseModels = computed(() => Array.isArray(archInfo.value.database_models) ? archInfo.value.database_models : [])
const securityBoundaries = computed(() => archInfo.value.security_boundaries && typeof archInfo.value.security_boundaries === 'object' ? archInfo.value.security_boundaries : null)
const externalIntegrations = computed(() => Array.isArray(archInfo.value.external_integrations) ? archInfo.value.external_integrations : [])
const gapAnalysis = computed(() => archInfo.value._gap_analysis && typeof archInfo.value._gap_analysis === 'object' ? archInfo.value._gap_analysis : null)

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
    const routeCount = routeCountOf(stage)
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
const stageRecoveryNote = (stage) => {
  if (!stage?.findings || typeof stage.findings !== 'object' || !stage.findings._salvaged) return ''
  return stage.findings.parse_error || t('stageRecoveryFallback')
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
const stageQualityStats = (stage) => {
  const findings = stage?.findings
  if (!findings || typeof findings !== 'object') return { candidate: 0, formal: 0, filtered: 0 }
  const rawCandidate = Number(findings._candidate_vulnerability_count)
  const fallbackCandidate = Number.isFinite(Number(findings._vulnerability_count))
    ? Number(findings._vulnerability_count)
    : (Array.isArray(findings.vulnerabilities) ? findings.vulnerabilities.length : 0)
  const candidate = Number.isFinite(rawCandidate) ? rawCandidate : fallbackCandidate
  const rawFormal = Number(findings._formal_vulnerability_count)
  const formal = Number.isFinite(rawFormal) ? rawFormal : candidate
  const rawFiltered = Number(findings._filtered_vulnerability_count)
  const filtered = Number.isFinite(rawFiltered) ? rawFiltered : Math.max(candidate - formal, 0)
  return { candidate, formal, filtered }
}
const vulnCountForStage = (stageNum) => {
  const s = stageMap.value[stageNum]
  return stageQualityStats(s).formal
}
const stageQualityNote = (stage) => {
  const stats = stageQualityStats(stage)
  if (!stats.filtered) return ''
  return stage?.findings?._quality_gate_note || t('stageQualityGateNote', stats)
}
const stageCandidateText = (stage) => {
  const stats = stageQualityStats(stage)
  if (!stats.candidate || stats.candidate === stats.formal) return ''
  return t('stageCandidateSummary', stats)
}

const viewStageOneDetail = () => emit('view-stage-one')
</script>

<template>
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
            <el-button size="small" text type="primary" @click="viewStageOneDetail">{{ t('viewStageOneDetail') }}</el-button>
          </div>
        </div>
        <div v-if="archStage && stageSummary(archStage)" style="margin-top: 8px; color: var(--text-secondary); line-height: 1.6; white-space: pre-wrap">{{ stageSummary(archStage) }}</div>
        <el-collapse v-if="archStage?.findings?._debug" style="margin-top: 6px; border: none">
          <el-collapse-item :title="t('debugInfo')" name="debug-arch">
            <div style="color: var(--text-muted); font-size: 12px; white-space: pre-wrap">{{ debugSummary(archStage) }}</div>
          </el-collapse-item>
        </el-collapse>

        <div
          v-if="stageOneRiskHints.length"
          style="margin-top: 10px; padding: 10px 12px; border-radius: 8px; background: var(--bg-warning); border: 1px solid var(--border-warning); color: var(--text-warning); font-size: 12px; line-height: 1.6"
        >
          <div style="font-weight: 600; margin-bottom: 6px">{{ t('stageOneRiskHints') }} ({{ stageOneRiskHints.length }})</div>
          <div style="color: var(--text-muted); margin-bottom: 8px">{{ t('stageOneRiskHintsNotice') }}</div>
          <div v-for="(hint, index) in stageOneRiskHints.slice(0, 4)" :key="`stage1-hint-${index}`" style="margin-top: 6px">
            <strong>{{ hint.title }}</strong>
            <span v-if="hint.vuln_type"> · {{ hint.vuln_type === 'risk_hint' ? t('riskHint') : hint.vuln_type }}</span>
            <div v-if="riskHintMeta(hint)" style="color: var(--text-muted)">{{ riskHintMeta(hint) }}</div>
          </div>
        </div>

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
                <el-tag v-if="stageCandidateText(stage)" size="small" type="info" effect="plain">{{ stageCandidateText(stage) }}</el-tag>
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
            <div v-if="stageQualityNote(stage)" style="margin-top: 4px; color: var(--text-muted); font-size: 12px; line-height: 1.5">
              {{ stageQualityNote(stage) }}
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
</template>

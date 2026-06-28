<script setup>
import { computed } from 'vue'
import { useI18n } from '../../i18n'

const props = defineProps({
  stages: { type: Array, default: () => [] },
  agentRuns: { type: Array, default: () => [] },
  diagnostics: { type: Object, default: null },
  routeCoverage: { type: Object, default: null },
  vulnerabilities: { type: Array, default: () => [] },
})

const { t, statusLabel, statusType, formatTimeOnly } = useI18n()

const stageLabel = (num) => {
  if (Number(num) === -1) return t('phasePlan')
  if (Number(num) === -2) return t('phaseReview')
  if (Number(num) === 1) return t('phaseArch')
  return `Stage ${num}`
}

const guard = computed(() => {
  const value = props.diagnostics?.orchestration_guard
  return value && typeof value === 'object' ? value : {}
})

const plannedSet = computed(() => new Set((guard.value.planned_stage_nums || []).map(Number)))
const completedSet = computed(() => new Set((guard.value.completed_stage_nums || []).map(Number)))
const failedSet = computed(() => new Set((guard.value.failed_stage_nums || []).map(Number)))
const missingSet = computed(() => new Set((guard.value.missing_stage_nums || []).map(Number)))
const unresolvedSet = computed(() => new Set((guard.value.unresolved_stage_nums || []).map(Number)))

const agentRunsByStage = computed(() => {
  const map = new Map()
  for (const run of props.agentRuns || []) {
    if (!run || run.stage_num === null || run.stage_num === undefined) continue
    const key = Number(run.stage_num)
    const rows = map.get(key) || []
    rows.push(run)
    map.set(key, rows)
  }
  for (const rows of map.values()) {
    rows.sort((a, b) => Number(b.id || 0) - Number(a.id || 0))
  }
  return map
})

const vulnCountByStage = computed(() => {
  const map = new Map()
  for (const vuln of props.vulnerabilities || []) {
    if (!vuln || vuln.stage_id === null || vuln.stage_id === undefined) continue
    const stage = (props.stages || []).find(item => Number(item.id) === Number(vuln.stage_id))
    if (!stage) continue
    const key = Number(stage.stage_num)
    map.set(key, (map.get(key) || 0) + 1)
  }
  return map
})

const routeCoverageByStage = computed(() => {
  const map = new Map()
  const rows = props.routeCoverage?.stage_coverage
  if (!Array.isArray(rows)) return map
  for (const row of rows) {
    if (!row || row.stage_num === null || row.stage_num === undefined) continue
    map.set(Number(row.stage_num), row)
  }
  return map
})

const stageNums = computed(() => {
  const nums = new Set([-1, 1, -2])
  for (let num = 2; num <= 9; num += 1) nums.add(num)
  for (const stage of props.stages || []) {
    if (stage?.stage_num !== null && stage?.stage_num !== undefined) nums.add(Number(stage.stage_num))
  }
  for (const num of plannedSet.value) nums.add(num)
  const ordered = [...nums].filter(num => Number.isFinite(num))
  const orderOf = (num) => {
    if (num === 1) return 10
    if (num === -1) return 20
    if (num >= 2 && num <= 9) return 20 + num
    if (num === -2) return 40
    return 100 + num
  }
  return ordered.sort((a, b) => orderOf(a) - orderOf(b))
})

const stageByNum = computed(() => {
  const map = new Map()
  for (const stage of props.stages || []) {
    if (stage?.stage_num === null || stage?.stage_num === undefined) continue
    map.set(Number(stage.stage_num), stage)
  }
  return map
})

const stageError = (stage, runs) => {
  const failedRun = runs.find(run => run.status === 'failed' && run.error_message)
  if (failedRun?.error_message) return failedRun.error_message
  const findings = stage?.findings
  if (findings && typeof findings === 'object') {
    if (findings._debug?.error) return findings._debug.error
    if (findings.parse_error) return findings.parse_error
    if (findings.skip_reason) return findings.skip_reason
  }
  if (stage?.llm_response && stage.status === 'failed') return stage.llm_response
  return ''
}

const planStateFor = (num, stage) => {
  if (num >= 2 && num <= 9) {
    if (plannedSet.value.has(num)) return completedSet.value.has(num) ? 'completed' : failedSet.value.has(num) ? 'failed' : unresolvedSet.value.has(num) ? 'blocked' : 'planned'
    if (stage?.status === 'skipped') return 'skipped'
    return 'not_planned'
  }
  return stage ? 'planned' : 'not_planned'
}

const rowClass = (row) => ({
  'is-unresolved': row.unresolved,
  'is-failed': row.status === 'failed',
  'is-missing': row.missing,
})

const matrixRows = computed(() => stageNums.value.map((num) => {
  const stage = stageByNum.value.get(num) || null
  const runs = agentRunsByStage.value.get(num) || []
  const routeRow = routeCoverageByStage.value.get(num) || null
  const latestRun = runs[0] || null
  const missing = missingSet.value.has(num) || !stage
  const unresolved = unresolvedSet.value.has(num)
  const status = missing ? 'missing' : (stage.status || 'pending')
  const error = stageError(stage, runs)
  return {
    key: num,
    stage_num: num,
    stage_name: stage?.stage_name || stageLabel(num),
    status,
    status_label: missing ? t('missing') : statusLabel(status),
    status_type: missing ? 'danger' : statusType(status),
    plan_state: planStateFor(num, stage),
    planned: plannedSet.value.has(num),
    completed: completedSet.value.has(num),
    failed: failedSet.value.has(num) || status === 'failed',
    missing,
    unresolved,
    attempts: runs.length,
    latest_role: latestRun?.agent_role || stage?.agent_role || '--',
    latest_error: error,
    vuln_count: vulnCountByStage.value.get(num) || Number(stage?.findings?._formal_vulnerability_count || 0) || 0,
    route_attested: Number(routeRow?.attested_route_count || 0),
    route_missing: Number(routeRow?.missing_focus_route_count || 0),
    started_at: stage?.started_at || latestRun?.started_at || null,
    completed_at: stage?.completed_at || latestRun?.completed_at || null,
  }
}))

const summary = computed(() => {
  const auditRows = matrixRows.value.filter(row => row.stage_num >= 2 && row.stage_num <= 9)
  return {
    planned: plannedSet.value.size,
    completed: auditRows.filter(row => row.completed || row.status === 'completed').length,
    failed: auditRows.filter(row => row.failed).length,
    unresolved: auditRows.filter(row => row.unresolved).length,
  }
})

const planStateLabel = (state) => {
  const map = {
    planned: 'planned',
    completed: 'completed',
    failed: 'failed',
    blocked: 'diagnosticBlocked',
    skipped: 'skipped',
    not_planned: 'notPlanned',
  }
  return t(map[state] || state)
}

const planStateType = (state) => {
  if (state === 'completed') return 'success'
  if (state === 'failed' || state === 'blocked') return 'danger'
  if (state === 'planned') return 'warning'
  return 'info'
}
</script>

<template>
  <div class="stage-matrix">
    <div class="stage-matrix__head">
      <div>
        <div class="stage-matrix__title">{{ t('stageMatrixWorkbench') }}</div>
        <div class="stage-matrix__subtitle">{{ guard?.message || t('stageMatrixSubtitle') }}</div>
      </div>
      <div class="stage-matrix__summary">
        <div><span>{{ t('plannedStages') }}</span><strong>{{ summary.planned }}</strong></div>
        <div><span>{{ t('completedStages') }}</span><strong>{{ summary.completed }}</strong></div>
        <div><span>{{ t('failedStages') }}</span><strong>{{ summary.failed }}</strong></div>
        <div><span>{{ t('unresolvedStages') }}</span><strong>{{ summary.unresolved }}</strong></div>
      </div>
    </div>

    <el-table :data="matrixRows" size="small" :row-class-name="({ row }) => rowClass(row)" class="stage-matrix__table">
      <el-table-column :label="t('stage')" min-width="160">
        <template #default="{ row }">
          <div class="stage-matrix__stage">
            <strong>{{ stageLabel(row.stage_num) }}</strong>
            <small>{{ row.stage_name }}</small>
          </div>
        </template>
      </el-table-column>
      <el-table-column :label="t('status')" width="100">
        <template #default="{ row }">
          <el-tag size="small" :type="row.status_type" effect="plain">{{ row.status_label }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="t('planState')" width="110">
        <template #default="{ row }">
          <el-tag size="small" :type="planStateType(row.plan_state)" effect="plain">{{ planStateLabel(row.plan_state) }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="t('agentAttempts')" width="105">
        <template #default="{ row }">
          <span>{{ row.attempts || '--' }}</span>
        </template>
      </el-table-column>
      <el-table-column :label="t('agentRole')" min-width="120">
        <template #default="{ row }">
          <span class="stage-matrix__truncate">{{ row.latest_role }}</span>
        </template>
      </el-table-column>
      <el-table-column :label="t('vulnerabilityCount')" width="100">
        <template #default="{ row }">
          <strong :class="{ 'is-danger': row.vuln_count > 0 }">{{ row.vuln_count || 0 }}</strong>
        </template>
      </el-table-column>
      <el-table-column :label="t('routeCoverage')" width="130">
        <template #default="{ row }">
          <span>{{ row.route_attested || 0 }}/{{ row.route_missing || 0 }}</span>
        </template>
      </el-table-column>
      <el-table-column :label="t('time')" width="130">
        <template #default="{ row }">
          <span>{{ formatTimeOnly(row.completed_at || row.started_at) }}</span>
        </template>
      </el-table-column>
      <el-table-column :label="t('blockedReason')" min-width="190">
        <template #default="{ row }">
          <span class="stage-matrix__truncate" :title="row.latest_error">{{ row.latest_error || '--' }}</span>
        </template>
      </el-table-column>
    </el-table>

    <div class="stage-matrix__cards">
      <div v-for="row in matrixRows" :key="`matrix-card-${row.key}`" class="stage-matrix__card" :class="rowClass(row)">
        <div class="stage-matrix__card-main">
          <div>
            <strong>{{ stageLabel(row.stage_num) }}</strong>
            <small>{{ row.stage_name }}</small>
          </div>
          <el-tag size="small" :type="row.status_type" effect="plain">{{ row.status_label }}</el-tag>
        </div>
        <div class="stage-matrix__card-grid">
          <span>{{ t('planState') }}: {{ planStateLabel(row.plan_state) }}</span>
          <span>{{ t('agentAttempts') }}: {{ row.attempts || 0 }}</span>
          <span>{{ t('vulnerabilityCount') }}: {{ row.vuln_count || 0 }}</span>
          <span>{{ t('routeCoverage') }}: {{ row.route_attested || 0 }}/{{ row.route_missing || 0 }}</span>
        </div>
        <div v-if="row.latest_error" class="stage-matrix__card-error">{{ row.latest_error }}</div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.stage-matrix {
  display: grid;
  gap: 12px;
  margin-bottom: 14px;
}

.stage-matrix__head {
  display: grid;
  grid-template-columns: minmax(240px, 1fr) minmax(360px, 1.2fr);
  gap: 12px;
  align-items: stretch;
}

.stage-matrix__title {
  color: var(--text-primary);
  font-size: 14px;
  font-weight: 700;
}

.stage-matrix__subtitle {
  margin-top: 4px;
  color: var(--text-muted);
  font-size: 12px;
  line-height: 1.45;
  overflow-wrap: anywhere;
}

.stage-matrix__summary {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 8px;
}

.stage-matrix__summary div {
  min-width: 0;
  padding: 8px 10px;
  border: 1px solid var(--border-default);
  border-radius: 8px;
  background: var(--bg-page);
}

.stage-matrix__summary span {
  display: block;
  margin-bottom: 3px;
  color: var(--text-muted);
  font-size: 11px;
}

.stage-matrix__summary strong {
  display: block;
  color: var(--text-primary);
  font-size: 16px;
  line-height: 1.2;
}

.stage-matrix__stage {
  min-width: 0;
  display: grid;
  gap: 2px;
}

.stage-matrix__stage strong,
.stage-matrix__card-main strong {
  color: var(--text-primary);
  font-size: 13px;
}

.stage-matrix__stage small,
.stage-matrix__card-main small {
  min-width: 0;
  color: var(--text-muted);
  font-size: 11px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.stage-matrix__truncate {
  display: block;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.stage-matrix__cards {
  display: none;
}

.stage-matrix__card {
  min-width: 0;
  padding: 10px;
  border: 1px solid var(--border-default);
  border-radius: 8px;
  background: var(--bg-page);
}

.stage-matrix__card.is-unresolved,
:deep(.stage-matrix__table .is-unresolved) {
  --el-table-tr-bg-color: var(--bg-danger);
}

.stage-matrix__card.is-failed,
.stage-matrix__card.is-missing {
  border-color: var(--border-danger);
}

.stage-matrix__card-main {
  display: flex;
  justify-content: space-between;
  gap: 10px;
  align-items: flex-start;
}

.stage-matrix__card-main > div {
  min-width: 0;
  display: grid;
  gap: 2px;
}

.stage-matrix__card-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 5px 10px;
  margin-top: 8px;
  color: var(--text-muted);
  font-size: 12px;
}

.stage-matrix__card-error {
  margin-top: 8px;
  color: var(--text-danger);
  font-size: 12px;
  line-height: 1.45;
  overflow-wrap: anywhere;
}

.is-danger {
  color: var(--text-danger);
}

@media (max-width: 1100px) {
  .stage-matrix__head {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 760px) {
  .stage-matrix__table {
    display: none;
  }

  .stage-matrix__cards {
    display: grid;
    gap: 8px;
  }

  .stage-matrix__summary {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
</style>

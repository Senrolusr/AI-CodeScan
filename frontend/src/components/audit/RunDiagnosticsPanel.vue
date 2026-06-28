<script setup>
import { computed } from 'vue'
import { useI18n } from '../../i18n'

const props = defineProps({
  diagnostics: { type: Object, default: null },
  agentRuns: { type: Array, default: () => [] },
  currentRun: { type: Object, default: null },
})

const { t, statusLabel, statusType, formatDateTime, formatTimeOnly } = useI18n()

const statusMap = {
  not_started: { labelKey: 'diagnosticNotStarted', type: 'info' },
  starting: { labelKey: 'diagnosticStarting', type: 'warning' },
  running: { labelKey: 'diagnosticRunning', type: 'warning' },
  waiting: { labelKey: 'diagnosticWaiting', type: 'info' },
  stalled: { labelKey: 'diagnosticStalled', type: 'danger' },
  blocked: { labelKey: 'diagnosticBlocked', type: 'danger' },
  failed: { labelKey: 'failed', type: 'danger' },
  paused: { labelKey: 'paused', type: 'warning' },
  completed: { labelKey: 'completed', type: 'success' },
  cancelled: { labelKey: 'cancelled', type: 'info' },
}

const statusInfo = computed(() => {
  const key = props.diagnostics?.focus_status || props.currentRun?.status || 'not_started'
  const entry = statusMap[key] || { labelKey: key, type: statusType(key) }
  return {
    key,
    label: t(entry.labelKey),
    type: entry.type,
  }
})

const sortedAgentRuns = computed(() => {
  return [...(props.agentRuns || [])]
    .filter(item => item && typeof item === 'object')
    .sort((a, b) => Number(b.id || 0) - Number(a.id || 0))
})

const recentAgentRuns = computed(() => sortedAgentRuns.value.slice(0, 6))
const activeAgent = computed(() => {
  const activeId = props.diagnostics?.active_agent_run_id
  if (activeId != null) return sortedAgentRuns.value.find(item => Number(item.id) === Number(activeId)) || null
  return sortedAgentRuns.value.find(item => item.status === 'running') || null
})

const stageText = computed(() => {
  const value = props.diagnostics?.current_stage_num
  if (value === null || value === undefined || value === '') return '--'
  if (Number(value) === -1) return t('phasePlan')
  if (Number(value) === -2) return t('phaseReview')
  return `Stage ${value}`
})

const focusRole = computed(() => props.diagnostics?.current_role || activeAgent.value?.agent_role || '--')
const silenceText = computed(() => {
  const seconds = Number(props.diagnostics?.silence_seconds)
  if (!Number.isFinite(seconds)) return '--'
  if (seconds < 60) return t('secondsShort', { count: seconds })
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return t('minutesShort', { count: minutes })
  return t('hoursShort', { count: Math.floor(minutes / 60) })
})

const mainReason = computed(() => {
  const diag = props.diagnostics || {}
  return diag.error_message || diag.blocked_reason || diag.focus_reason || diag.latest_event_message || ''
})

const orchestrationGuard = computed(() => {
  const guard = props.diagnostics?.orchestration_guard
  return guard && typeof guard === 'object' ? guard : null
})

const hasOrchestrationGuard = computed(() => Boolean(orchestrationGuard.value?.status))
const orchestrationGuardType = computed(() => orchestrationGuard.value?.status === 'blocked' ? 'danger' : 'success')
const orchestrationGuardStatus = computed(() => {
  if (!orchestrationGuard.value) return '--'
  return orchestrationGuard.value.status === 'blocked' ? t('diagnosticBlocked') : t('completed')
})

const formatStageNums = (items) => {
  const nums = Array.isArray(items) ? items.filter(item => item !== null && item !== undefined && item !== '') : []
  if (!nums.length) return '--'
  return nums.map(item => `S${item}`).join(', ')
}

const hasAgentRows = computed(() => recentAgentRuns.value.length > 0)
</script>

<template>
  <div class="run-diagnostics">
    <div class="run-diagnostics__summary">
      <div class="run-diagnostics__status">
        <el-tag :type="statusInfo.type" effect="dark">{{ statusInfo.label }}</el-tag>
        <span class="run-diagnostics__reason">{{ mainReason || t('notAvailable') }}</span>
      </div>
      <div class="run-diagnostics__metrics">
        <div class="run-diagnostics__metric">
          <span>{{ t('currentStage') }}</span>
          <strong>{{ stageText }}</strong>
        </div>
        <div class="run-diagnostics__metric">
          <span>{{ t('agentRole') }}</span>
          <strong>{{ focusRole }}</strong>
        </div>
        <div class="run-diagnostics__metric">
          <span>{{ t('lastProgress') }}</span>
          <strong>{{ diagnostics?.last_progress_at ? formatTimeOnly(diagnostics.last_progress_at) : '--' }}</strong>
        </div>
        <div class="run-diagnostics__metric">
          <span>{{ t('silenceTime') }}</span>
          <strong :class="{ 'is-danger': diagnostics?.stalled }">{{ silenceText }}</strong>
        </div>
      </div>
    </div>

    <div v-if="hasOrchestrationGuard" class="run-diagnostics__guard" :class="{ 'is-blocked': orchestrationGuard?.status === 'blocked' }">
      <div class="run-diagnostics__guard-head">
        <span>{{ t('orchestrationGuard') }}</span>
        <el-tag size="small" :type="orchestrationGuardType" effect="plain">{{ orchestrationGuardStatus }}</el-tag>
      </div>
      <div class="run-diagnostics__guard-message">{{ orchestrationGuard?.message || '--' }}</div>
      <div class="run-diagnostics__guard-metrics">
        <div>
          <span>{{ t('plannedStages') }}</span>
          <strong>{{ formatStageNums(orchestrationGuard?.planned_stage_nums) }}</strong>
        </div>
        <div>
          <span>{{ t('completedStages') }}</span>
          <strong>{{ formatStageNums(orchestrationGuard?.completed_stage_nums) }}</strong>
        </div>
        <div>
          <span>{{ t('missingStages') }}</span>
          <strong>{{ formatStageNums(orchestrationGuard?.missing_stage_nums) }}</strong>
        </div>
        <div>
          <span>{{ t('unresolvedStages') }}</span>
          <strong>{{ formatStageNums(orchestrationGuard?.unresolved_stage_nums) }}</strong>
        </div>
      </div>
    </div>

    <div class="run-diagnostics__details">
      <div class="run-diagnostics__detail">
        <span>{{ t('latestEvent') }}</span>
        <strong>{{ diagnostics?.latest_event_type || '--' }}</strong>
        <small>{{ diagnostics?.latest_event_at ? formatDateTime(diagnostics.latest_event_at) : '--' }}</small>
      </div>
      <div class="run-diagnostics__detail">
        <span>{{ t('activeAgent') }}</span>
        <strong>{{ activeAgent?.agent_role || '--' }}</strong>
        <small>{{ activeAgent?.started_at ? formatDateTime(activeAgent.started_at) : '--' }}</small>
      </div>
      <div class="run-diagnostics__detail">
        <span>{{ t('runId') }}</span>
        <strong>{{ diagnostics?.run_id || currentRun?.id || '--' }}</strong>
        <small>{{ currentRun?.mode && currentRun.mode !== 'full' ? currentRun.mode : t('fullAudit') }}</small>
      </div>
    </div>

    <div v-if="hasAgentRows" class="run-diagnostics__agents">
      <div class="run-diagnostics__agents-title">{{ t('agentAttempts') }}</div>
      <el-table :data="recentAgentRuns" size="small" max-height="220" style="width: 100%">
        <el-table-column prop="agent_role" :label="t('agentRole')" min-width="130" />
        <el-table-column :label="t('stage')" width="110">
          <template #default="{ row }">
            <span>{{ row.stage_num === -1 ? t('phasePlan') : row.stage_num === -2 ? t('phaseReview') : `Stage ${row.stage_num ?? '--'}` }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="t('status')" width="100">
          <template #default="{ row }">
            <el-tag size="small" :type="statusType(row.status)" effect="plain">{{ statusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="t('tokenUsage')" width="130">
          <template #default="{ row }">
            <span>{{ Number(row.prompt_tokens || 0) + Number(row.completion_tokens || 0) || '--' }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="t('latency')" width="110">
          <template #default="{ row }">
            <span>{{ row.latency_ms ? `${row.latency_ms} ms` : '--' }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="t('time')" width="110">
          <template #default="{ row }">
            <span>{{ formatTimeOnly(row.completed_at || row.started_at) }}</span>
          </template>
        </el-table-column>
      </el-table>
    </div>
  </div>
</template>

<style scoped>
.run-diagnostics {
  display: grid;
  gap: 12px;
}

.run-diagnostics__summary {
  display: grid;
  grid-template-columns: minmax(240px, 1.2fr) minmax(320px, 2fr);
  gap: 12px;
  align-items: stretch;
}

.run-diagnostics__status {
  min-width: 0;
  padding: 10px 12px;
  border: 1px solid var(--border-default);
  border-radius: 8px;
  background: var(--bg-page);
  display: flex;
  align-items: flex-start;
  gap: 10px;
}

.run-diagnostics__reason {
  min-width: 0;
  color: var(--text-primary);
  font-size: 13px;
  line-height: 1.55;
  overflow-wrap: anywhere;
}

.run-diagnostics__metrics,
.run-diagnostics__details {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 8px;
}

.run-diagnostics__detail,
.run-diagnostics__metric {
  min-width: 0;
  padding: 9px 10px;
  border: 1px solid var(--border-default);
  border-radius: 8px;
  background: var(--bg-page);
}

.run-diagnostics__detail span,
.run-diagnostics__metric span {
  display: block;
  margin-bottom: 4px;
  color: var(--text-muted);
  font-size: 12px;
}

.run-diagnostics__detail strong,
.run-diagnostics__metric strong {
  display: block;
  color: var(--text-primary);
  font-size: 13px;
  line-height: 1.35;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.run-diagnostics__detail small {
  display: block;
  margin-top: 3px;
  color: var(--text-muted);
  font-size: 11px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.run-diagnostics__guard {
  min-width: 0;
  padding: 10px 12px;
  border: 1px solid var(--border-default);
  border-radius: 8px;
  background: var(--bg-page);
  display: grid;
  grid-template-columns: minmax(150px, 0.8fr) minmax(220px, 1.2fr) minmax(340px, 2fr);
  gap: 10px;
  align-items: center;
}

.run-diagnostics__guard.is-blocked {
  border-color: color-mix(in srgb, var(--text-danger) 34%, var(--border-default));
}

.run-diagnostics__guard-head {
  min-width: 0;
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--text-primary);
  font-size: 13px;
  font-weight: 600;
}

.run-diagnostics__guard-message {
  min-width: 0;
  color: var(--text-primary);
  font-size: 13px;
  line-height: 1.45;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.run-diagnostics__guard-metrics {
  min-width: 0;
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 8px;
}

.run-diagnostics__guard-metrics div {
  min-width: 0;
}

.run-diagnostics__guard-metrics span {
  display: block;
  margin-bottom: 3px;
  color: var(--text-muted);
  font-size: 11px;
}

.run-diagnostics__guard-metrics strong {
  display: block;
  color: var(--text-primary);
  font-size: 12px;
  line-height: 1.3;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.run-diagnostics__agents {
  min-width: 0;
}

.run-diagnostics__agents-title {
  margin-bottom: 8px;
  color: var(--text-primary);
  font-size: 13px;
  font-weight: 600;
}

.is-danger {
  color: var(--text-danger) !important;
}

@media (max-width: 1100px) {
  .run-diagnostics__summary {
    grid-template-columns: 1fr;
  }

  .run-diagnostics__guard {
    grid-template-columns: 1fr;
    align-items: stretch;
  }
}

@media (max-width: 760px) {
  .run-diagnostics__metrics,
  .run-diagnostics__details {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .run-diagnostics__status {
    flex-direction: column;
  }

  .run-diagnostics__guard-metrics {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 480px) {
  .run-diagnostics__metrics,
  .run-diagnostics__details,
  .run-diagnostics__guard-metrics {
    grid-template-columns: 1fr;
  }
}
</style>

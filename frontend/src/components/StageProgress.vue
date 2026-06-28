<script setup>
import { computed } from 'vue'
import { useI18n } from '../i18n'

const props = defineProps({
  stages: Array,
})
const { t, statusLabel } = useI18n()

const stageColor = (stage) => {
  if (stage.status === 'completed') return '#67C23A'
  if (stage.status === 'running') return '#409EFF'
  if (stage.status === 'failed') return '#F56C6C'
  if (stage.status === 'skipped') return '#C0C4CC'
  return '#DCDFE6'
}

const phases = computed(() => {
  const map = {}
  for (const s of props.stages) {
    map[s.stage_num] = s
  }

  const archStage = map[1]
  const planStage = map[-1]
  const auditStages = []
  for (let i = 2; i <= 9; i++) {
    if (map[i]) auditStages.push(map[i])
  }
  const reviewStage = map[-2]

  const result = []

  result.push({
    key: 'arch',
    label: t('phaseArch'),
    icon: '1',
    stage: archStage,
    color: stageColor(archStage || { status: 'pending' }),
  })

  result.push({
    key: 'plan',
    label: t('phasePlan'),
    icon: 'S',
    stage: planStage,
    color: stageColor(planStage || { status: 'pending' }),
  })

  const plannedAudits = auditStages.length
  const completedAudits = auditStages.filter(s => s.status === 'completed').length
  const runningAudits = auditStages.some(s => s.status === 'running')
  const failedAudits = auditStages.some(s => s.status === 'failed')
  const skippedAudits = auditStages.filter(s => s.status === 'skipped').length
  const executableAudits = Math.max(0, plannedAudits - skippedAudits)
  const auditColor = runningAudits ? '#409EFF' : failedAudits ? '#F56C6C' : completedAudits > 0 ? '#67C23A' : '#DCDFE6'

  result.push({
    key: 'audit',
    label: t('phaseAudit'),
    subLabel: `${completedAudits}/${executableAudits} · ${plannedAudits} ${t('planned') || 'planned'}${skippedAudits ? ` (${skippedAudits} ${t('skipped')})` : ''}`,
    icon: 'A',
    color: auditColor,
    stages: auditStages,
    running: runningAudits,
  })

  result.push({
    key: 'review',
    label: t('phaseReview'),
    icon: 'S',
    stage: reviewStage,
    color: stageColor(reviewStage || { status: 'pending' }),
  })

  return result
})

const phaseTooltip = (phase) => {
  if (phase.stage) {
    return `${phase.label} (${statusLabel(phase.stage.status)})`
  }
  if (phase.stages) {
    const completed = phase.stages.filter(s => s.status === 'completed').length
    return `${phase.label}: ${completed}/${phase.stages.length}`
  }
  return phase.label
}
</script>

<template>
  <div style="display: flex; align-items: center; gap: 0; padding: 4px 0">
    <template v-for="(phase, idx) in phases" :key="phase.key">
      <el-tooltip :content="phaseTooltip(phase)" placement="top">
        <div
          class="phase-node"
          :style="{
            background: phase.color,
            borderColor: phase.color,
            animation: phase.running ? 'pulse 1.5s infinite' : 'none',
          }"
        >
          <span style="color: #fff; font-size: 13px; font-weight: bold">{{ phase.icon }}</span>
        </div>
      </el-tooltip>
      <div
        v-if="idx < phases.length - 1"
        class="stage-line"
        :style="{ background: phase.color }"
      />
    </template>
  </div>
  <div style="display: flex; justify-content: space-between; margin-top: 8px">
    <div v-for="phase in phases" :key="'l' + phase.key" style="text-align: center; flex: 1; min-width: 0">
      <div style="font-size: 12px; color: var(--text-primary); font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis">
        {{ phase.label }}
      </div>
      <div v-if="phase.subLabel" style="font-size: 11px; color: var(--text-muted); margin-top: 2px">
        {{ phase.subLabel }}
      </div>
    </div>
  </div>
</template>

<style scoped>
.phase-node {
  width: 36px;
  height: 36px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  border: 2px solid;
}
.stage-line {
  height: 3px;
  flex: 1;
  min-width: 12px;
}
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}
</style>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { getAudit, getAuditEvents, getAuditStages } from '../api'
import { useI18n } from '../i18n'
import { usePolling } from '../composables/usePolling'

const props = defineProps({ id: [String, Number] })
const router = useRouter()
const { t, statusLabel, statusType, formatDateTime, formatTimeOnly } = useI18n()

const loading = ref(true)
const task = ref(null)
const stages = ref([])
const events = ref([])
const lastSequence = ref(0)
const filter = ref({ stage_num: '', event_type: '', phase_group: '' })
const autoScroll = ref(true)
const expandedRows = ref([])

const taskStatus = computed(() => task.value?.status || '')
const running = computed(() => ['running', 'pending'].includes(taskStatus.value))
const stageOptions = computed(() => [
  { value: 1, label: `Stage 1 · ${t('phaseArch')}` },
  ...stages.value
    .filter(stage => stage.stage_num >= 2 && stage.stage_num <= 9)
    .map(stage => ({ value: stage.stage_num, label: `Stage ${stage.stage_num} · ${stage.stage_name}` })),
])

const visibleEvents = computed(() => {
  const group = filter.value.phase_group
  return events.value.filter((event) => {
    if (filter.value.stage_num && Number(event.stage_num || 0) !== Number(filter.value.stage_num)) return false
    if (filter.value.event_type && event.event_type !== filter.value.event_type) return false
    if (group === 'stage1' && !(event.stage_num === 1 || String(event.phase || '').startsWith('stage1'))) return false
    if (group === 'stage3' && !(Number(event.stage_num) >= 2 || String(event.phase || '').startsWith('stage3'))) return false
    if (group === 'errors' && event.level !== 'error' && event.status !== 'failed') return false
    return true
  })
})

const eventStats = computed(() => {
  const stats = { total: events.value.length, llm: 0, errors: 0, running: 0, tokens: 0 }
  for (const event of events.value) {
    if (String(event.event_type || '').startsWith('llm_')) stats.llm += 1
    if (event.level === 'error' || event.status === 'failed') stats.errors += 1
    if (event.status === 'running') stats.running += 1
    stats.tokens += Number(event.token_usage?.total_tokens || 0)
  }
  return stats
})

const latestEvents = computed(() => visibleEvents.value.slice(-80).reverse())

const loadBase = async () => {
  const [taskRes, stagesRes] = await Promise.all([getAudit(props.id), getAuditStages(props.id)])
  task.value = taskRes.data
  stages.value = stagesRes.data || []
}

const loadEvents = async ({ incremental = true } = {}) => {
  const afterId = incremental ? lastSequence.value : 0
  const res = await getAuditEvents(props.id, afterId, 500)
  const payload = res.data || { events: [], after_id: 0 }
  const incoming = payload.events || []
  if (incremental && events.value.length) {
    const seen = new Set(events.value.map(event => event.id || event.sequence))
    events.value = [
      ...events.value,
      ...incoming.filter(event => !seen.has(event.id || event.sequence)),
    ].slice(-2000)
  } else {
    events.value = incoming
  }
  lastSequence.value = Number(payload.after_id || lastSequence.value || 0)
}

const loadData = async () => {
  try {
    await loadBase()
    await loadEvents({ incremental: false })
  } catch (e) {
    ElMessage.error(e.friendlyMessage || t('executionEventsLoadFailed'))
  } finally {
    loading.value = false
  }
}

const polling = usePolling({
  statusRef: taskStatus,
  intervals: { running: 1800, pending: 2500 },
  fetchFn: async () => {
    await loadBase()
    await loadEvents({ incremental: true })
    if (autoScroll.value) {
      requestAnimationFrame(() => {
        const node = document.querySelector('.execution-console')
        if (node) node.scrollTop = node.scrollHeight
      })
    }
  },
})

onMounted(async () => {
  await loadData()
  polling.start()
})

const refreshAll = async () => {
  loading.value = true
  lastSequence.value = 0
  await loadData()
}

const eventTypeLabel = (event) => {
  const key = `executionEvent_${event.event_type}`
  const label = t(key)
  return label === key ? event.event_type : label
}

const levelTagType = (event) => {
  if (event.level === 'error' || event.status === 'failed') return 'danger'
  if (event.level === 'success' || event.status === 'completed') return 'success'
  if (event.status === 'running') return 'warning'
  return 'info'
}

const stageLabel = (event) => {
  if (!event.stage_num) return t('allStages')
  const stage = stages.value.find(item => Number(item.stage_num) === Number(event.stage_num))
  return stage ? `Stage ${stage.stage_num} · ${stage.stage_name}` : `Stage ${event.stage_num}`
}

const tokenText = (event) => {
  const usage = event.token_usage || {}
  if (!usage.total_tokens && !usage.prompt_tokens && !usage.completion_tokens) return '-'
  return `${usage.total_tokens || 0} (${usage.prompt_tokens || 0}/${usage.completion_tokens || 0})`
}

const compactJson = (value) => JSON.stringify(value || {}, null, 2)
</script>

<template>
  <div v-loading="loading">
    <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 20px; flex-wrap: wrap">
      <div>
        <h2 style="margin: 0 0 4px">{{ t('executionProcess') }}</h2>
        <div class="text-muted">
          {{ t('audit') }} #{{ task?.id || props.id }} | {{ statusLabel(task?.status || '-') }}
          <el-tag v-if="running" size="small" type="warning" effect="plain" style="margin-left: 8px">{{ t('realtime') }}</el-tag>
        </div>
      </div>
      <div style="display: flex; gap: 8px; flex-wrap: wrap">
        <el-button @click="router.push(`/audits/${props.id}`)">{{ t('backToAudit') }}</el-button>
        <el-button type="primary" plain :loading="loading" @click="refreshAll">{{ t('refresh') }}</el-button>
      </div>
    </div>

    <div class="execution-grid">
      <el-card>
        <template #header><span class="card-title">{{ t('executionOverview') }}</span></template>
        <div class="metric-grid">
          <div class="metric">
            <span>{{ t('executionEvents') }}</span>
            <strong>{{ eventStats.total }}</strong>
          </div>
          <div class="metric">
            <span>{{ t('llmCalls') }}</span>
            <strong>{{ eventStats.llm }}</strong>
          </div>
          <div class="metric">
            <span>{{ t('running') }}</span>
            <strong>{{ eventStats.running }}</strong>
          </div>
          <div class="metric">
            <span>{{ t('failed') }}</span>
            <strong>{{ eventStats.errors }}</strong>
          </div>
          <div class="metric">
            <span>{{ t('tokenUsage') }}</span>
            <strong>{{ eventStats.tokens }}</strong>
          </div>
        </div>
      </el-card>

      <el-card>
        <template #header><span class="card-title">{{ t('executionFilters') }}</span></template>
        <div class="filter-row">
          <el-segmented
            v-model="filter.phase_group"
            :options="[
              { label: t('all'), value: '' },
              { label: t('phaseArch'), value: 'stage1' },
              { label: t('phaseAudit'), value: 'stage3' },
              { label: t('failed'), value: 'errors' },
            ]"
          />
          <el-select v-model="filter.stage_num" :placeholder="t('stage')" clearable size="small" style="width: 220px">
            <el-option v-for="stage in stageOptions" :key="stage.value" :label="stage.label" :value="stage.value" />
          </el-select>
          <el-select v-model="filter.event_type" :placeholder="t('type')" clearable size="small" style="width: 220px">
            <el-option label="llm_start" value="llm_start" />
            <el-option label="llm_success" value="llm_success" />
            <el-option label="llm_error" value="llm_error" />
            <el-option label="pass_start" value="pass_start" />
            <el-option label="pass_complete" value="pass_complete" />
            <el-option label="agent_start" value="agent_start" />
            <el-option label="agent_complete" value="agent_complete" />
            <el-option label="agent_error" value="agent_error" />
          </el-select>
          <el-checkbox v-model="autoScroll">{{ t('autoScroll') }}</el-checkbox>
        </div>
      </el-card>
    </div>

    <el-card style="margin-top: 20px">
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap">
          <span class="card-title">{{ t('executionTimeline') }} ({{ visibleEvents.length }})</span>
          <span class="text-muted">{{ t('latestSequence') }} {{ lastSequence }}</span>
        </div>
      </template>

      <div v-if="latestEvents.length" class="execution-console">
        <div
          v-for="event in latestEvents"
          :key="event.id || event.sequence"
          :class="['console-event', event.level === 'error' || event.status === 'failed' ? 'is-error' : event.status === 'running' ? 'is-running' : '']"
        >
          <div class="event-head">
            <div class="event-title">
              <span class="event-time">{{ formatTimeOnly(event.ts) }}</span>
              <el-tag size="small" :type="levelTagType(event)" effect="plain">{{ eventTypeLabel(event) }}</el-tag>
              <strong>{{ event.title }}</strong>
            </div>
            <div class="event-meta">
              <span>{{ stageLabel(event) }}</span>
              <span v-if="event.model">{{ event.model }}</span>
              <span v-if="event.duration_ms !== undefined">{{ event.duration_ms }}ms</span>
            </div>
          </div>
          <div v-if="event.message || event.error" class="event-message">
            {{ event.error || event.message }}
          </div>
          <div class="event-stats">
            <span>{{ t('promptLength') }} {{ event.prompt_chars || 0 }}</span>
            <span>{{ t('responseChars') }} {{ event.response_chars || 0 }}</span>
            <span>{{ t('tokenUsage') }} {{ tokenText(event) }}</span>
            <span>{{ t('phase') }} {{ event.phase || '-' }}</span>
          </div>
          <el-collapse v-if="event.prompt_preview || event.response_preview || event.meta" v-model="expandedRows">
            <el-collapse-item :title="t('debugInfo')" :name="String(event.id || event.sequence)">
              <div class="preview-grid">
                <div v-if="event.prompt_preview">
                  <div class="preview-title">{{ t('promptPreview') }}</div>
                  <pre>{{ event.prompt_preview }}</pre>
                </div>
                <div v-if="event.response_preview">
                  <div class="preview-title">{{ t('responsePreview') }}</div>
                  <pre>{{ event.response_preview }}</pre>
                </div>
                <div>
                  <div class="preview-title">{{ t('metadata') }}</div>
                  <pre>{{ compactJson(event.meta) }}</pre>
                </div>
              </div>
            </el-collapse-item>
          </el-collapse>
        </div>
      </div>
      <el-empty v-else :description="t('noExecutionEvents')" :image-size="60" />
    </el-card>

    <el-card style="margin-top: 20px">
      <template #header><span class="card-title">{{ t('executionTable') }}</span></template>
      <el-table :data="visibleEvents" size="small" height="520">
        <el-table-column prop="sequence" label="#" width="80" />
        <el-table-column :label="t('time')" width="170">
          <template #default="{ row }">{{ formatDateTime(row.ts) }}</template>
        </el-table-column>
        <el-table-column :label="t('stage')" width="190">
          <template #default="{ row }">{{ stageLabel(row) }}</template>
        </el-table-column>
        <el-table-column :label="t('type')" width="150">
          <template #default="{ row }"><el-tag size="small" :type="levelTagType(row)" effect="plain">{{ row.event_type }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="title" :label="t('title')" min-width="260" show-overflow-tooltip />
        <el-table-column prop="model" :label="t('model')" width="160" show-overflow-tooltip />
        <el-table-column prop="duration_ms" :label="t('latency')" width="100" />
        <el-table-column prop="prompt_chars" :label="t('promptLength')" width="120" />
        <el-table-column prop="response_chars" :label="t('responseChars')" width="120" />
      </el-table>
    </el-card>
  </div>
</template>

<style scoped>
.execution-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1.4fr);
  gap: 20px;
}

.metric-grid {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 10px;
}

.metric {
  padding: 12px;
  border: 1px solid var(--border-default);
  border-radius: 8px;
  background: var(--bg-alt);
}

.metric span {
  display: block;
  color: var(--text-muted);
  font-size: 12px;
}

.metric strong {
  display: block;
  margin-top: 6px;
  font-size: 20px;
}

.filter-row {
  display: flex;
  gap: 10px;
  align-items: center;
  flex-wrap: wrap;
}

.execution-console {
  max-height: 720px;
  overflow: auto;
  display: flex;
  flex-direction: column-reverse;
  gap: 10px;
  padding-right: 4px;
}

.console-event {
  padding: 12px 14px;
  border: 1px solid var(--border-default);
  border-radius: 8px;
  background: var(--bg-card);
}

.console-event.is-running {
  border-color: var(--border-warning);
  background: var(--bg-warning);
}

.console-event.is-error {
  border-color: var(--border-danger);
  background: var(--bg-danger);
}

.event-head {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  align-items: flex-start;
}

.event-title {
  display: flex;
  gap: 8px;
  align-items: center;
  flex-wrap: wrap;
}

.event-time {
  color: var(--text-muted);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
}

.event-meta,
.event-stats {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  color: var(--text-muted);
  font-size: 12px;
}

.event-message {
  margin-top: 8px;
  color: var(--text-danger);
  font-size: 13px;
  line-height: 1.6;
  white-space: pre-wrap;
}

.event-stats {
  margin-top: 8px;
}

.preview-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}

.preview-title {
  margin-bottom: 6px;
  color: var(--text-muted);
  font-size: 12px;
  font-weight: 600;
}

pre {
  max-height: 260px;
  overflow: auto;
  margin: 0;
  padding: 10px;
  border-radius: 8px;
  background: var(--bg-page);
  color: var(--text-secondary);
  font-size: 12px;
  line-height: 1.6;
  white-space: pre-wrap;
  word-break: break-word;
}

@media (max-width: 980px) {
  .execution-grid,
  .preview-grid {
    grid-template-columns: 1fr;
  }

  .metric-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .event-head {
    flex-direction: column;
  }
}
</style>

<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { getAuditEvents } from '../../api'
import { usePolling } from '../../composables/usePolling'
import { useAuditEventStream } from '../../composables/useAuditEventStream'
import { useI18n } from '../../i18n'
import { eventLabel, eventStageText, eventSummary } from '../../utils/auditEvents'

const props = defineProps({
  taskId: { type: [String, Number], required: true },
  // 任务状态字符串：pending/running/completed/failed/cancelled/paused
  status: { type: String, default: '' },
  // snapshot 提供的最近事件（兜底 / 首屏种子）
  initialEvents: { type: Array, default: () => [] },
})

const { t, formatDateTime, formatTimeOnly } = useI18n()

// 累积事件（按 id 升序，最新在底部）。
const events = ref([])
const lastId = ref(0)
const loadingMore = ref(false)
const errorMsg = ref('')

const statusRef = ref(props.status)
const streamDegraded = ref(false) // SSE 致命失败 → 显示轻量提示，轮询接管
watch(() => props.status, (v) => {
  const changed = statusRef.value !== v
  statusRef.value = v
  // 从非活跃切回活跃时重新启动 SSE + 轮询（例如重跑）。
  if (changed && ['pending', 'running'].includes(v)) {
    startAll()
  } else if (changed && ['completed', 'failed', 'cancelled', 'paused'].includes(v)) {
    // 终态 / 暂停后任务不再产生事件 → 关闭 SSE（避免服务端关流或 600s 生命周期内空挂；
    // resume 回到 pending 时代理上面分支重新 startAll，Last-Event-ID 保证不丢帧）。
    stopAll()
  }
})

const _seedFrom = (list) => {
  if (!Array.isArray(list) || !list.length) return
  const seen = new Set(events.value.map(e => e.id))
  let appended = false
  for (const ev of list) {
    if (ev && ev.id != null && !seen.has(ev.id)) {
      events.value.push(ev)
      seen.add(ev.id)
      appended = true
    }
  }
  if (appended) {
    events.value.sort((a, b) => Number(a.id) - Number(b.id))
    lastId.value = Math.max(lastId.value, ...events.value.map(e => Number(e.id)))
  }
}

const fetchEvents = async (afterId) => {
  try {
    const res = await getAuditEvents(props.taskId, afterId)
    errorMsg.value = ''
    _seedFrom(res.data?.events || [])
  } catch (e) {
    errorMsg.value = e?.friendlyMessage || t('loadFailed') || '加载失败'
  }
}

// §11.3：SSE 为实时主通道（~2s），轮询降为 ~20s 快照兜底（SSE 断线时仍可用）。
const polling = usePolling({
  statusRef,
  intervals: { running: 20000, pending: 5000 },
  fetchFn: async () => { await fetchEvents(lastId.value) },
  onComplete: () => {
    // 终态后再拉一次，确保最终事件落盘。
    fetchEvents(lastId.value)
  },
})

// SSE 实时事件流：onEvent 增量喂入既有 _seedFrom（按 id 去重，与轮询双源无重复）；
// onFallback → 标记降级提示（轮询已在跑，无需额外动作）。
const stream = useAuditEventStream(props.taskId, statusRef, {
  onEvent: (e) => { streamDegraded.value = false; _seedFrom([e]) },
  onFallback: () => { streamDegraded.value = true },
})

// 用函数声明（hoisted）以便上面的 watch 在定义前引用。
function startAll() {
  polling.start()
  stream.start()
}

function stopAll() {
  polling.stop()
  stream.stop()
}

const reversedEvents = computed(() => [...events.value].reverse()) // 最新在顶部展示
const isEmpty = computed(() => events.value.length === 0)
const runStatusLabel = computed(() => {
  if (['pending', 'running'].includes(props.status)) return t('running') || '运行中'
  return ''
})

onMounted(async () => {
  // 首屏先用 snapshot 的 recent_events 占位，再尝试增量拉取。
  _seedFrom(props.initialEvents)
  await fetchEvents(lastId.value)
  startAll()
})

// 手动展开更多（一次性拉取最近 200 条）。
const handleLoadMore = async () => {
  loadingMore.value = true
  try {
    const res = await getAuditEvents(props.taskId, 0, 200)
    _seedFrom(res.data?.events || [])
  } catch (e) {
    errorMsg.value = e?.friendlyMessage || '加载失败'
  } finally {
    loadingMore.value = false
  }
}

defineExpose({ refresh: () => fetchEvents(lastId.value) })
</script>

<template>
  <div class="run-activity">
    <div v-if="errorMsg" class="run-activity__error text-muted">{{ errorMsg }}</div>
    <div v-if="streamDegraded" class="run-activity__hint text-muted">
      {{ t('streamDegraded') || '实时连接已断开，改用轮询' }}
    </div>
    <el-table
      v-if="!isEmpty"
      :data="reversedEvents"
      size="small"
      max-height="420"
      style="width: 100%"
    >
      <el-table-column :label="t('time') || '时间'" width="150">
        <template #default="{ row }">
          <span :title="formatDateTime(row.created_at)">{{ formatTimeOnly(row.created_at) }}</span>
        </template>
      </el-table-column>
      <el-table-column :label="t('type') || '类型'" width="150">
        <template #default="{ row }">
          <el-tag size="small" effect="plain">{{ eventLabel(row.event_type) }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="t('stage') || '阶段'" width="160">
        <template #default="{ row }">
          <span class="text-muted">{{ eventStageText(row) }}</span>
        </template>
      </el-table-column>
      <el-table-column :label="t('description') || '摘要'">
        <template #default="{ row }">
          <span>{{ eventSummary(row) }}</span>
        </template>
      </el-table-column>
    </el-table>
    <el-empty v-else :description="runStatusLabel || t('noEvents') || '暂无运行事件'" :image-size="50" />
    <div v-if="!isEmpty" style="margin-top: 8px; text-align: center">
      <el-button size="small" text :loading="loadingMore" @click="handleLoadMore">{{ t('loadMore') || '加载更多' }}</el-button>
    </div>
  </div>
</template>

<style scoped>
.run-activity__error {
  margin-bottom: 8px;
  font-size: 12px;
}

.run-activity__hint {
  margin-bottom: 8px;
  font-size: 12px;
  font-style: italic;
}
</style>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { getAudit, getAuditStageArtifact, getAuditStages } from '../api'
import { useI18n } from '../i18n'

const props = defineProps({ id: [String, Number], stageNum: [String, Number] })
const router = useRouter()
const { t } = useI18n()

const loading = ref(true)
const task = ref(null)
const stages = ref([])
const artifact = ref(null)

const stage = computed(() => stages.value.find(item => String(item.stage_num) === String(props.stageNum)) || null)
const payload = computed(() => artifact.value?.payload || {})
const focusSummary = computed(() => payload.value?.focus_summary || {})
const responsePreview = computed(() => payload.value?.response_preview || {})

const loadData = async () => {
  try {
    const [taskRes, stagesRes, artifactRes] = await Promise.all([
      getAudit(props.id),
      getAuditStages(props.id),
      getAuditStageArtifact(props.id, props.stageNum),
    ])
    task.value = taskRes.data
    stages.value = stagesRes.data
    artifact.value = artifactRes.data
  } catch {
    ElMessage.error(t('stageArtifactLoadFailed'))
  } finally {
    loading.value = false
  }
}

const prettyJson = (value) => JSON.stringify(value || {}, null, 2)

onMounted(loadData)
</script>

<template>
  <div v-loading="loading">
    <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 20px; flex-wrap: wrap">
      <div>
        <h2 style="margin: 0 0 4px">{{ t('stageArtifactTitle') }}</h2>
        <div class="text-muted">
          {{ t('audit') }} #{{ task?.id || props.id }} | {{ t('stage') }} {{ props.stageNum }} | {{ stage?.stage_name || '-' }}
        </div>
      </div>
      <div style="display: flex; gap: 8px; flex-wrap: wrap">
        <el-button @click="router.push(`/audits/${props.id}`)">{{ t('backToAudit') }}</el-button>
        <el-button v-if="String(props.stageNum) === '1'" type="primary" plain @click="router.push(`/audits/${props.id}/stage-one`)">
          {{ t('openStageOneStandalone') }}
        </el-button>
      </div>
    </div>

    <el-card style="margin-bottom: 20px">
      <template #header><span class="card-title">{{ t('basicInfo') }}</span></template>
      <el-descriptions :column="4" border size="small">
        <el-descriptions-item :label="t('stage')">{{ payload.stage_num || props.stageNum }}</el-descriptions-item>
        <el-descriptions-item :label="t('name')">{{ payload.stage_name || stage?.stage_name || '-' }}</el-descriptions-item>
        <el-descriptions-item :label="t('status')">{{ payload.status || stage?.status || '-' }}</el-descriptions-item>
        <el-descriptions-item :label="t('artifactPath')">{{ artifact?.artifact_path || '-' }}</el-descriptions-item>
      </el-descriptions>
    </el-card>

    <el-card style="margin-bottom: 20px">
      <template #header><span class="card-title">{{ t('compactFocus') }}</span></template>
      <el-descriptions :column="4" border size="small" style="margin-bottom: 16px">
        <el-descriptions-item :label="t('compactedChunks')">{{ focusSummary.selected_chunk_count || 0 }}</el-descriptions-item>
        <el-descriptions-item :label="t('focusFiles')">{{ focusSummary.focus_file_count || 0 }}</el-descriptions-item>
        <el-descriptions-item :label="t('routeClues')">{{ focusSummary.route_line_count || 0 }}</el-descriptions-item>
        <el-descriptions-item :label="t('codeLength')">{{ focusSummary.code_text_length || 0 }}</el-descriptions-item>
      </el-descriptions>

      <div style="display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px">
        <div>
          <div style="font-weight: bold; margin-bottom: 8px">{{ t('focusFiles') }}</div>
          <div style="display: flex; gap: 6px; flex-wrap: wrap">
            <el-tag v-for="path in (focusSummary.focus_files || [])" :key="path" size="small" effect="plain">{{ path }}</el-tag>
            <span v-if="!(focusSummary.focus_files || []).length" class="text-muted">{{ t('noData') }}</span>
          </div>
        </div>
        <div>
          <div style="font-weight: bold; margin-bottom: 8px">{{ t('routeClues') }}</div>
          <pre style="margin: 0; white-space: pre-wrap; color: var(--text-secondary); background: var(--bg-alt); padding: 10px; border-radius: 8px; min-height: 120px">{{ (focusSummary.route_lines || []).join('\n') || t('noData') }}</pre>
        </div>
      </div>
    </el-card>

    <el-card style="margin-bottom: 20px">
      <template #header><span class="card-title">{{ t('stageOutputPreview') }}</span></template>
      <pre style="margin: 0; white-space: pre-wrap; color: var(--text-secondary); background: var(--bg-alt); padding: 12px; border-radius: 8px">{{ prettyJson(responsePreview) }}</pre>
    </el-card>
  </div>
</template>

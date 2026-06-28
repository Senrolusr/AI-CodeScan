<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import {
  createAudit,
  getAudits,
  getLlmConfigs,
  getProject,
  getProjectFile,
  getProjectRoutes,
  getProjectRuleHits,
  rebuildProjectCache,
} from '../api'
import FileTree from '../components/FileTree.vue'
import { useI18n } from '../i18n'
import { buildProjectCacheRecommendations } from '../utils/auditRecommendations'
import { useAuditDeletion } from '../composables/useAuditDeletion'
import { isAuditDeleteBlocked } from '../utils/auditTaskState'
import { isPartialScan } from '../utils/scanStats'

const props = defineProps({ id: [String, Number] })
const router = useRouter()
const { locale, t, statusLabel, statusType, formatDate } = useI18n()

const project = ref(null)
const fileContent = ref('')
const currentFile = ref('')
const loading = ref(true)
const fileLoading = ref(false)
const rebuildingCache = ref(false)

const auditDialog = ref(false)
const llmConfigs = ref([])
const selectedLlmConfig = ref(null)
const auditName = ref('')
const creatingAudit = ref(false)
const existingAudits = ref([])

const projectRoutes = ref([])
const projectRuleHits = ref([])

const cacheSummary = computed(() => {
  const value = project.value?.cache_summary
  return value && typeof value === 'object'
    ? value
    : { available: false, scan_stats: {}, rule_hit_count: 0, cache_schema_version: null }
})

const cacheScanStats = computed(() => {
  const value = cacheSummary.value?.scan_stats
  return value && typeof value === 'object'
    ? value
    : {
        source_files_indexed: 0,
        files_selected_for_audit: 0,
        files_skipped_by_audit_file_budget: 0,
        chunk_count: 0,
        route_count: 0,
        rule_hit_count: 0,
        truncated_by_audit_file_count: false,
        truncated_by_code_chunks: false,
        truncated_by_total_chars: false,
        partial_audit: false,
        oversized_files_compacted: 0,
      }
})

const cacheRecommendations = computed(() => {
  return buildProjectCacheRecommendations({
    cacheSummary: cacheSummary.value || {},
    cacheScanStats: cacheScanStats.value || {},
    locale: locale.value,
  })
})

const loadProject = async () => {
  loading.value = true
  try {
    const res = await getProject(props.id)
    project.value = res.data
    const auditsRes = await getAudits(parseInt(props.id, 10))
    existingAudits.value = auditsRes.data || []
  } catch {
    ElMessage.error(t('projectNotFound'))
  } finally {
    loading.value = false
  }
}

const loadProjectIndex = async () => {
  try {
    const [routesRes, hitsRes] = await Promise.all([
      getProjectRoutes(props.id),
      getProjectRuleHits(props.id),
    ])
    projectRoutes.value = routesRes.data || []
    projectRuleHits.value = hitsRes.data || []
  } catch {
    // 索引可能尚未构建（旧项目 / 上传前），静默处理
  }
}

onMounted(async () => {
  await loadProject()
  loadProjectIndex()
})

const { removeAudit } = useAuditDeletion(loadProject)

const auditProgressText = (row) => {
  const total = Number(row.total_stages || 9)
  const rawCurrent = Number(row.current_stage || 0)
  const current = row.status === 'completed' && rawCurrent <= 0 ? total : rawCurrent
  return `${current}/${total} ${t('stages')}`
}

const openFile = async (path) => {
  currentFile.value = path
  fileLoading.value = true
  try {
    const res = await getProjectFile(props.id, path)
    fileContent.value = res.data
  } catch {
    fileContent.value = t('fileViewUnavailable')
  } finally {
    fileLoading.value = false
  }
}

const openAuditDialog = async () => {
  const res = await getLlmConfigs()
  llmConfigs.value = res.data
  if (llmConfigs.value.length === 0) {
    ElMessage.warning(t('addLlmFirst'))
    router.push('/llm-configs')
    return
  }
  selectedLlmConfig.value = llmConfigs.value.find(c => c.is_default)?.id || llmConfigs.value[0]?.id
  auditName.value = ''
  auditDialog.value = true
}

const startAudit = async () => {
  if (!selectedLlmConfig.value) {
    ElMessage.warning(t('selectLlmConfig'))
    return
  }
  creatingAudit.value = true
  try {
    const res = await createAudit({
      name: auditName.value.trim() || undefined,
      project_id: parseInt(props.id, 10),
      llm_config_id: selectedLlmConfig.value,
    })
    ElMessage.success(t('auditStarted'))
    auditDialog.value = false
    router.push(`/audits/${res.data.id}`)
  } catch (e) {
    ElMessage.error(e.friendlyMessage || t('startAuditFailed'))
  } finally {
    creatingAudit.value = false
  }
}

const handleRebuildCache = async () => {
  rebuildingCache.value = true
  try {
    const res = await rebuildProjectCache(props.id)
    ElMessage.success(res.data?.message || t('rebuildCacheSuccess'))
    await loadProject()
    await loadProjectIndex()
  } catch (e) {
    ElMessage.error(e.friendlyMessage || t('rebuildCacheFailed'))
  } finally {
    rebuildingCache.value = false
  }
}
</script>

<template>
  <div v-loading="loading">
    <div v-if="project">
      <div class="page-header">
        <div>
          <h2 style="margin: 0 0 4px">{{ project.name }}</h2>
          <el-tag v-if="project.tech_stack" size="small" type="info">{{ project.tech_stack }}</el-tag>
          <span style="color: #909399; font-size: 13px; margin-left: 12px">{{ formatDate(project.created_at) }}</span>
        </div>
        <div style="display: flex; gap: 8px; flex-wrap: wrap">
          <el-button plain :loading="rebuildingCache" @click="handleRebuildCache">
            {{ t('rebuildCache') }}
          </el-button>
          <el-button type="primary" @click="openAuditDialog">
            <el-icon><VideoPlay /></el-icon> {{ t('startAudit') }}
          </el-button>
        </div>
      </div>

      <el-card style="margin-bottom: 20px">
        <template #header>
          <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap">
            <span class="card-title">{{ t('cacheSummary') }}</span>
            <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap">
              <el-tag :type="cacheSummary.available ? 'success' : 'info'" size="small">
                {{ cacheSummary.available ? t('cacheReady') : t('cacheNotBuilt') }}
              </el-tag>
              <el-tag v-if="cacheSummary.cache_schema_version" size="small" type="info">
                v{{ cacheSummary.cache_schema_version }}
              </el-tag>
            </div>
          </div>
        </template>
        <el-descriptions :column="4" border size="small">
          <el-descriptions-item :label="t('codeChunks')">
            {{ cacheScanStats.chunk_count || 0 }}
          </el-descriptions-item>
          <el-descriptions-item :label="t('sourceFilesIndexed')">
            {{ cacheScanStats.source_files_indexed || cacheScanStats.source_files_detected || 0 }}
          </el-descriptions-item>
          <el-descriptions-item :label="t('auditFilesSelected')">
            {{ cacheScanStats.files_selected_for_audit || cacheScanStats.files_considered_for_chunks || 0 }}
          </el-descriptions-item>
          <el-descriptions-item :label="t('staticRoutes')">
            {{ cacheScanStats.route_count || 0 }}
          </el-descriptions-item>
          <el-descriptions-item :label="t('rulesPreFilter')">
            {{ cacheSummary.rule_hit_count || cacheScanStats.rule_hit_count || 0 }}
          </el-descriptions-item>
          <el-descriptions-item :label="t('largeFileCompensation')">
            {{ cacheScanStats.oversized_files_compacted || 0 }}
          </el-descriptions-item>
        </el-descriptions>
        <div
          v-if="isPartialScan(cacheScanStats)"
          class="warning-notice"
        >
          <div>{{ t('cachePartialNotice') }}</div>
          <div v-if="cacheScanStats.oversized_files_compacted">{{ t('cacheCompactedNotice', { count: cacheScanStats.oversized_files_compacted }) }}</div>
          <div v-if="cacheScanStats.truncated_by_audit_file_count">{{ t('auditFilesTruncatedNotice', { selected: cacheScanStats.files_selected_for_audit || 0, skipped: cacheScanStats.files_skipped_by_audit_file_budget || 0 }) }}</div>
          <div v-if="cacheScanStats.truncated_by_code_chunks">{{ t('codeChunksTruncatedNotice') }}</div>
          <div v-if="cacheScanStats.truncated_by_total_chars">{{ t('cacheTruncatedNotice') }}</div>
        </div>
      </el-card>

      <el-card style="margin-bottom: 20px">
        <template #header>
          <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap">
            <span class="card-title">{{ t('cacheRecommendations') }}</span>
            <el-tag size="small" type="success">{{ t('recommendationCount', { count: cacheRecommendations.length }) }}</el-tag>
          </div>
        </template>
        <div style="display: grid; gap: 10px">
          <div
            v-for="(item, index) in cacheRecommendations"
            :key="`cache-recommendation-${index}`"
            class="recommendation-item"
          >
            <strong style="margin-right: 8px">{{ index + 1 }}.</strong>{{ item }}
          </div>
        </div>
      </el-card>

      <el-card style="margin-bottom: 20px">
        <template #header>
          <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px">
            <span class="card-title">{{ t('projectRoutes') }}</span>
            <el-tag size="small" type="info">{{ projectRoutes.length }}</el-tag>
          </div>
        </template>
        <el-table v-if="projectRoutes.length" :data="projectRoutes" stripe size="small" max-height="420">
          <el-table-column prop="method" :label="t('method')" width="90" />
          <el-table-column prop="path" :label="t('path')" min-width="200" show-overflow-tooltip />
          <el-table-column prop="handler" :label="t('handler')" min-width="140" show-overflow-tooltip />
          <el-table-column prop="file_path" :label="t('file')" min-width="180" show-overflow-tooltip />
        </el-table>
        <el-empty v-else :description="t('noProjectRoutes')" :image-size="60" />
      </el-card>

      <el-card style="margin-bottom: 20px">
        <template #header>
          <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px">
            <span class="card-title">{{ t('projectRuleHits') }}</span>
            <el-tag size="small" type="info">{{ projectRuleHits.length }}</el-tag>
          </div>
        </template>
        <el-table v-if="projectRuleHits.length" :data="projectRuleHits" stripe size="small" max-height="420">
          <el-table-column prop="label" :label="t('ruleLabel')" width="110" show-overflow-tooltip />
          <el-table-column prop="title" :label="t('title')" min-width="160" show-overflow-tooltip />
          <el-table-column prop="file_path" :label="t('file')" min-width="180" show-overflow-tooltip />
          <el-table-column prop="risk_score" :label="t('riskScore')" width="90" />
          <el-table-column prop="weighted_score" :label="t('weightedScore')" width="100" />
        </el-table>
        <el-empty v-else :description="t('noProjectRuleHits')" :image-size="60" />
      </el-card>

      <el-card v-if="existingAudits.length" style="margin-bottom: 20px">
        <template #header>
          <span class="card-title">{{ t('auditHistory') }}</span>
        </template>
        <el-table :data="existingAudits" stripe size="small">
          <el-table-column prop="id" label="ID" width="60" />
          <el-table-column prop="name" :label="t('auditName')" min-width="160" show-overflow-tooltip />
          <el-table-column prop="status" :label="t('status')" width="120">
            <template #default="{ row }">
              <el-tag :type="statusType(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column :label="t('progress')" width="140">
            <template #default="{ row }">{{ auditProgressText(row) }}</template>
          </el-table-column>
          <el-table-column prop="created_at" :label="t('createdAt')" width="180">
            <template #default="{ row }">{{ formatDate(row.created_at) }}</template>
          </el-table-column>
          <el-table-column :label="t('action')" width="140">
            <template #default="{ row }">
              <el-button size="small" text type="primary" @click="router.push(`/audits/${row.id}`)">{{ t('view') }}</el-button>
              <el-button
                size="small"
                text
                type="danger"
                :disabled="isAuditDeleteBlocked(row)"
                @click="removeAudit(row)"
              >
                {{ t('delete') }}
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-card>

      <el-row :gutter="16">
        <el-col :span="6">
          <el-card shadow="hover" style="max-height: 600px; overflow: auto">
            <template #header><span class="card-title">{{ t('fileTree') }}</span></template>
            <FileTree :tree="project.file_tree || []" @select="openFile" />
          </el-card>
        </el-col>
        <el-col :span="18">
          <el-card shadow="hover">
            <template #header>
              <span class="card-title">{{ currentFile || t('selectFileToView') }}</span>
            </template>
            <div v-loading="fileLoading" style="max-height: 540px; overflow: auto">
              <pre v-if="fileContent" class="code-block">{{ fileContent }}</pre>
              <el-empty v-else :description="t('clickFileToView')" :image-size="60" />
            </div>
          </el-card>
        </el-col>
      </el-row>

      <el-dialog v-model="auditDialog" :title="t('startCodeAudit')" width="560px">
        <el-form label-width="110px">
          <el-form-item :label="t('auditName')">
            <el-input
              v-model="auditName"
              maxlength="255"
              show-word-limit
              :placeholder="t('auditNamePlaceholder')"
            />
          </el-form-item>
          <el-form-item :label="t('llmConfig')">
            <el-select v-model="selectedLlmConfig" style="width: 100%">
              <el-option
                v-for="c in llmConfigs"
                :key="c.id"
                :label="`${c.name} (${c.model_name})`"
                :value="c.id"
              />
            </el-select>
          </el-form-item>
        </el-form>
        <el-alert
          :title="t('auditBackgroundTip')"
          type="info"
          :closable="false"
          show-icon
          style="margin-top: 12px"
        />
        <template #footer>
          <el-button @click="auditDialog = false">{{ t('cancel') }}</el-button>
          <el-button type="primary" :loading="creatingAudit" @click="startAudit">{{ t('startAudit') }}</el-button>
        </template>
      </el-dialog>
    </div>
  </div>
</template>

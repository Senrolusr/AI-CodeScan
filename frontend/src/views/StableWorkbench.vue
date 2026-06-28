<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import {
  getAudit,
  getAuditManifest,
  getAuditStages,
  queryAuditRoutes,
  queryAuditStageOutput,
  submitAuditFindings,
  submitAuditReviews,
  submitAuditRoutes,
} from '../api'
import { useI18n } from '../i18n'

const props = defineProps({ id: [String, Number] })
const router = useRouter()
const { t, statusLabel } = useI18n()

const loading = ref(true)
const task = ref(null)
const stages = ref([])
const activeTab = ref('routes')

const routeLoading = ref(false)
const routeQuery = ref({ method: '', path: '', source: '', page: 1, page_size: 50 })
const routeResult = ref({ items: [], total: 0, page: 1, page_size: 50, has_more: false })

const stageOutputLoading = ref(false)
const stageOutputQuery = ref({ stage_num: 2, verification_status: '', page: 1, page_size: 50 })
const stageOutputResult = ref({ items: [], total: 0, page: 1, page_size: 50, has_more: false })

const manifestLoading = ref(false)
const manifest = ref(null)

const submitLoading = ref(false)
const submitTarget = ref('routes')
const submitStageNum = ref(2)
const submitJson = ref('')

const auditStages = computed(() => stages.value.filter(stage => stage.stage_num >= 2 && stage.stage_num <= 9))

const submitPlaceholder = computed(() => {
  if (submitTarget.value === 'routes') {
    return '[{"method":"GET","path":"/api/users","source":"src/routes.py","handler":"list_users"}]'
  }
  if (submitTarget.value === 'findings') {
    return '[{"title":"SQL injection","vuln_type":"SQL injection","file_path":"app.py","endpoint":"GET /q","description":"input reaches dynamic SQL"}]'
  }
  return '[{"finding_index":0,"finding_id":"finding-id","verification_status":"confirmed","reviewed_severity":"High","verification_reason":"evidence complete"}]'
})

const loadBase = async () => {
  const [taskRes, stagesRes] = await Promise.all([
    getAudit(props.id),
    getAuditStages(props.id),
  ])
  task.value = taskRes.data
  stages.value = stagesRes.data || []
  if (!auditStages.value.some(stage => stage.stage_num === Number(stageOutputQuery.value.stage_num))) {
    stageOutputQuery.value.stage_num = auditStages.value[0]?.stage_num || 2
    submitStageNum.value = auditStages.value[0]?.stage_num || 2
  }
}

const loadRoutes = async () => {
  routeLoading.value = true
  try {
    const params = Object.fromEntries(
      Object.entries(routeQuery.value).filter(([, value]) => value !== '' && value !== null && value !== undefined)
    )
    const res = await queryAuditRoutes(props.id, params)
    routeResult.value = res.data || { items: [], total: 0, page: 1, page_size: 50, has_more: false }
  } catch (e) {
    ElMessage.error(e.friendlyMessage || t('stableQueryFailed'))
  } finally {
    routeLoading.value = false
  }
}

const loadStageOutput = async () => {
  const stageNum = Number(stageOutputQuery.value.stage_num || 2)
  stageOutputLoading.value = true
  try {
    const params = {
      verification_status: stageOutputQuery.value.verification_status || undefined,
      page: stageOutputQuery.value.page,
      page_size: stageOutputQuery.value.page_size,
    }
    const res = await queryAuditStageOutput(props.id, stageNum, params)
    stageOutputResult.value = res.data || { items: [], total: 0, page: 1, page_size: 50, has_more: false }
  } catch (e) {
    ElMessage.error(e.friendlyMessage || t('stableQueryFailed'))
  } finally {
    stageOutputLoading.value = false
  }
}

const loadManifest = async () => {
  manifestLoading.value = true
  try {
    const res = await getAuditManifest(props.id, { page_size: 80 })
    manifest.value = res.data || null
  } catch (e) {
    manifest.value = null
    ElMessage.error(e.friendlyMessage || t('stableQueryFailed'))
  } finally {
    manifestLoading.value = false
  }
}

const loadData = async () => {
  try {
    await loadBase()
    await Promise.all([loadRoutes(), loadStageOutput(), loadManifest()])
  } catch {
    ElMessage.error(t('auditTaskNotFound'))
  } finally {
    loading.value = false
  }
}

const handleRoutePage = (page) => {
  routeQuery.value.page = page
  loadRoutes()
}

const handleOutputPage = (page) => {
  stageOutputQuery.value.page = page
  loadStageOutput()
}

const parseSubmitJson = () => {
  try {
    const value = JSON.parse(submitJson.value || '[]')
    if (!Array.isArray(value)) throw new Error('expected array')
    return value
  } catch {
    ElMessage.error(t('stableSubmitInvalidJson'))
    return null
  }
}

const handleSubmit = async () => {
  const items = parseSubmitJson()
  if (!items || !items.length) {
    ElMessage.error(t('stableSubmitEmpty'))
    return
  }
  submitLoading.value = true
  try {
    if (submitTarget.value === 'routes') {
      await submitAuditRoutes(props.id, items)
      await loadRoutes()
    } else if (submitTarget.value === 'findings') {
      await submitAuditFindings(props.id, Number(submitStageNum.value || 2), items)
      await loadStageOutput()
    } else {
      await submitAuditReviews(props.id, Number(submitStageNum.value || 2), items)
      await loadStageOutput()
    }
    submitJson.value = ''
    ElMessage.success(t('stableSubmitSuccess'))
    await loadBase()
  } catch (e) {
    ElMessage.error(e.friendlyMessage || t('stableSubmitFailed'))
  } finally {
    submitLoading.value = false
  }
}

onMounted(loadData)
</script>

<template>
  <div v-loading="loading">
    <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 20px; flex-wrap: wrap">
      <div>
        <h2 style="margin: 0 0 4px">{{ t('stableWorkbench') }}</h2>
        <div class="text-muted">
          {{ t('audit') }} #{{ task?.id || props.id }} | {{ statusLabel(task?.status || '-') }}
        </div>
      </div>
      <div style="display: flex; gap: 8px; flex-wrap: wrap">
        <el-button @click="router.push(`/audits/${props.id}`)">{{ t('backToAudit') }}</el-button>
        <el-button type="primary" plain :loading="manifestLoading || routeLoading || stageOutputLoading" @click="loadData">{{ t('refresh') }}</el-button>
      </div>
    </div>

    <el-card>
      <el-tabs v-model="activeTab">
        <el-tab-pane :label="t('routeInventory')" name="routes">
          <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 12px">
            <el-select v-model="routeQuery.method" :placeholder="t('method')" clearable size="small" style="width: 120px">
              <el-option label="GET" value="GET" />
              <el-option label="POST" value="POST" />
              <el-option label="PUT" value="PUT" />
              <el-option label="PATCH" value="PATCH" />
              <el-option label="DELETE" value="DELETE" />
            </el-select>
            <el-input v-model="routeQuery.path" :placeholder="t('path')" clearable size="small" style="width: 220px" />
            <el-input v-model="routeQuery.source" :placeholder="t('sourceFile')" clearable size="small" style="width: 220px" />
            <el-button size="small" type="primary" :loading="routeLoading" @click="loadRoutes">{{ t('query') }}</el-button>
          </div>
          <el-table v-loading="routeLoading" :data="routeResult.items || []" size="small" height="560">
            <el-table-column prop="method" :label="t('method')" width="90" />
            <el-table-column prop="path" :label="t('path')" min-width="220" show-overflow-tooltip />
            <el-table-column prop="handler" :label="t('handler')" min-width="160" show-overflow-tooltip />
            <el-table-column :label="t('sourceFile')" min-width="220" show-overflow-tooltip>
              <template #default="{ row }">{{ row.source || row.source_file || row.file_path || '-' }}</template>
            </el-table-column>
            <el-table-column prop="submitted_at" :label="t('submittedAt')" width="180" show-overflow-tooltip />
          </el-table>
          <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-top: 10px">
            <span class="text-muted">{{ t('totalCount', { count: routeResult.total || 0 }) }}</span>
            <el-pagination small layout="prev, pager, next" :page-size="routeResult.page_size || 50" :total="routeResult.total || 0" :current-page="routeResult.page || 1" @current-change="handleRoutePage" />
          </div>
        </el-tab-pane>

        <el-tab-pane :label="t('stageOutput')" name="output">
          <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 12px">
            <el-select v-model="stageOutputQuery.stage_num" :placeholder="t('stage')" size="small" style="width: 200px" @change="loadStageOutput">
              <el-option v-for="stage in auditStages" :key="`output-stage-${stage.stage_num}`" :label="`Stage ${stage.stage_num} · ${stage.stage_name}`" :value="stage.stage_num" />
            </el-select>
            <el-select v-model="stageOutputQuery.verification_status" :placeholder="t('verificationStatus')" clearable size="small" style="width: 180px">
              <el-option :label="t('confirmed')" value="confirmed" />
              <el-option :label="t('uncertain')" value="uncertain" />
              <el-option :label="t('rejected')" value="rejected" />
            </el-select>
            <el-button size="small" type="primary" :loading="stageOutputLoading" @click="loadStageOutput">{{ t('query') }}</el-button>
          </div>
          <el-table v-loading="stageOutputLoading" :data="stageOutputResult.items || []" size="small" height="560">
            <el-table-column prop="finding_index" label="#" width="64" />
            <el-table-column prop="title" :label="t('title')" min-width="220" show-overflow-tooltip />
            <el-table-column prop="vuln_type" :label="t('type')" min-width="160" show-overflow-tooltip />
            <el-table-column prop="severity" :label="t('severity')" width="100" />
            <el-table-column :label="t('endpoint')" min-width="160" show-overflow-tooltip>
              <template #default="{ row }">{{ row.endpoint || row.route || '-' }}</template>
            </el-table-column>
            <el-table-column prop="verification_status" :label="t('verificationStatus')" width="140" />
          </el-table>
          <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-top: 10px">
            <span class="text-muted">{{ t('totalCount', { count: stageOutputResult.total || 0 }) }}</span>
            <el-pagination small layout="prev, pager, next" :page-size="stageOutputResult.page_size || 50" :total="stageOutputResult.total || 0" :current-page="stageOutputResult.page || 1" @current-change="handleOutputPage" />
          </div>
        </el-tab-pane>

        <el-tab-pane :label="t('manifest')" name="manifest">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px">
            <div style="display: flex; gap: 8px; flex-wrap: wrap">
              <el-tag size="small" type="info">{{ t('routeCount') }} {{ manifest?.route_count || 0 }}</el-tag>
              <el-tag size="small" type="warning">{{ t('ruleHitCount') }} {{ manifest?.rule_hit_count || 0 }}</el-tag>
              <el-tag size="small" type="success">{{ t('codeChunkCount') }} {{ manifest?.code_chunk_count || 0 }}</el-tag>
            </div>
            <el-button size="small" text type="primary" :loading="manifestLoading" @click="loadManifest">{{ t('refresh') }}</el-button>
          </div>
          <el-table v-loading="manifestLoading" :data="manifest?.routes || []" size="small" height="300">
            <el-table-column prop="method" :label="t('method')" width="90" />
            <el-table-column prop="path" :label="t('path')" min-width="220" show-overflow-tooltip />
            <el-table-column :label="t('sourceFile')" min-width="220" show-overflow-tooltip>
              <template #default="{ row }">{{ row.source || row.source_file || row.file_path || '-' }}</template>
            </el-table-column>
          </el-table>
          <el-table :data="manifest?.candidate_files || []" size="small" height="260" style="margin-top: 12px">
            <el-table-column :label="t('candidateFiles')">
              <template #default="{ row }">{{ row }}</template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane :label="t('manualSubmit')" name="submit">
          <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 12px">
            <el-select v-model="submitTarget" size="small" style="width: 180px">
              <el-option :label="t('submittedRoutes')" value="routes" />
              <el-option :label="t('submittedFindings')" value="findings" />
              <el-option :label="t('submittedReviews')" value="reviews" />
            </el-select>
            <el-select v-if="submitTarget !== 'routes'" v-model="submitStageNum" size="small" style="width: 200px">
              <el-option v-for="stage in auditStages" :key="`submit-stage-${stage.stage_num}`" :label="`Stage ${stage.stage_num} · ${stage.stage_name}`" :value="stage.stage_num" />
            </el-select>
            <el-button size="small" type="primary" :loading="submitLoading" @click="handleSubmit">{{ t('submit') }}</el-button>
          </div>
          <el-input
            v-model="submitJson"
            type="textarea"
            :rows="18"
            :placeholder="submitPlaceholder"
          />
        </el-tab-pane>
      </el-tabs>
    </el-card>
  </div>
</template>

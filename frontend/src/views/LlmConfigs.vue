<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { createLlmConfig, deleteLlmConfig, getLlmConfigs, testLlmConfig, updateLlmConfig } from '../api'
import { useI18n } from '../i18n'

const configs = ref([])
const loading = ref(true)
const dialogVisible = ref(false)
const dialogTitle = ref('addLlmConfig')
const editingId = ref(null)
const saving = ref(false)
const testingId = ref(null)
const testDialogVisible = ref(false)
const testResult = ref(null)
const { t } = useI18n()

const defaultForm = {
  name: '',
  provider: 'openai',
  api_key: '',
  base_url: 'https://api.openai.com/v1',
  api_mode: 'chat_completions',
  model_name: 'gpt-4',
  temperature: 0.1,
  max_tokens: 4096,
  is_default: false,
}

const form = ref({ ...defaultForm })

const modeLabel = (mode) => (mode === 'responses' ? t('responses') : t('chatCompletions'))

const categoryLabel = (category) => {
  const keyMap = {
    ok: 'connectionCategoryOk',
    auth: 'connectionCategoryAuth',
    blocked: 'connectionCategoryBlocked',
    model: 'connectionCategoryModel',
    timeout: 'connectionCategoryTimeout',
    network: 'connectionCategoryNetwork',
    probe_mismatch: 'connectionCategoryProbeMismatch',
    empty_response: 'connectionCategoryEmptyResponse',
  }
  return t(keyMap[category] || category || 'unknown')
}

const normalizeTestResult = (payload, success) => ({
  success,
  strict_success: Boolean(payload?.strict_success),
  message: payload?.message || payload?.detail || '',
  model: payload?.model || '-',
  preferred_mode: payload?.preferred_mode || '-',
  successful_mode: payload?.successful_mode || '',
  strict_successful_mode: payload?.strict_successful_mode || '',
  attempts: Array.isArray(payload?.attempts) ? payload.attempts : [],
})

const loadConfigs = async () => {
  loading.value = true
  try {
    const res = await getLlmConfigs()
    configs.value = res.data
  } finally {
    loading.value = false
  }
}

onMounted(loadConfigs)

const openCreate = () => {
  editingId.value = null
  dialogTitle.value = 'addLlmConfig'
  form.value = { ...defaultForm }
  dialogVisible.value = true
}

const openEdit = (row) => {
  editingId.value = row.id
  dialogTitle.value = 'editLlmConfig'
  form.value = { ...defaultForm, ...row, api_key: '' }
  dialogVisible.value = true
}

const handleSave = async () => {
  if (!form.value.name || (!editingId.value && !form.value.api_key)) {
    ElMessage.warning(t('saveRequired'))
    return
  }
  saving.value = true
  try {
    if (editingId.value) {
      const payload = { ...form.value }
      if (!payload.api_key) delete payload.api_key
      await updateLlmConfig(editingId.value, payload)
      ElMessage.success(t('updated'))
    } else {
      await createLlmConfig(form.value)
      ElMessage.success(t('created'))
    }
    dialogVisible.value = false
    loadConfigs()
  } catch (e) {
    ElMessage.error(e.friendlyMessage || t('saveFailed'))
  } finally {
    saving.value = false
  }
}

const handleTest = async (row) => {
  testingId.value = row.id
  try {
    const res = await testLlmConfig(row.id)
    testResult.value = normalizeTestResult(res.data, true)
    testDialogVisible.value = true
    const successMode = res.data.successful_mode ? modeLabel(res.data.successful_mode) : '-'
    const strictText = res.data.strict_success ? t('strictProbePassedSuffix') : t('strictProbeFailedSuffix')
    ElMessage.success(t('connectivityModeOk', { mode: successMode, strictText }))
  } catch (e) {
    const errData = e.response?.data || {}
    const rawDetail = e.details || errData.details || errData.detail
    if (rawDetail && typeof rawDetail === 'object') {
      testResult.value = normalizeTestResult(rawDetail, false)
      testDialogVisible.value = true
      ElMessage.error(rawDetail.detail || rawDetail.message || e.friendlyMessage || t('connectivityFailed'))
    } else {
      ElMessage.error(e.friendlyMessage || t('connectivityFailed'))
    }
  } finally {
    testingId.value = null
  }
}

const handleDelete = async (row) => {
  try {
    await ElMessageBox.confirm(t('deleteConfigConfirm', { name: row.name }), t('confirm'), { type: 'warning' })
    await deleteLlmConfig(row.id)
    ElMessage.success(t('deleted'))
    loadConfigs()
  } catch {}
}
</script>

<template>
  <div>
    <div class="page-header">
      <h2 style="margin: 0">{{ t('llmConfigurations') }}</h2>
      <el-button type="primary" @click="openCreate">
        <el-icon><Plus /></el-icon> {{ t('addConfig') }}
      </el-button>
    </div>

    <el-table :data="configs" v-loading="loading" stripe>
      <el-table-column prop="name" :label="t('name')" width="150" />
      <el-table-column prop="provider" :label="t('provider')" width="120" />
      <el-table-column :label="t('apiKey')" width="120">
        <template #default="{ row }">
          <el-tag :type="row.has_api_key ? 'success' : 'info'" size="small">
            {{ row.has_api_key ? t('configured') : t('missing') }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="base_url" :label="t('baseUrl')" show-overflow-tooltip />
      <el-table-column prop="api_mode" :label="t('apiMode')" width="160">
        <template #default="{ row }">{{ modeLabel(row.api_mode) }}</template>
      </el-table-column>
      <el-table-column prop="model_name" :label="t('model')" width="160" />
      <el-table-column prop="temperature" :label="t('temp')" width="90" />
      <el-table-column prop="max_tokens" :label="t('maxTokens')" width="100" />
      <el-table-column :label="t('default')" width="80">
        <template #default="{ row }">
          <el-tag v-if="row.is_default" type="success" size="small">{{ t('yes') }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="t('actions')" width="260">
        <template #default="{ row }">
          <el-button size="small" text type="primary" @click="openEdit(row)">{{ t('edit') }}</el-button>
          <el-button size="small" text type="primary" :loading="testingId === row.id" @click="handleTest(row)">
            {{ t('testConnection') }}
          </el-button>
          <el-button size="small" text type="danger" @click="handleDelete(row)">{{ t('delete') }}</el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-empty v-if="!loading && !configs.length" :description="t('noConfigs')" />

    <el-dialog v-model="dialogVisible" :title="t(dialogTitle)" width="550px">
      <el-form :model="form" label-width="100px">
        <el-form-item :label="t('name')">
          <el-input v-model="form.name" :placeholder="t('exampleProductionModel')" />
        </el-form-item>
        <el-form-item :label="t('provider')">
          <el-select v-model="form.provider">
            <el-option label="OpenAI" value="openai" />
            <el-option label="Anthropic (proxy)" value="anthropic" />
            <el-option label="Ollama" value="ollama" />
            <el-option label="Other" value="other" />
          </el-select>
        </el-form-item>
        <el-form-item :label="t('apiKey')">
          <el-input
            v-model="form.api_key"
            type="password"
            show-password
            :placeholder="editingId ? t('keepCurrentKey') : 'sk-...'"
          />
        </el-form-item>
        <el-form-item :label="t('baseUrl')">
          <el-input v-model="form.base_url" :placeholder="t('exampleBaseUrl')" />
        </el-form-item>
        <el-form-item :label="t('apiMode')">
          <el-select v-model="form.api_mode">
            <el-option :label="t('chatCompletions')" value="chat_completions" />
            <el-option :label="t('responses')" value="responses" />
          </el-select>
        </el-form-item>
        <el-form-item :label="t('model')">
          <el-input v-model="form.model_name" :placeholder="t('exampleModel')" />
        </el-form-item>
        <el-form-item :label="t('temp')">
          <el-slider v-model="form.temperature" :min="0" :max="1" :step="0.1" show-input />
        </el-form-item>
        <el-form-item :label="t('maxTokens')">
          <el-input-number v-model="form.max_tokens" :min="256" :max="128000" :step="512" />
        </el-form-item>
        <el-form-item :label="t('default')">
          <el-switch v-model="form.is_default" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">{{ t('cancel') }}</el-button>
        <el-button type="primary" :loading="saving" @click="handleSave">{{ t('save') }}</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="testDialogVisible" :title="t('testConnection')" width="980px">
      <div v-if="testResult" style="display: flex; flex-direction: column; gap: 16px">
        <el-alert
          :title="testResult.success ? t('connectivityOk') : t('connectivityFailed')"
          :description="testResult.message || '-'"
          :type="testResult.success ? 'success' : 'error'"
          show-icon
          :closable="false"
        />

        <el-descriptions :column="2" border size="small">
          <el-descriptions-item :label="t('basicConnectivity')">
            <el-tag :type="testResult.success ? 'success' : 'danger'">
              {{ testResult.success ? t('success') : t('failed') }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item :label="t('strictProbe')">
            <el-tag :type="testResult.strict_success ? 'success' : 'warning'">
              {{ testResult.strict_success ? t('passed') : t('failed') }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item :label="t('model')">{{ testResult.model || '-' }}</el-descriptions-item>
          <el-descriptions-item :label="t('configuredMode')">{{ modeLabel(testResult.preferred_mode) }}</el-descriptions-item>
          <el-descriptions-item :label="t('basicSuccessMode')">
            {{ testResult.successful_mode ? modeLabel(testResult.successful_mode) : '-' }}
          </el-descriptions-item>
          <el-descriptions-item :label="t('strictSuccessMode')">
            {{ testResult.strict_successful_mode ? modeLabel(testResult.strict_successful_mode) : '-' }}
          </el-descriptions-item>
        </el-descriptions>

        <el-table :data="testResult.attempts" border size="small" :empty-text="t('noTestAttempts')">
          <el-table-column :label="t('attemptMode')" min-width="120">
            <template #default="{ row }">{{ modeLabel(row.stage) }}</template>
          </el-table-column>
          <el-table-column :label="t('basicConnectivity')" width="120">
            <template #default="{ row }">
              <el-tag :type="row.base_success ? 'success' : 'danger'">
                {{ row.base_success ? t('success') : t('failed') }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column :label="t('strictProbe')" width="120">
            <template #default="{ row }">
              <el-tag :type="row.strict_success ? 'success' : 'warning'">
                {{ row.strict_success ? t('passed') : t('failed') }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column :label="t('category')" min-width="190">
            <template #default="{ row }">{{ categoryLabel(row.category) }}</template>
          </el-table-column>
          <el-table-column :label="t('latency')" width="110">
            <template #default="{ row }">{{ row.latency_ms != null ? `${row.latency_ms} ms` : '-' }}</template>
          </el-table-column>
          <el-table-column :label="t('model')" min-width="120" prop="model" />
          <el-table-column :label="t('responseDetail')" min-width="260" show-overflow-tooltip>
            <template #default="{ row }">{{ row.message || '-' }}</template>
          </el-table-column>
          <el-table-column :label="t('diagnosisSuggestion')" min-width="280" show-overflow-tooltip>
            <template #default="{ row }">{{ row.diagnosis || '-' }}</template>
          </el-table-column>
          <el-table-column label="Tokens" width="100">
            <template #default="{ row }">{{ row.usage?.total_tokens ?? '-' }}</template>
          </el-table-column>
        </el-table>
      </div>
      <template #footer>
        <el-button @click="testDialogVisible = false">{{ t('cancel') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

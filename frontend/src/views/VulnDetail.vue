<script setup>
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { getVuln, updateVulnStatus } from '../api'
import { useI18n } from '../i18n'

const props = defineProps({ id: [String, Number] })
const router = useRouter()
const {
  t,
  statusLabel,
  severityLabel,
  severityColor,
  diffStatusLabel,
  pocTagType,
  verificationStateLabel,
  verificationStateType,
} = useI18n()

const vuln = ref(null)
const loading = ref(true)
const statusUpdating = ref(false)

const statusOptions = [
  { labelKey: 'pending', value: 'pending' },
  { labelKey: 'confirmed', value: 'confirmed' },
  { labelKey: 'falsePositive', value: 'false_positive' },
  { labelKey: 'fixed', value: 'fixed' },
]

onMounted(async () => {
  try {
    const res = await getVuln(props.id)
    vuln.value = res.data
  } catch {
    ElMessage.error(t('vulnerabilityNotFound'))
  } finally {
    loading.value = false
  }
})

const changeStatus = async (status) => {
  statusUpdating.value = true
  try {
    await updateVulnStatus(vuln.value.id, status)
    vuln.value.confirmed_status = status
    ElMessage.success(t('statusUpdated'))
  } catch {
    ElMessage.error(t('statusUpdateFailed'))
  } finally {
    statusUpdating.value = false
  }
}
</script>

<template>
  <div v-loading="loading">
    <div v-if="vuln">
      <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px">
        <div>
          <el-button text @click="router.push(`/audits/${vuln.task_id}`)">
            <el-icon><ArrowLeft /></el-icon> {{ t('backToAudit') }}
          </el-button>
          <h2 style="margin: 8px 0">{{ vuln.title }}</h2>
          <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap">
            <el-tag :color="severityColor(vuln.severity)" effect="dark" style="border: none">{{ severityLabel(vuln.severity) }}</el-tag>
            <el-tag>{{ vuln.vuln_type }}</el-tag>
            <el-tag :type="vuln.confirmed_status === 'confirmed' ? 'success' : vuln.confirmed_status === 'false_positive' ? 'info' : 'warning'">
              {{ statusLabel(vuln.confirmed_status) }}
            </el-tag>
            <el-tag :type="vuln.diff_status === 'existing' ? 'info' : 'danger'">
              {{ diffStatusLabel(vuln.diff_status) }}
            </el-tag>
            <el-tag :type="verificationStateType(vuln.verification_state)">
              {{ verificationStateLabel(vuln.verification_state) }}
            </el-tag>
            <el-tag :type="pocTagType(vuln.poc_validation_status)">
              {{ vuln.poc_validation_status === 'valid' ? t('pocValid') : vuln.poc_validation_status === 'invalid' ? t('pocInvalid') : t('pocUnknown') }}
            </el-tag>
            <el-tag
              v-if="vuln.confidence"
              size="small"
              :type="vuln.confidence === 'high' ? 'danger' : vuln.confidence === 'medium' ? 'warning' : 'info'"
            >
              {{ vuln.confidence === 'high' ? t('confidenceHigh') : vuln.confidence === 'medium' ? t('confidenceMedium') : t('confidenceLow') }}
            </el-tag>
          </div>
        </div>
        <el-dropdown @command="changeStatus">
          <el-button type="primary" :loading="statusUpdating">
            {{ t('updateStatus') }} <el-icon class="el-icon--right"><ArrowDown /></el-icon>
          </el-button>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item v-for="s in statusOptions" :key="s.value" :command="s.value">
                {{ t(s.labelKey) }}
              </el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </div>

      <el-row :gutter="20">
        <el-col :span="16">
          <el-card v-if="vuln.description" style="margin-bottom: 16px">
            <template #header><span style="font-weight: bold">{{ t('description') }}</span></template>
            <div style="white-space: pre-wrap; line-height: 1.8">{{ vuln.description }}</div>
          </el-card>

          <el-card v-if="vuln.code_snippet" style="margin-bottom: 16px">
            <template #header>
              <span style="font-weight: bold">
                {{ t('code') }}
                <span v-if="vuln.file_path" style="color: var(--text-muted); font-weight: normal; margin-left: 8px">
                  {{ vuln.file_path }}
                  <span v-if="vuln.line_start"> (L{{ vuln.line_start }}<span v-if="vuln.line_end">-{{ vuln.line_end }}</span>)</span>
                </span>
              </span>
            </template>
            <pre class="code-block">{{ vuln.code_snippet }}</pre>
          </el-card>

          <el-card v-if="vuln.poc_raw" style="margin-bottom: 16px">
            <template #header>
              <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap">
                <span style="font-weight: bold">{{ t('poc') }}</span>
                <el-tag size="small" :type="pocTagType(vuln.poc_validation_status)">
                  {{ vuln.poc_validation_status === 'valid' ? t('pocValid') : vuln.poc_validation_status === 'invalid' ? t('pocInvalid') : t('pocUnknown') }}
                </el-tag>
              </div>
            </template>
            <pre class="poc-block">{{ vuln.poc_raw }}</pre>
            <div
              v-if="vuln.poc_validation_note"
              :style="{
                marginTop: '12px',
                color: vuln.poc_validation_status === 'valid' ? '#67c23a' : '#c45656',
                lineHeight: '1.7',
                whiteSpace: 'pre-wrap',
              }"
            >
              {{ t('pocValidationNote') }}: {{ vuln.poc_validation_note }}
            </div>
          </el-card>

          <el-card v-if="vuln.fix_suggestion">
            <template #header><span style="font-weight: bold; color: var(--text-success)">{{ t('fixSuggestion') }}</span></template>
            <div style="white-space: pre-wrap; line-height: 1.8">{{ vuln.fix_suggestion }}</div>
          </el-card>
        </el-col>

        <el-col :span="8">
          <el-card shadow="hover">
            <template #header><span style="font-weight: bold">{{ t('details') }}</span></template>
            <el-descriptions :column="1" size="small" border>
              <el-descriptions-item label="ID">#{{ vuln.id }}</el-descriptions-item>
              <el-descriptions-item :label="t('type')">{{ vuln.vuln_type }}</el-descriptions-item>
              <el-descriptions-item :label="t('severity')">
                <el-tag :color="severityColor(vuln.severity)" effect="dark" size="small" style="border: none">{{ severityLabel(vuln.severity) }}</el-tag>
              </el-descriptions-item>
              <el-descriptions-item :label="t('file')">{{ vuln.file_path || t('notAvailable') }}</el-descriptions-item>
              <el-descriptions-item :label="t('lines')">
                {{ vuln.line_start ? `${vuln.line_start}-${vuln.line_end || vuln.line_start}` : t('notAvailable') }}
              </el-descriptions-item>
              <el-descriptions-item :label="t('endpoint')">
                <code v-if="vuln.endpoint">{{ vuln.endpoint }}</code>
                <span v-else class="text-muted">{{ t('notAvailable') }}</span>
              </el-descriptions-item>
              <el-descriptions-item :label="t('diffStatus')">
                {{ diffStatusLabel(vuln.diff_status) }}
              </el-descriptions-item>
              <el-descriptions-item :label="t('verificationState')">
                <el-tag size="small" :type="verificationStateType(vuln.verification_state)">
                  {{ verificationStateLabel(vuln.verification_state) }}
                </el-tag>
              </el-descriptions-item>
              <el-descriptions-item :label="t('confidence')">
                <el-tag
                  size="small"
                  :type="vuln.confidence === 'high' ? 'danger' : vuln.confidence === 'medium' ? 'warning' : 'info'"
                >
                  {{ vuln.confidence === 'high' ? t('confidenceHigh') : vuln.confidence === 'medium' ? t('confidenceMedium') : t('confidenceLow') }}
                </el-tag>
              </el-descriptions-item>
              <el-descriptions-item :label="t('status')">{{ statusLabel(vuln.confirmed_status) }}</el-descriptions-item>
            </el-descriptions>
          </el-card>
        </el-col>
      </el-row>
    </div>
  </div>
</template>

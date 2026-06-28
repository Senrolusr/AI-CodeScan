<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { getVuln, updateVulnReview } from '../api'
import { useI18n } from '../i18n'
import {
  localizeVulnerabilityLabel,
  reviewStatusLabel,
  reviewStatusTagType,
  vulnLifecycleLabel,
} from '../utils/vulnerabilityLabels'

const props = defineProps({ id: [String, Number] })
const router = useRouter()
const {
  locale,
  t,
  severityLabel,
  severityColor,
  pocTagType,
  confidenceTagType,
  confidenceLabel,
  formatDateTime,
} = useI18n()

const vuln = ref(null)
const loading = ref(true)
const saving = ref(false)

// 复核表单：review_status / status / review_note。
// reviewer 由后端按登录用户写入，前端不采集（见 L248 保存后只读展示）。
const reviewForm = ref({
  review_status: 'unreviewed',
  status: 'open',
  review_note: '',
})

const reviewOptions = computed(() => [
  { value: 'unreviewed', label: reviewStatusLabel('unreviewed', locale.value) },
  { value: 'confirmed', label: reviewStatusLabel('confirmed', locale.value) },
  { value: 'rejected', label: reviewStatusLabel('rejected', locale.value) },
  { value: 'needs_review', label: reviewStatusLabel('needs_review', locale.value) },
])

const lifecycleOptions = computed(() => [
  { value: 'open', label: vulnLifecycleLabel('open', locale.value) },
  { value: 'accepted_risk', label: vulnLifecycleLabel('accepted_risk', locale.value) },
  { value: 'fixed', label: vulnLifecycleLabel('fixed', locale.value) },
])

const hydrateReviewForm = (data) => {
  if (!data) return
  reviewForm.value.review_status = data.review_status || 'unreviewed'
  reviewForm.value.status = data.status || 'open'
  reviewForm.value.review_note = data.review_note || ''
}

onMounted(async () => {
  try {
    const res = await getVuln(props.id)
    vuln.value = res.data
    hydrateReviewForm(res.data)
  } catch {
    ElMessage.error(t('vulnerabilityNotFound'))
  } finally {
    loading.value = false
  }
})

const saveReview = async () => {
  if (!vuln.value) return
  saving.value = true
  try {
    const payload = {
      review_status: reviewForm.value.review_status,
      status: reviewForm.value.status,
      review_note: reviewForm.value.review_note,
    }
    const res = await updateVulnReview(vuln.value.id, payload)
    vuln.value = res.data
    ElMessage.success(t('reviewSaveSuccess'))
  } catch (err) {
    ElMessage.error(err?.friendlyMessage || t('reviewSaveFailed'))
  } finally {
    saving.value = false
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
            <el-tag>{{ localizeVulnerabilityLabel(vuln.vuln_type, locale) }}</el-tag>
            <el-tag :type="pocTagType(vuln.poc_validation_status)">
              {{ vuln.poc_validation_status === 'valid' ? t('pocValid') : vuln.poc_validation_status === 'invalid' ? t('pocInvalid') : t('pocUnknown') }}
            </el-tag>
            <el-tag
              v-if="vuln.review_status && vuln.review_status !== 'unreviewed'"
              :type="reviewStatusTagType(vuln.review_status)"
            >
              {{ reviewStatusLabel(vuln.review_status, locale) }}
            </el-tag>
            <el-tag
              v-if="vuln.confidence"
              size="small"
              :type="confidenceTagType(vuln.confidence)"
            >
              {{ confidenceLabel(vuln.confidence) }}
            </el-tag>
          </div>
        </div>
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
              <el-descriptions-item :label="t('type')">{{ localizeVulnerabilityLabel(vuln.vuln_type, locale) }}</el-descriptions-item>
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
              <el-descriptions-item v-if="vuln.route_id" :label="t('relatedRoute')">
                <code>{{ vuln.route_method }} {{ vuln.route_path }}</code>
                <div v-if="vuln.route_handler" style="font-size: 12px; color: var(--text-muted); margin-top: 2px">{{ vuln.route_handler }}</div>
              </el-descriptions-item>
              <el-descriptions-item :label="t('confidence')">
                <el-tag
                  size="small"
                  :type="confidenceTagType(vuln.confidence)"
                >
                  {{ confidenceLabel(vuln.confidence) }}
                </el-tag>
              </el-descriptions-item>
            </el-descriptions>
          </el-card>

          <el-card shadow="hover" style="margin-top: 16px">
            <template #header><span style="font-weight: bold">{{ t('manualReview') }}</span></template>
            <el-form label-position="top" size="small">
              <el-form-item :label="t('reviewConclusionLabel')">
                <el-select v-model="reviewForm.review_status" style="width: 100%">
                  <el-option
                    v-for="opt in reviewOptions"
                    :key="opt.value"
                    :label="opt.label"
                    :value="opt.value"
                  />
                </el-select>
              </el-form-item>
              <el-form-item :label="t('reviewLifecycle')">
                <el-select v-model="reviewForm.status" style="width: 100%">
                  <el-option
                    v-for="opt in lifecycleOptions"
                    :key="opt.value"
                    :label="opt.label"
                    :value="opt.value"
                  />
                </el-select>
              </el-form-item>
              <el-form-item :label="t('reviewNote')">
                <el-input
                  v-model="reviewForm.review_note"
                  type="textarea"
                  :rows="3"
                  :placeholder="t('reviewNotePlaceholder')"
                />
              </el-form-item>
              <el-form-item>
                <el-button type="primary" :loading="saving" style="width: 100%" @click="saveReview">
                  {{ t('save') }}
                </el-button>
              </el-form-item>
            </el-form>
            <div v-if="vuln.reviewed_at" style="margin-top: 8px; color: var(--text-muted); font-size: 12px; line-height: 1.6">
              <div>{{ t('reviewedAt') }}：{{ formatDateTime(vuln.reviewed_at) }}</div>
              <div v-if="vuln.reviewer">{{ t('reviewer') }}：{{ vuln.reviewer }}</div>
            </div>
            <div v-if="reviewForm.review_status === 'rejected'" style="margin-top: 8px; color: var(--text-danger); font-size: 12px; line-height: 1.6">
              {{ t('rejectExcludedHint') }}
            </div>
          </el-card>
        </el-col>
      </el-row>
    </div>
  </div>
</template>

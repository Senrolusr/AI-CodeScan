<script setup>
import { useI18n } from '../i18n'

defineProps({ vuln: Object })
const emit = defineEmits(['click'])
const {
  statusLabel,
  severityLabel,
  severityColor,
  diffStatusLabel,
  pocTagType,
  verificationStateLabel,
  verificationStateType,
  t,
} = useI18n()
</script>

<template>
  <div class="vuln-card" @click="emit('click')">
    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px">
      <el-tag :color="severityColor(vuln.severity)" effect="dark" size="small" style="border: none">
        {{ severityLabel(vuln.severity) }}
      </el-tag>
      <el-tag size="small">{{ vuln.vuln_type }}</el-tag>
      <span style="font-weight: 600; font-size: 14px; color: var(--text-primary)">{{ vuln.title }}</span>
    </div>
    <div style="display: flex; gap: 16px; color: var(--text-muted); font-size: 12px; flex-wrap: wrap">
      <span v-if="vuln.file_path">
        <el-icon><Document /></el-icon> {{ vuln.file_path }}
      </span>
      <span v-if="vuln.endpoint">
        <el-icon><Link /></el-icon> {{ vuln.endpoint }}
      </span>
      <el-tag
        :type="vuln.confirmed_status === 'confirmed' ? 'success' : vuln.confirmed_status === 'false_positive' ? 'info' : 'warning'"
        size="small"
      >
        {{ statusLabel(vuln.confirmed_status) }}
      </el-tag>
      <el-tag size="small" :type="vuln.diff_status === 'existing' ? 'info' : 'danger'">
        {{ diffStatusLabel(vuln.diff_status) }}
      </el-tag>
      <el-tag size="small" :type="verificationStateType(vuln.verification_state)">
        {{ verificationStateLabel(vuln.verification_state) }}
      </el-tag>
      <el-tag size="small" :type="pocTagType(vuln.poc_validation_status)">
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
    <div
      v-if="vuln.poc_validation_note && vuln.poc_validation_status === 'invalid'"
      style="margin-top: 8px; color: var(--text-danger); font-size: 12px; line-height: 1.6"
    >
      {{ vuln.poc_validation_note }}
    </div>
  </div>
</template>

<style scoped>
.vuln-card {
  padding: 12px 16px;
  border: 1px solid var(--border-default);
  border-radius: 6px;
  margin-bottom: 8px;
  cursor: pointer;
  transition: all 0.2s;
}

.vuln-card:hover {
  border-color: #409eff;
  box-shadow: 0 2px 8px rgba(64, 158, 255, 0.15);
}
</style>

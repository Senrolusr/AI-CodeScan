<script setup>
import { computed } from 'vue'
import { useI18n } from '../i18n'
import { normalizeScanStats } from '../utils/scanStats'

const props = defineProps({
  stats: { type: Object, default: () => ({}) },
  routeCountFallback: { type: Number, default: 0 },
  ruleHitFallback: { type: Number, default: 0 },
  tokenStats: { type: Object, default: null },
  showTokenUsage: { type: Boolean, default: false },
  showRouteSourceFiles: { type: Boolean, default: true },
  showWarnings: { type: Boolean, default: true },
})

const { t } = useI18n()
const scanStats = computed(() => normalizeScanStats(props.stats, {
  routeCountFallback: props.routeCountFallback,
  ruleHitFallback: props.ruleHitFallback,
}))
const shouldShowTokenUsage = computed(() => props.showTokenUsage && props.tokenStats)
const shouldShowWarning = computed(() => props.showWarnings && (
  scanStats.value.partial_audit
  || scanStats.value.truncated_by_audit_file_count
  || scanStats.value.truncated_by_code_chunks
  || scanStats.value.truncated_by_total_chars
))
</script>

<template>
  <el-card style="margin-bottom: 20px">
    <template #header><span class="card-title">{{ t('scanOverview') }}</span></template>
    <el-descriptions :column="4" border size="small">
      <el-descriptions-item :label="t('sourceFilesDetected')">{{ scanStats.source_files_detected || 0 }}</el-descriptions-item>
      <el-descriptions-item :label="t('sourceFilesIndexed')">{{ scanStats.source_files_indexed || 0 }}</el-descriptions-item>
      <el-descriptions-item :label="t('auditFilesSelected')">{{ scanStats.files_selected_for_audit || 0 }}</el-descriptions-item>
      <el-descriptions-item :label="t('chunkCandidateFiles')">{{ scanStats.files_considered_for_chunks || 0 }}</el-descriptions-item>
      <el-descriptions-item :label="t('effectiveContentFiles')">{{ scanStats.files_with_content || 0 }}</el-descriptions-item>
      <el-descriptions-item :label="t('chunkCount')">{{ scanStats.chunk_count || 0 }}</el-descriptions-item>
      <el-descriptions-item :label="t('routeCount')">{{ scanStats.route_count || 0 }}</el-descriptions-item>
      <el-descriptions-item v-if="showRouteSourceFiles" :label="t('routeSourceFiles')">{{ scanStats.route_source_files || 0 }}</el-descriptions-item>
      <el-descriptions-item :label="t('oversizedFilesSkipped')">{{ scanStats.oversized_files_skipped || 0 }}</el-descriptions-item>
      <el-descriptions-item :label="t('oversizedFilesCompacted')">{{ scanStats.oversized_files_compacted || 0 }}</el-descriptions-item>
      <el-descriptions-item :label="t('ruleHitCount')">{{ scanStats.rule_hit_count || 0 }}</el-descriptions-item>
      <el-descriptions-item v-if="shouldShowTokenUsage" :label="t('tokenUsage')">
        <span>{{ t('promptTokens') }}: {{ tokenStats.prompt_tokens?.toLocaleString() || 0 }} / {{ t('completionTokens') }}: {{ tokenStats.completion_tokens?.toLocaleString() || 0 }}</span>
        <span style="margin-left: 12px; color: var(--el-color-info)">({{ tokenStats.llm_call_count || 0 }} {{ t('llmCalls') }})</span>
      </el-descriptions-item>
    </el-descriptions>
    <div v-if="shouldShowWarning" class="warning-notice">
      <div>{{ t('scanTruncatedNotice') }}</div>
      <div v-if="scanStats.oversized_files_skipped">{{ t('oversizedFilesSkippedNotice', { count: scanStats.oversized_files_skipped }) }}</div>
      <div v-if="scanStats.truncated_by_audit_file_count">{{ t('auditFilesTruncatedNotice', { selected: scanStats.files_selected_for_audit || 0, skipped: scanStats.files_skipped_by_audit_file_budget || 0 }) }}</div>
      <div v-if="scanStats.truncated_by_code_chunks">{{ t('codeChunksTruncatedNotice') }}</div>
      <div v-if="scanStats.truncated_by_total_chars">{{ t('totalCharsTruncatedNotice') }}</div>
    </div>
  </el-card>
</template>

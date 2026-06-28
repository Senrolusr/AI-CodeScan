<script setup>
import { computed } from 'vue'
import { storeToRefs } from 'pinia'
import VulnCard from '../VulnCard.vue'
import { useAuditDetailStore } from '../../stores/auditDetail'
import { useI18n } from '../../i18n'
import { buildSeverityStats } from '../../utils/auditRecommendations'
import { reviewStatusLabel } from '../../utils/vulnerabilityLabels'

// 漏洞列表 + 复核/严重度筛选。直接读 auditDetail store（filter 与列表同源，
// 筛选变更触发 store.loadVulns 重拉）；点击单条交由父组件路由跳转。
const emit = defineEmits(['select'])
const store = useAuditDetailStore()
const { vulns, filter, reviewSummary } = storeToRefs(store)
const { locale, t, severityLabel } = useI18n()
const severityStats = computed(() => buildSeverityStats(vulns.value || []))
const handleFilter = () => store.loadVulns()
</script>

<template>
  <el-card>
    <template #header>
      <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap">
        <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap">
          <span class="card-title">{{ t('vulnerabilities') }} ({{ vulns.length }})</span>
          <el-tag size="small" type="danger">{{ severityLabel('Critical') }} {{ severityStats.Critical }}</el-tag>
          <el-tag size="small" type="warning">{{ severityLabel('High') }} {{ severityStats.High }}</el-tag>
          <el-tag v-if="reviewSummary.confirmed" size="small" type="success">{{ reviewStatusLabel('confirmed', locale) }} {{ reviewSummary.confirmed }}</el-tag>
          <el-tag v-if="reviewSummary.rejected" size="small" type="info">{{ reviewStatusLabel('rejected', locale) }} {{ reviewSummary.rejected }}</el-tag>
          <el-tag v-if="reviewSummary.needs_review" size="small" type="warning">{{ reviewStatusLabel('needs_review', locale) }} {{ reviewSummary.needs_review }}</el-tag>
        </div>
        <div style="display: flex; gap: 8px">
          <el-select v-model="filter.review_status" :placeholder="t('reviewStatus')" clearable size="small" style="width: 120px" @change="handleFilter">
            <el-option :label="reviewStatusLabel('unreviewed', locale)" value="unreviewed" />
            <el-option :label="reviewStatusLabel('confirmed', locale)" value="confirmed" />
            <el-option :label="reviewStatusLabel('rejected', locale)" value="rejected" />
            <el-option :label="reviewStatusLabel('needs_review', locale)" value="needs_review" />
          </el-select>
          <el-select v-model="filter.severity" :placeholder="t('severity')" clearable size="small" style="width: 120px" @change="handleFilter">
            <el-option :label="severityLabel('Critical')" value="Critical" />
            <el-option :label="severityLabel('High')" value="High" />
            <el-option :label="severityLabel('Medium')" value="Medium" />
            <el-option :label="severityLabel('Low')" value="Low" />
          </el-select>
        </div>
      </div>
    </template>
    <div v-if="vulns.length">
      <VulnCard v-for="v in vulns" :key="v.id" :vuln="v" @click="emit('select', v.id)" />
    </div>
    <el-empty v-else :description="t('noVulnsInAudit')" :image-size="60" />
  </el-card>
</template>

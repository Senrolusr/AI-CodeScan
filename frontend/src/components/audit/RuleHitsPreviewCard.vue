<script setup>
import { computed, ref } from 'vue'
import { storeToRefs } from 'pinia'
import { useAuditDetailStore } from '../../stores/auditDetail'
import { useI18n } from '../../i18n'

// 规则命中预览卡：读 store 的 project_rule_hits（M4 结构化表，Top 20 按
// weighted_score desc 已排好），展开/折叠态本地持有。自包含，无 props/emits。
const store = useAuditDetailStore()
const { projectRuleHits } = storeToRefs(store)
const { t } = useI18n()

const expandedRuleHits = ref([])
const ruleHitsExpanded = ref(false)
const ruleHitsPreview = computed(() => projectRuleHits.value.slice(0, 20))

// U+FFFD（替换字符）用 fromCodePoint 构造，避免源码里写裸替换字符被编辑器/工具链改写。
const _REPLACEMENT_RE = new RegExp(String.fromCodePoint(0xFFFD) + '+', 'g')
const cleanRuleHitText = (value) => String(value || '').replace(_REPLACEMENT_RE, '').replace(/\s+/g, ' ').trim()
const formatRuleHitTitle = (hit) => cleanRuleHitText(hit?.title || hit?.label || t('noRuleHit')) || t('noRuleHit')
const formatRuleHitEvidence = (hit) => {
  const text = cleanRuleHitText(hit?.evidence || '')
  if (!text) return '--'
  return text.length > 280 ? `${text.slice(0, 280)}...` : text
}
const hitStageLabels = (hit) => {
  const nums = hit?.stage_nums
  if (!Array.isArray(nums) || !nums.length) return ''
  return nums.map(n => `S${n}`).join(', ')
}
</script>

<template>
  <el-card v-if="ruleHitsPreview.length" style="margin-bottom: 20px">
    <template #header>
      <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; cursor: pointer" @click="ruleHitsExpanded = !ruleHitsExpanded">
        <div style="display: flex; align-items: center; gap: 8px">
          <span class="card-title">{{ t('ruleHitPreview') }}</span>
          <el-tag type="warning" size="small">Top {{ ruleHitsPreview.length }}</el-tag>
        </div>
        <el-button size="small" text :icon="ruleHitsExpanded ? 'ArrowUp' : 'ArrowDown'" @click.stop="ruleHitsExpanded = !ruleHitsExpanded">
          {{ ruleHitsExpanded ? t('collapse') : t('expand') }}
        </el-button>
      </div>
    </template>
    <div v-show="ruleHitsExpanded" style="display: grid; gap: 10px">
      <el-collapse v-model="expandedRuleHits">
        <el-collapse-item
          v-for="(hit, index) in ruleHitsPreview"
          :key="`${hit.file_path || 'rule'}-${hit.label || 'hit'}-${index}`"
          :name="index"
        >
          <template #title>
            <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap">
              <strong>{{ formatRuleHitTitle(hit) }}</strong>
              <el-tag size="small" type="danger">{{ hit.label || 'rule' }}</el-tag>
              <el-tag size="small" type="info">score {{ hit.risk_score || 0 }}</el-tag>
              <el-tag size="small" type="warning">hits {{ hit.keyword_hit_count || 0 }}</el-tag>
              <el-tag v-if="hit.chunk_type && hit.chunk_type !== 'full'" size="small" type="" effect="plain">{{ hit.chunk_type }}</el-tag>
              <span v-if="hitStageLabels(hit)" style="color: var(--text-muted); font-size: 12px">{{ t('relatedStages') }}: {{ hitStageLabels(hit) }}</span>
            </div>
          </template>
          <div style="color: var(--text-secondary); font-size: 13px; line-height: 1.8; word-break: break-all; padding: 4px 0">
            <div><strong>{{ t('hitFile') }}:</strong> {{ hit.file_path || '--' }}</div>
            <div><strong>{{ t('hitChunk') }}:</strong> {{ hit.chunk_path || '--' }}</div>
            <div><strong>{{ t('hitEvidence') }}:</strong> {{ formatRuleHitEvidence(hit) }}</div>
          </div>
        </el-collapse-item>
      </el-collapse>
    </div>
  </el-card>
</template>

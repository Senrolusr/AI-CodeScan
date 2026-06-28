import { describe, it, expect, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import ElementPlus from 'element-plus'

import RuleHitsPreviewCard from './RuleHitsPreviewCard.vue'
import { useAuditDetailStore } from '../../stores/auditDetail'

const FFFD = String.fromCodePoint(0xFFFD) // U+FFFD 替换字符

describe('RuleHitsPreviewCard', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  it('renders nothing when there are no rule hits', () => {
    const store = useAuditDetailStore()
    store.$patch({ projectRuleHits: [] })
    const wrapper = mount(RuleHitsPreviewCard, { global: { plugins: [ElementPlus] } })
    // 卡片 v-if="ruleHitsPreview.length" 为假 → 不渲染
    expect(wrapper.text()).toBe('')
  })

  it('renders the top hit and strips U+FFFD from its title', () => {
    const store = useAuditDetailStore()
    store.$patch({
      projectRuleHits: [
        {
          label: 'L1',
          // 故意夹带替换字符 + 多余空白，验证 cleanRuleHitText 清洗
          title: 'bad' + FFFD + '  title',
          risk_score: 9,
          keyword_hit_count: 3,
          file_path: '/a.py',
          chunk_path: '/a.py:c1',
          stage_nums: [2],
        },
      ],
    })
    const wrapper = mount(RuleHitsPreviewCard, { global: { plugins: [ElementPlus] } })
    const html = wrapper.html()
    expect(html).not.toContain(FFFD) // 替换字符已被清掉
    // 'bad�  title' → 去替换字符 → 'bad  title' → 折叠空白 → 'bad title'
    expect(html).toContain('bad title')
  })

  it('limits the preview to the top 20 from projectRuleHits', () => {
    const store = useAuditDetailStore()
    const hits = Array.from({ length: 25 }, (_, i) => ({ label: `L${i}`, title: `t${i}`, file_path: '/x' }))
    store.$patch({ projectRuleHits: hits })
    const wrapper = mount(RuleHitsPreviewCard, { global: { plugins: [ElementPlus] } })
    expect(wrapper.text()).toContain('Top 20')
  })
})

import { describe, it, expect } from 'vitest'
import { eventLabel, stageLabel, eventStageText, eventSummary } from './auditEvents'

describe('auditEvents utils', () => {
  describe('eventLabel', () => {
    it('返回已知事件类型的中文标签', () => {
      expect(eventLabel('finding.created')).toBe('发现写入')
      expect(eventLabel('finding.filtered')).toBe('发现过滤')
      expect(eventLabel('artifact.written')).toBe('产物写入')
      expect(eventLabel('stage.completed')).toBe('审计阶段完成')
    })

    it('未知类型回退到原值', () => {
      expect(eventLabel('something.weird')).toBe('something.weird')
      expect(eventLabel(undefined)).toBe('--')
    })
  })

  describe('stageLabel / eventStageText', () => {
    it('把阶段号映射为短标签', () => {
      expect(stageLabel(2)).toBe('Stage 2 RCE')
      expect(stageLabel(-1)).toBe('Supervisor 规划')
      expect(stageLabel(99)).toBe('Stage 99')
    })

    it('eventStageText 读 event.stage_num', () => {
      expect(eventStageText({ stage_num: 3 })).toBe('Stage 3 注入')
      expect(eventStageText({ stage_num: null })).toBe('')
      expect(eventStageText({})).toBe('')
    })
  })

  describe('eventSummary — 新增三类事件 payload 形状', () => {
    it('finding.created：带 title+severity', () => {
      expect(eventSummary({
        event_type: 'finding.created',
        stage_num: 2,
        payload: { title: 'SQL 注入', severity: 'High', vuln_type: 'sqli', file_path: 'app/api.py' },
      })).toBe('发现新漏洞：SQL 注入（High）')
    })

    it('finding.created：缺 title 回退通用文案', () => {
      expect(eventSummary({ event_type: 'finding.created', payload: {} })).toBe('写入新漏洞')
    })

    it('finding.filtered：带 title', () => {
      expect(eventSummary({
        event_type: 'finding.filtered',
        stage_num: 2,
        payload: { title: '幽灵漏洞', reason: '缺少 file_path' },
      })).toBe('过滤候选：幽灵漏洞')
    })

    it('artifact.written：携带 artifact_path → 阶段产物已写入', () => {
      expect(eventSummary({
        event_type: 'artifact.written',
        stage_num: 3,
        payload: { artifact_path: 'data/stage_artifacts/1/stage_3_passes.json', stage_num: 3 },
      })).toBe('Stage 3 注入产物已写入')
    })

    it('artifact.written：无 stage → 通用文案', () => {
      expect(eventSummary({
        event_type: 'artifact.written',
        payload: { artifact_path: 'x.json' },
      })).toBe('阶段产物已写入')
    })
  })

  describe('eventSummary — 既有事件回归', () => {
    it('run.completed / stage.completed 不受影响', () => {
      expect(eventSummary({ event_type: 'run.completed', payload: { message: 'done' } })).toBe('done')
      expect(eventSummary({ event_type: 'stage.completed', stage_num: 2, payload: {} })).toBe('Stage 2 RCE 完成')
    })

    it('review/rerun/reset 事件有清晰摘要（111.md）', () => {
      expect(eventLabel('review.started')).toBe('Supervisor 复核开始')
      expect(eventLabel('rerun.requested')).toBe('复核请求重跑')
      expect(eventLabel('stage.reset_for_rerun')).toBe('阶段重置重跑')
      expect(eventSummary({ event_type: 'review.started', payload: {} })).toBe('Supervisor 开始复核审计结果')
      expect(eventSummary({ event_type: 'rerun.requested', payload: { stage_nums: [2, 7] } })).toBe('复核请求重跑 Stage 2 RCE、Stage 7 配置依赖')
      expect(eventSummary({ event_type: 'stage.reset_for_rerun', payload: { stage_nums: [2, 7] } })).toBe('已重置 Stage 2 RCE、Stage 7 配置依赖，准备重跑')
      expect(eventSummary({ event_type: 'review.completed', payload: { request_rerun: true, rerun_stage_nums: [7] } })).toBe('Supervisor 复核完成，建议重跑 Stage 7 配置依赖')
    })

    it('run.paused / run.resumed 摘要��GAP3）', () => {
      expect(eventSummary({ event_type: 'run.paused', payload: { reason: '用户暂停' } })).toBe('用户暂停')
      expect(eventSummary({ event_type: 'run.paused', payload: {} })).toBe('任务已暂停，可在阶段边界恢复')
      expect(eventSummary({ event_type: 'run.resumed', payload: { mode: 'rerun' } })).toBe('已恢复执行（续跑）')
    })

    it('空对象返回空串', () => {
      expect(eventSummary(null)).toBe('')
      expect(eventSummary({})).toBe('')
    })
  })
})

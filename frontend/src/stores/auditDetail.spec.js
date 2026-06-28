import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

// 拦截 api 层：store 只应消费这些函数的返回值，绝不真正发网络请求。
vi.mock('../api', () => ({
  getAuditSnapshot: vi.fn(),
  getAuditStageArtifact: vi.fn(),
  getProjectRuleHits: vi.fn(),
}))

import { getAuditSnapshot, getAuditStageArtifact, getProjectRuleHits } from '../api'
import { useAuditDetailStore } from './auditDetail'

// 构造一份可控快照。stage-1 默认带 artifact_path + completed，便于测 artifact 去重。
function makeSnapshot({
  taskId = 1,
  taskProjectId = 7,
  taskStatus = 'completed',
  stageOneStatus = 'completed',
  artifactPath = '/runs/1/stage1.json',
  vulns = [],
  stageOneDetail = null,
} = {}) {
  return {
    task: { id: taskId, project_id: taskProjectId, status: taskStatus, summary: {} },
    stages: [
      { stage_num: 1, status: stageOneStatus, artifact_path: artifactPath, stage_name: '架构', findings: {} },
      { stage_num: 2, status: 'completed', stage_name: '注入', findings: {} },
    ],
    stage_one_detail: stageOneDetail,
    reports: [],
    recent_events: [],
    current_run: null,
    agent_runs: [],
    diagnostics: null,
    vulnerabilities: vulns,
    review_summary: { confirmed: 0, rejected: 0, needs_review: 0, unreviewed: 0 },
  }
}

describe('useAuditDetailStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
    // 默认成功返回，个别用例覆盖。
    getAuditSnapshot.mockResolvedValue({ data: makeSnapshot() })
    getAuditStageArtifact.mockResolvedValue({ data: { artifact_path: '/x', payload: {} } })
    getProjectRuleHits.mockResolvedValue({ data: [] })
  })

  describe('init / applySnapshot', () => {
    it('loads snapshot + rule hits and clears loading', async () => {
      getAuditSnapshot.mockResolvedValue({ data: makeSnapshot({ vulns: [{ id: 1 }, { id: 2 }] }) })
      getProjectRuleHits.mockResolvedValue({ data: [{ label: 'rule-a' }] })
      const store = useAuditDetailStore()
      expect(store.loading).toBe(true)
      await store.init(1)
      expect(store.task.id).toBe(1)
      expect(store.stages).toHaveLength(2)
      expect(store.vulns).toHaveLength(2)
      expect(store.projectRuleHits).toHaveLength(1)
      expect(store.reviewSummary.confirmed).toBe(0)
      expect(store.loading).toBe(false)
      // 首拉会用默认 filter
      expect(getAuditSnapshot).toHaveBeenCalledWith(1, { severity: '', review_status: '' })
    })

    it('propagates snapshot error and still clears loading (caller shows the message)', async () => {
      getAuditSnapshot.mockRejectedValue(new Error('network down'))
      const store = useAuditDetailStore()
      await expect(store.init(1)).rejects.toThrow('network down')
      expect(store.loading).toBe(false)
      expect(store.task).toBeNull()
    })

    it('resets stale state from a previous task on re-init', async () => {
      getAuditSnapshot.mockResolvedValue({ data: makeSnapshot({ vulns: [{ id: 99 }], taskProjectId: 7 }) })
      getProjectRuleHits.mockResolvedValue({ data: [{ label: 'old' }] })
      const store = useAuditDetailStore()
      await store.init(1)
      expect(store.vulns).toHaveLength(1)
      expect(store.projectRuleHits).toHaveLength(1)

      getAuditSnapshot.mockResolvedValue({
        data: { task: { id: 2, project_id: 8 }, stages: [], vulnerabilities: [], reports: [], review_summary: {} },
      })
      getProjectRuleHits.mockResolvedValue({ data: [] })
      await store.init(2)
      expect(store.task.id).toBe(2)
      expect(store.vulns).toHaveLength(0)
      expect(store.projectRuleHits).toHaveLength(0)
    })

    it('passes the current filter through to getAuditSnapshot', async () => {
      const store = useAuditDetailStore()
      await store.init(1) // 设默认 filter
      store.filter = { severity: 'Critical', review_status: 'confirmed' }
      await store.loadSnapshot()
      expect(getAuditSnapshot).toHaveBeenLastCalledWith(1, { severity: 'Critical', review_status: 'confirmed' })
    })

    it('maps route_coverage from the top-level snapshot key (§17.3, not from task.summary)', async () => {
      const snap = makeSnapshot()
      snap.route_coverage = { coverage_ratio: 0.75, has_route_gaps: true, total_routes: 8 }
      getAuditSnapshot.mockResolvedValue({ data: snap })
      const store = useAuditDetailStore()
      await store.init(1)
      expect(store.routeCoverage.coverage_ratio).toBe(0.75)
      expect(store.routeCoverage.has_route_gaps).toBe(true)
    })

    it('maps run diagnostics and agent runs from the snapshot', async () => {
      const snap = makeSnapshot()
      snap.agent_runs = [{ id: 11, agent_role: 'sub_agent', status: 'running' }]
      snap.diagnostics = { focus_status: 'running', current_stage_num: 3, active_agent_run_id: 11 }
      getAuditSnapshot.mockResolvedValue({ data: snap })
      const store = useAuditDetailStore()
      await store.init(1)
      expect(store.agentRuns).toHaveLength(1)
      expect(store.agentRuns[0].id).toBe(11)
      expect(store.diagnostics.focus_status).toBe('running')
      expect(store.diagnostics.current_stage_num).toBe(3)
    })
  })

  describe('loadStageOneArtifact dedup', () => {
    it('does NOT refetch when stage-1 status is unchanged', async () => {
      const store = useAuditDetailStore()
      await store.init(1)
      expect(getAuditStageArtifact).toHaveBeenCalledTimes(1)
      await store.loadSnapshot() // 同状态
      await store.loadSnapshot()
      expect(getAuditStageArtifact).toHaveBeenCalledTimes(1) // 仍只 1 次（去重生效）
    })

    it('refetches when stage-1 status changes', async () => {
      getAuditSnapshot.mockResolvedValue({ data: makeSnapshot({ stageOneStatus: 'running' }) })
      const store = useAuditDetailStore()
      await store.init(1)
      expect(getAuditStageArtifact).toHaveBeenCalledTimes(1)
      getAuditSnapshot.mockResolvedValue({ data: makeSnapshot({ stageOneStatus: 'completed' }) })
      await store.loadSnapshot()
      expect(getAuditStageArtifact).toHaveBeenCalledTimes(2)
    })

    it('force: true bypasses the dedup', async () => {
      const store = useAuditDetailStore()
      await store.init(1)
      const before = getAuditStageArtifact.mock.calls.length
      await store.loadStageOneArtifact({ force: true })
      expect(getAuditStageArtifact.mock.calls.length).toBe(before + 1)
    })

    it('nulls the artifact and skips fetch when stage-1 has no artifact_path', async () => {
      getAuditSnapshot.mockResolvedValue({ data: makeSnapshot({ artifactPath: '' }) })
      const store = useAuditDetailStore()
      await store.init(1)
      expect(getAuditStageArtifact).not.toHaveBeenCalled()
      expect(store.stageOneArtifact).toBeNull()
    })
  })

  describe('loadProjectRuleHits', () => {
    it('clears to empty when task has no project_id', async () => {
      getAuditSnapshot.mockResolvedValue({ data: { ...makeSnapshot(), task: { id: 1, status: 'completed' } } })
      const store = useAuditDetailStore()
      await store.init(1)
      // project_id 缺失 → 不请求、置空
      expect(getProjectRuleHits).not.toHaveBeenCalled()
      expect(store.projectRuleHits).toEqual([])
    })

    it('swallows fetch errors and keeps an empty list (does not break the view)', async () => {
      getProjectRuleHits.mockRejectedValue(new Error('boom'))
      const store = useAuditDetailStore()
      await store.init(1)
      expect(store.projectRuleHits).toEqual([])
    })
  })

  describe('loadReports', () => {
    it('refreshes snapshot data but leaves vulns untouched', async () => {
      getAuditSnapshot.mockResolvedValue({ data: makeSnapshot({ vulns: [{ id: 1 }] }) })
      const store = useAuditDetailStore()
      await store.init(1)
      expect(store.vulns).toHaveLength(1)
      getAuditSnapshot.mockResolvedValue({ data: makeSnapshot({ vulns: [{ id: 2 }, { id: 3 }, { id: 4 }] }) })
      await store.loadReports()
      expect(store.vulns).toHaveLength(1) // 未被覆盖
    })
  })

  describe('computed', () => {
    it('stageMap indexes stages by stage_num (incl. negative nums for supervisor)', async () => {
      getAuditSnapshot.mockResolvedValue({
        data: makeSnapshot({ stageOneDetail: null, vulns: [] }),
      })
      const store = useAuditDetailStore()
      await store.init(1)
      expect(store.stageMap[1].stage_name).toBe('架构')
      expect(store.stageMap[2].stage_name).toBe('注入')
    })

    it('stageOneStage prefers stage_one_detail and archStage mirrors it', async () => {
      const detail = {
        stage_num: 1, status: 'completed', artifact_path: '/x',
        findings: { architecture_info: { tech_stack: 'flask' } },
      }
      getAuditSnapshot.mockResolvedValue({ data: makeSnapshot({ stageOneDetail: detail }) })
      const store = useAuditDetailStore()
      await store.init(1)
      expect(store.stageOneStage.findings.architecture_info.tech_stack).toBe('flask')
      expect(store.archStage).toBe(store.stageOneStage)
    })

    it('stageOneStage falls back to stages[1] when no stage_one_detail', async () => {
      getAuditSnapshot.mockResolvedValue({ data: makeSnapshot({ stageOneDetail: null }) })
      const store = useAuditDetailStore()
      await store.init(1)
      expect(store.stageOneStage.stage_num).toBe(1)
    })

    it('stageOneRiskHints collects hints from stage-one findings + compressed_summary', async () => {
      const detail = {
        stage_num: 1, status: 'completed', artifact_path: '/x',
        findings: { architecture_info: {}, risk_hints: [{ title: 'SQL 注入', vuln_type: 'risk_hint' }] },
        compressed_summary: { vulnerability_hints: [{ title: 'XSS' }, { title: 'XSS' }] }, // 去重：两条 XSS 留一条
      }
      getAuditSnapshot.mockResolvedValue({ data: makeSnapshot({ stageOneDetail: detail }) })
      const store = useAuditDetailStore()
      await store.init(1)
      const titles = store.stageOneRiskHints.map(h => h.title)
      expect(titles).toEqual(expect.arrayContaining(['SQL 注入', 'XSS']))
      expect(store.stageOneRiskHints).toHaveLength(2) // 去重后
    })
  })
})

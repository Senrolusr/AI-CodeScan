// 运行时事件（M2）的中文标签与摘要工具。
// 与后端 services/audit_runtime.py 的 EVENT_TYPES 一一对应。

const EVENT_LABELS = {
  'run.queued': '任务入队',
  'run.started': '任务开始',
  'run.completed': '任务完成',
  'run.failed': '任务失败',
  'run.cancelled': '任务取消',
  'run.paused': '任务暂停',
  'run.resumed': '任务恢复',
  'phase.changed': '阶段切换',
  'stage.started': '审计阶段开始',
  'stage.completed': '审计阶段完成',
  'stage.failed': '审计阶段失败',
  'stage.skipped': '审计阶段跳过',
  'review.started': 'Supervisor 复核开始',
  'review.completed': 'Supervisor 复核完成',
  'rerun.requested': '复核请求重跑',
  'stage.reset_for_rerun': '阶段重置重跑',
  'agent.started': 'Agent 开始',
  'agent.completed': 'Agent 完成',
  'agent.failed': 'Agent 失败',
  'finding.created': '发现写入',
  'finding.filtered': '发现过滤',
  'artifact.written': '产物写入',
  'worker.timeout': 'Worker 超时',
  'worker.recovered': '任务恢复',
}

const STAGE_NAME_MAP = {
  [-1]: 'Supervisor 规划',
  [-2]: 'Supervisor 复核',
  1: 'Stage 1 架构',
  2: 'Stage 2 RCE',
  3: 'Stage 3 注入',
  4: 'Stage 4 XSS',
  5: 'Stage 5 认证会话',
  6: 'Stage 6 授权',
  7: 'Stage 7 配置依赖',
  8: 'Stage 8 文件操作',
  9: 'Stage 9 业务逻辑',
}

export const eventLabel = (type) => EVENT_LABELS[type] || type || '--'

export const stageLabel = (num) => {
  const n = Number(num)
  if (!Number.isFinite(n)) return '--'
  return STAGE_NAME_MAP[n] || `Stage ${n}`
}

// 把阶段号渲染成短标签（表格“阶段”列）。
export const eventStageText = (event) => {
  const num = event?.stage_num
  if (num === null || num === undefined || num === '') return ''
  return stageLabel(num)
}

// 根据事件类型与 payload 生成一句中文摘要。
export const eventSummary = (event) => {
  if (!event || typeof event !== 'object') return ''
  const type = event.event_type
  const p = (event.payload && typeof event.payload === 'object') ? event.payload : {}
  const stage = event.stage_num !== null && event.stage_num !== undefined && event.stage_num !== ''
    ? stageLabel(event.stage_num)
    : ''
  switch (type) {
    case 'run.queued':
      return p.mode && p.mode !== 'full' ? `已入队（${p.mode === 'rerun' ? '重跑' : p.mode}）` : '已入队等待执行'
    case 'run.started':
      return p.mode && p.mode !== 'full' ? `开始执行（${p.mode === 'rerun' ? '重跑' : p.mode}）` : '开始执行'
    case 'run.completed':
      return p.message || '审计流程已完成'
    case 'run.failed':
      return p.error_message || p.message || '任务执行失败'
    case 'run.cancelled':
      return p.reason || p.message || '任务已取消'
    case 'run.paused':
      return p.reason || '任务已暂停，可在阶段边界恢复'
    case 'run.resumed':
      return p.mode && p.mode !== 'full' ? `已恢复执行（${p.mode === 'rerun' ? '续跑' : p.mode}）` : '已恢复执行'
    case 'phase.changed': {
      const name = p.name || (p.phase ? `Phase ${p.phase}` : '')
      return name ? `进入 ${name}` : '切换到下一阶段'
    }
    case 'stage.started':
      return stage ? `${stage} 开始` : '阶段开始'
    case 'stage.completed':
      return stage ? `${stage} 完成` : '阶段完成'
    case 'stage.failed':
      return `${stage || '阶段'} 失败：${p.error_message || p.message || '未知原因'}`
    case 'review.started':
      return 'Supervisor 开始复核审计结果'
    case 'review.completed':
      return p.request_rerun ? `Supervisor 复核完成，建议重跑 ${_stageNumsText(p.rerun_stage_nums)}` : 'Supervisor 复核完成'
    case 'rerun.requested':
      return `复核请求重跑 ${_stageNumsText(p.stage_nums)}`
    case 'stage.reset_for_rerun':
      return `已重置 ${_stageNumsText(p.stage_nums)}，准备重跑`
    case 'agent.started': {
      const role = _roleLabel(p.role || p.agent_role)
      return `${role} 开始${p.attempt ? `（第 ${p.attempt} 次）` : ''}`
    }
    case 'agent.completed': {
      const role = _roleLabel(p.role || p.agent_role)
      const tok = _tokenText(p)
      return `${role} 完成${tok ? ` · ${tok}` : ''}`
    }
    case 'agent.failed':
      return `${_roleLabel(p.role || p.agent_role)} 失败：${p.error_message || p.message || '未知原因'}`
    case 'finding.created': {
      // 后端 payload：{title, severity, vuln_type, file_path, endpoint}（每条新漏洞一事件）
      const sev = p.severity ? `（${p.severity}）` : ''
      return p.title ? `发现新漏洞：${p.title}${sev}` : '写入新漏洞'
    }
    case 'finding.filtered': {
      // 后端 payload：{title, reason, file_path}（质量门过滤的候选）
      return p.title ? `过滤候选：${p.title}` : '过滤候选发现'
    }
    case 'artifact.written':
      // 后端 payload：{artifact_path, stage_num}
      return p.artifact_path || p.path
        ? `${stage || '阶段'}产物已写入`
        : '写入阶段产物'
    case 'worker.timeout':
      return `Worker 超时：${p.message || p.error_message || '任务超时'}`
    case 'worker.recovered':
      return '启动时恢复未完成任务'
    default:
      return p.message || ''
  }
}

const _stageNumsText = (nums) => {
  if (!Array.isArray(nums) || nums.length === 0) return '--'
  return nums.map(num => stageLabel(num)).join('、')
}

const _roleLabel = (role) => {
  const map = {
    architecture: '架构分析',
    supervisor_plan: 'Supervisor 规划',
    supervisor_review: 'Supervisor 复核',
    sub_agent: '子 Agent',
  }
  return (role && map[role]) ? map[role] : (role || 'Agent')
}

const _tokenText = (p) => {
  const prompt = Number(p.prompt_tokens)
  const completion = Number(p.completion_tokens)
  if (!Number.isFinite(prompt) && !Number.isFinite(completion)) return ''
  return `${Number.isFinite(prompt) ? prompt : 0} + ${Number.isFinite(completion) ? completion : 0} tokens`
}

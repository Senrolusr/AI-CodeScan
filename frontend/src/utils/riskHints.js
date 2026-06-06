export function collectRiskHints(...sources) {
  const hints = []
  for (const source of sources) {
    if (!source || typeof source !== 'object') continue
    for (const key of ['risk_hints', 'vulnerability_hints', 'vulnerabilities']) {
      const value = source[key]
      if (Array.isArray(value)) hints.push(...value)
    }
  }

  const deduped = []
  const seen = new Set()
  for (const item of hints) {
    const hint = normalizeRiskHint(item)
    if (!hint) continue
    const key = [
      hint.title,
      hint.vuln_type,
      hint.file_path,
      hint.endpoint,
      String(hint.description || '').slice(0, 120),
    ].join('|')
    if (seen.has(key)) continue
    seen.add(key)
    deduped.push(hint)
  }
  return deduped
}

function normalizeStageNums(...values) {
  const stageNums = []
  for (const value of values) {
    if (value == null) continue
    const items = Array.isArray(value) ? value : [value]
    for (const item of items) {
      const stageNum = Number(item)
      if (Number.isInteger(stageNum) && stageNum >= 2 && stageNum <= 9 && !stageNums.includes(stageNum)) {
        stageNums.push(stageNum)
      }
    }
  }
  return stageNums
}

export function normalizeRiskHint(item) {
  if (typeof item === 'string') {
    const text = item.trim()
    return text ? { title: text, vuln_type: 'risk_hint', description: text } : null
  }
  if (!item || typeof item !== 'object') return null
  const title = String(item.title || item.vuln_type || item.description || '').trim()
  const description = String(item.description || item.evidence || item.impact || '').trim()
  if (!title && !description) return null
  const stageNums = normalizeStageNums(item.stage_nums, item.suggested_stage_nums)
  return {
    ...item,
    title: title || description.slice(0, 80),
    vuln_type: String(item.vuln_type || item.type || 'risk_hint').trim(),
    description,
    ...(stageNums.length ? { stage_nums: stageNums, suggested_stage_nums: stageNums } : {}),
  }
}

export function riskHintMeta(hint) {
  const parts = []
  if (hint.file_path) parts.push(hint.file_path)
  if (hint.endpoint) parts.push(hint.endpoint)
  const stageNums = normalizeStageNums(hint.stage_nums, hint.suggested_stage_nums)
  if (stageNums.length) {
    parts.push(`Stage ${stageNums.join(', ')}`)
  }
  return parts.join(' | ')
}

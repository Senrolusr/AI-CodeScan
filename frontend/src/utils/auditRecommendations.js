import { normalizeSeverity } from '../i18n'

const DEFAULT_SEVERITY_STATS = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 }

const TEXT = {
  criticalOrHigh: {
    zh: '优先复核新增的严重和高危问题，先处理可直接形成利用链的入口点。',
    en: 'Review newly found critical and high-risk issues first, especially entry points that can directly form an exploit chain.',
  },
  compactedFiles: {
    zh: '本轮存在大文件补偿切片，建议对相关大文件做人工抽查，避免关键信息落在切片边界之外。',
    en: 'Large-file compensation slices were used in this round. Manually spot-check those files to avoid missing critical context at chunk boundaries.',
  },
  truncatedFiles: {
    zh: '存在审计文件数、代码块或总代码截断，建议针对核心入口文件单独精扫，降低上下文截断带来的漏报风险。',
    en: 'Audit files, code chunks, or total code context were truncated. Run targeted scans on core entry files to reduce the risk of misses caused by context limits.',
  },
  denseRuleHits: {
    zh: '规则命中数明显高于入库漏洞数，建议把规则命中最集中的目录作为下一轮定向审计范围。',
    en: 'Rule hits are much higher than recorded vulnerabilities. Use the most frequently hit directories as the focus for the next targeted audit.',
  },
  stableCoverage: {
    zh: '当前扫描覆盖和结果结构较稳定，下一轮可优先关注新增代码区域和新增高危问题。',
    en: 'Coverage and result structure look stable. Prioritize newly changed code areas and new high-risk issues in the next round.',
  },
  noCache: {
    zh: '当前项目还没有可用缓存，建议先重建缓存，再启动首轮审计。',
    en: 'No usable cache is available for this project. Rebuild the cache before starting the first audit round.',
  },
  partialCache: {
    zh: '当前缓存对应的是部分审计结果，建议重建缓存后再发起正式复扫，避免范围不完整。',
    en: 'The current cache only reflects a partial audit result. Rebuild it before starting a formal rescan to avoid incomplete coverage.',
  },
  cacheCompactedFiles: {
    zh: '缓存中存在大文件补偿切片，建议对核心大文件人工抽查，并在重要改动后重新构建缓存。',
    en: 'The cache contains large-file compensation slices. Manually review key large files and rebuild the cache after important changes.',
  },
  cacheDenseRuleHits: {
    zh: '规则命中较多，建议在发起审计前优先确认高命中目录是否为本次重点范围。',
    en: 'There are many rule hits. Before launching the audit, confirm whether high-hit directories are part of the intended focus.',
  },
  cacheMissingVersion: {
    zh: '当前缓存缺少版本标记，建议执行一次重建缓存，确保后续审计结果可追踪。',
    en: 'The cache is missing a version marker. Rebuild it once so later audit results remain traceable.',
  },
  cacheReady: {
    zh: '当前缓存状态可直接用于发起下一轮审计，优先关注最近有改动的目录即可。',
    en: 'The current cache is ready for the next audit round. Focus first on directories with recent changes.',
  },
}

function resolveText(locale = 'zh', key) {
  return TEXT[key]?.[locale === 'en' ? 'en' : 'zh'] || key
}

export function buildSeverityStats(vulns = []) {
  const stats = { ...DEFAULT_SEVERITY_STATS }
  for (const vuln of vulns || []) {
    const key = normalizeSeverity(vuln?.severity)
    if (key) stats[key] += 1
  }
  return stats
}

export function buildTaskRescanRecommendations({ vulns = [], scanStats = {}, locale = 'zh' } = {}) {
  const recommendations = []
  const severityStats = buildSeverityStats(vulns)

  if (severityStats.Critical || severityStats.High) {
    recommendations.push(resolveText(locale, 'criticalOrHigh'))
  }
  if (scanStats.oversized_files_compacted) {
    recommendations.push(resolveText(locale, 'compactedFiles'))
  }
  if (
    scanStats.truncated_by_audit_file_count
    || scanStats.truncated_by_code_chunks
    || scanStats.truncated_by_total_chars
  ) {
    recommendations.push(resolveText(locale, 'truncatedFiles'))
  }
  if ((scanStats.rule_hit_count || 0) >= Math.max((vulns?.length || 0) * 2, 20)) {
    recommendations.push(resolveText(locale, 'denseRuleHits'))
  }
  if (!recommendations.length) {
    recommendations.push(resolveText(locale, 'stableCoverage'))
  }

  return recommendations.slice(0, 5)
}

export function buildProjectCacheRecommendations({ cacheSummary = {}, cacheScanStats = {}, locale = 'zh' } = {}) {
  const recommendations = []

  if (!cacheSummary.available) {
    recommendations.push(resolveText(locale, 'noCache'))
  }
  if (
    cacheScanStats.partial_audit
    || cacheScanStats.truncated_by_audit_file_count
    || cacheScanStats.truncated_by_code_chunks
    || cacheScanStats.truncated_by_total_chars
  ) {
    recommendations.push(resolveText(locale, 'partialCache'))
  }
  if (cacheScanStats.oversized_files_compacted) {
    recommendations.push(resolveText(locale, 'cacheCompactedFiles'))
  }
  if ((cacheSummary.rule_hit_count || cacheScanStats.rule_hit_count || 0) >= 20) {
    recommendations.push(resolveText(locale, 'cacheDenseRuleHits'))
  }
  if (!cacheSummary.cache_schema_version) {
    recommendations.push(resolveText(locale, 'cacheMissingVersion'))
  }
  if (!recommendations.length) {
    recommendations.push(resolveText(locale, 'cacheReady'))
  }

  return recommendations.slice(0, 4)
}

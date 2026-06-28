export const DEFAULT_SCAN_STATS = {
  source_files_detected: 0,
  source_files_indexed: 0,
  oversized_files_skipped: 0,
  oversized_files_compacted: 0,
  files_selected_for_audit: 0,
  files_skipped_by_audit_file_budget: 0,
  files_considered_for_chunks: 0,
  files_with_content: 0,
  chunk_count: 0,
  rule_hit_count: 0,
  truncated_by_audit_file_count: false,
  truncated_by_code_chunks: false,
  truncated_by_total_chars: false,
  route_count: 0,
  route_source_files: 0,
  partial_audit: false,
}

export function isPartialScan(stats = {}) {
  return Boolean(
    stats.partial_audit
    || stats.truncated_by_audit_file_count
    || stats.truncated_by_code_chunks
    || stats.truncated_by_total_chars
    || stats.oversized_files_compacted
  )
}

export function normalizeScanStats(value, { routeCountFallback = 0, ruleHitFallback = 0 } = {}) {
  const source = value && typeof value === 'object' ? value : {}
  const normalized = {
    ...DEFAULT_SCAN_STATS,
    ...source,
  }

  normalized.source_files_indexed = normalized.source_files_indexed || normalized.source_files_detected || 0
  normalized.files_selected_for_audit = normalized.files_selected_for_audit || normalized.files_considered_for_chunks || 0
  normalized.route_count = normalized.route_count || routeCountFallback || 0
  normalized.rule_hit_count = normalized.rule_hit_count || ruleHitFallback || 0
  normalized.partial_audit = isPartialScan(normalized)

  return normalized
}

/**
 * 阶段一（架构识别 + 覆盖）派生的纯函数集合。
 *
 * 三处消费方各自重复了同一组阶段一派生公式：
 * - ``useAuditDerived`` composable（读 auditDetail store，喂 AuditDetail 视图）
 * - ``StageOneDetail`` 视图（独立页，直拉阶段一详情，本地 refs）
 * - ``StageTimeline`` 组件（routeCount 用于架构阶段摘要文案）
 *
 * 数据源不同（store refs vs 本地 refs vs 单 stage 入参），但**公式必须一致**
 * （覆盖比 / 路由数 / gap 摘要）。把公式收敛到此单一真相，避免改一处漏一处
 * （曾因 coverage 比公式逐字重复，修 bug 仍残留在另一处）。所有函数纯输入纯输出，
 * 可脱离 Vue/Pinia 直接单测（见 stageOne.spec.js）。
 */

// 覆盖对象：stage.compressed_summary.coverage；缺省 / 非对象 → {}。
export function deriveCoverage(stage) {
  const coverage = stage?.compressed_summary?.coverage
  return coverage && typeof coverage === 'object' ? coverage : {}
}

// 覆盖比：scanned / total。total 优先 audit_scope_chunk_count、回退 total_chunk_count；
// 除数钳到 ≥1，避免 0/0 → NaN。
export function coverageRatioOf(coverage) {
  const total = Number(coverage.audit_scope_chunk_count || coverage.total_chunk_count || 0)
  const scanned = Number(coverage.scanned_chunk_count || 0)
  return scanned / Math.max(total || 1, 1)
}

// 覆盖说明：优先 audit_scope_note，缺省回退调用方给的 fallback（通常是 i18n key）。
export function coverageNoteOf(coverage, fallback) {
  return coverage.audit_scope_note || fallback
}

// 静态路由清单：architecture_info.routes 数组；非数组 / 缺省 → []。
export function routesOf(stage) {
  const routes = stage?.findings?.architecture_info?.routes
  return Array.isArray(routes) ? routes : []
}

// 路由数：优先显式 ``_route_count``，否则数 routes.length；无 architecture_info → 0。
export function routeCountOf(stage) {
  const arch = stage?.findings?.architecture_info
  if (!arch || typeof arch !== 'object') return 0
  if (Number.isFinite(Number(arch._route_count))) return Number(arch._route_count)
  return Array.isArray(arch.routes) ? arch.routes.length : 0
}

// route gap 摘要：artifact.payload.route_gap_summary；缺省 / 非对象 → 零值。
// 默认含 missing_route_samples（StageOneDetail 专页表格需要；其余消费方忽略即可）。
// 每次返回**全新字面量**（含新 []），避免多次取默认值时 missing_route_samples 共享同一数组被互相污染。
export function routeGapSummaryOf(artifact) {
  const gap = artifact?.payload?.route_gap_summary
  if (gap && typeof gap === 'object') return gap
  return {
    static_route_count: 0,
    confirmed_route_count: 0,
    missing_route_count: 0,
    missing_route_samples: [],
  }
}

import { describe, it, expect } from 'vitest'
import {
  deriveCoverage,
  coverageRatioOf,
  coverageNoteOf,
  routesOf,
  routeCountOf,
  routeGapSummaryOf,
} from './stageOne'

// 阶段一派生纯函数：锁定被三处消费方（useAuditDerived / StageOneDetail / StageTimeline）
// 共用的公式，防止改一处漏一处。无 Vue/Pinia，直接喂原始对象断言。

describe('utils/stageOne — 阶段一派生纯函数', () => {
  describe('deriveCoverage', () => {
    it('取 compressed_summary.coverage 对象', () => {
      const stage = { compressed_summary: { coverage: { scanned_chunk_count: 3 } } }
      expect(deriveCoverage(stage)).toEqual({ scanned_chunk_count: 3 })
    })
    it('缺省 / 非对象 → {}', () => {
      expect(deriveCoverage(null)).toEqual({})
      expect(deriveCoverage({})).toEqual({})
      expect(deriveCoverage({ compressed_summary: { coverage: null } })).toEqual({})
      expect(deriveCoverage({ compressed_summary: { coverage: 'x' } })).toEqual({}) // 非对象回退
    })
  })

  describe('coverageRatioOf', () => {
    it('scanned / total（audit_scope_chunk_count 优先）', () => {
      expect(coverageRatioOf({ audit_scope_chunk_count: 10, scanned_chunk_count: 5 })).toBeCloseTo(0.5)
    })
    it('回退 total_chunk_count', () => {
      expect(coverageRatioOf({ total_chunk_count: 4, scanned_chunk_count: 2 })).toBeCloseTo(0.5)
    })
    it('total 为 0 时不除零（除数钳到 1）', () => {
      expect(coverageRatioOf({ scanned_chunk_count: 0 })).toBe(0)
      expect(Number.isNaN(coverageRatioOf({}))).toBe(false)
    })
  })

  describe('coverageNoteOf', () => {
    it('优先 audit_scope_note', () => {
      expect(coverageNoteOf({ audit_scope_note: '自定义说明' }, 'fallback')).toBe('自定义说明')
    })
    it('缺省回退 fallback', () => {
      expect(coverageNoteOf({}, 'auditScopeCoverageNote')).toBe('auditScopeCoverageNote')
      expect(coverageNoteOf({ audit_scope_note: '' }, 'fb')).toBe('fb')
    })
  })

  describe('routesOf / routeCountOf', () => {
    const stage = (arch) => ({ findings: { architecture_info: arch } })
    it('routesOf 返回数组 / 缺省 []', () => {
      expect(routesOf(stage({ routes: [{ path: '/a' }, { path: '/b' }] }))).toHaveLength(2)
      expect(routesOf(stage({ routes: 'nope' }))).toEqual([])
      expect(routesOf(stage({}))).toEqual([])
      expect(routesOf(null)).toEqual([])
    })
    it('routeCountOf 优先 _route_count', () => {
      expect(routeCountOf(stage({ _route_count: 7, routes: [{}, {}] }))).toBe(7)
    })
    it('routeCountOf 无 _route_count 则数 routes.length', () => {
      expect(routeCountOf(stage({ routes: [{}, {}, {}] }))).toBe(3)
    })
    it('routeCountOf 无 architecture_info / 非对象 → 0', () => {
      expect(routeCountOf(null)).toBe(0)
      expect(routeCountOf({})).toBe(0)
      expect(routeCountOf(stage(null))).toBe(0)
    })
  })

  describe('routeGapSummaryOf', () => {
    it('取 artifact.payload.route_gap_summary', () => {
      const artifact = { payload: { route_gap_summary: { static_route_count: 5, missing_route_count: 2 } } }
      expect(routeGapSummaryOf(artifact)).toMatchObject({ static_route_count: 5, missing_route_count: 2 })
    })
    it('缺省 / 非对象 → 零值（含 missing_route_samples）', () => {
      const fallback = routeGapSummaryOf(null)
      expect(fallback).toEqual({
        static_route_count: 0,
        confirmed_route_count: 0,
        missing_route_count: 0,
        missing_route_samples: [],
      })
      expect(routeGapSummaryOf({ payload: { route_gap_summary: 'x' } })).toEqual(fallback)
    })
    it('默认值是独立副本（改一份不污染后续默认）', () => {
      const a = routeGapSummaryOf(null)
      a.missing_route_samples.push('x')
      expect(routeGapSummaryOf(null).missing_route_samples).toEqual([])
    })
  })
})

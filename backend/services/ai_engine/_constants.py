"""Shared tuning constants consumed across ai_engine modules (kept low to avoid import cycles)."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

STAGE1_MAX_PASSES = 5

STAGE1_BATCH_TARGET_LEN = 55000

STAGE1_MIN_PASSES = 3

STAGE1_EARLY_STOP_COVERAGE = 0.82

STAGE1_STRONG_STOP_COVERAGE = 0.94

STAGE1_PASS1_CODE_MAX_LEN = 65000

STAGE1_LATER_PASS_CODE_MAX_LEN = 52000

STAGE1_SOFT_MAX_BATCHES = 8

SECONDARY_STAGE_MAX_ROUNDS = 1

SECONDARY_STAGE_CHUNK_LIMIT = 16

ROUTE_FOLLOWUP_MAX_BATCHES = 2

ROUTE_FOLLOWUP_BATCH_SIZE = 6

STAGE_RETRY_POLICIES = {
    1: {"enabled": True, "max_vulnerabilities": 0, "code_limit": 22000, "prev_context_limit": 800, "route_limit": 20, "detail_enrichment_max_items": 0, "detail_enrichment_concurrency": 1},
    2: {"enabled": True, "max_vulnerabilities": 4, "code_limit": 18000, "prev_context_limit": 1200, "route_limit": 8, "detail_enrichment_max_items": 2, "detail_enrichment_concurrency": 1},
    3: {"enabled": True, "max_vulnerabilities": 4, "code_limit": 18000, "prev_context_limit": 1200, "route_limit": 8, "detail_enrichment_max_items": 2, "detail_enrichment_concurrency": 1},
    4: {"enabled": True, "max_vulnerabilities": 4, "code_limit": 18000, "prev_context_limit": 1200, "route_limit": 8, "detail_enrichment_max_items": 2, "detail_enrichment_concurrency": 1},
    5: {"enabled": True, "max_vulnerabilities": 3, "code_limit": 14000, "prev_context_limit": 900, "route_limit": 6, "detail_enrichment_max_items": 2, "detail_enrichment_concurrency": 1},
    6: {"enabled": True, "max_vulnerabilities": 5, "code_limit": 18000, "prev_context_limit": 1400, "route_limit": 10, "detail_enrichment_max_items": 3, "detail_enrichment_concurrency": 1},
    7: {"enabled": True, "max_vulnerabilities": 3, "code_limit": 14000, "prev_context_limit": 1000, "route_limit": 8, "detail_enrichment_max_items": 1, "detail_enrichment_concurrency": 1},
    8: {"enabled": True, "max_vulnerabilities": 3, "code_limit": 18000, "prev_context_limit": 1200, "route_limit": 8, "detail_enrichment_max_items": 2, "detail_enrichment_concurrency": 1},
    9: {"enabled": True, "max_vulnerabilities": 3, "code_limit": 18000, "prev_context_limit": 1200, "route_limit": 8, "detail_enrichment_max_items": 2, "detail_enrichment_concurrency": 1},
}

def _get_stage_retry_policy(stage_num: int) -> dict:
    base = {
        "enabled": False,
        "max_vulnerabilities": 5,
        "code_limit": 32000,
        "prev_context_limit": 2400,
        "route_limit": 16,
        "detail_enrichment_max_items": 4,
        "detail_enrichment_concurrency": 2,
    }
    return {**base, **STAGE_RETRY_POLICIES.get(stage_num, {})}

__all__ = [
    'STAGE1_MAX_PASSES',
    'STAGE1_BATCH_TARGET_LEN',
    'STAGE1_MIN_PASSES',
    'STAGE1_EARLY_STOP_COVERAGE',
    'STAGE1_STRONG_STOP_COVERAGE',
    'STAGE1_PASS1_CODE_MAX_LEN',
    'STAGE1_LATER_PASS_CODE_MAX_LEN',
    'STAGE1_SOFT_MAX_BATCHES',
    'SECONDARY_STAGE_MAX_ROUNDS',
    'SECONDARY_STAGE_CHUNK_LIMIT',
    'ROUTE_FOLLOWUP_MAX_BATCHES',
    'ROUTE_FOLLOWUP_BATCH_SIZE',
    'STAGE_RETRY_POLICIES',
    '_get_stage_retry_policy',
]

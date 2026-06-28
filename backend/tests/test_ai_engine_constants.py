"""M3 per-module tests: ai_engine._constants (shared tuning + retry-policy accessor)."""

from __future__ import annotations

from services.ai_engine._constants import (
    STAGE1_MAX_PASSES,
    STAGE1_SOFT_MAX_BATCHES,
    STAGE_RETRY_POLICIES,
    _get_stage_retry_policy,
)


def test_stage_retry_policies_cover_all_stages():
    assert set(STAGE_RETRY_POLICIES.keys()) == set(range(1, 10))
    for policy in STAGE_RETRY_POLICIES.values():
        assert policy["enabled"] is True
        assert "max_vulnerabilities" in policy


def test_get_stage_retry_policy_known_overrides_base():
    p2 = _get_stage_retry_policy(2)
    assert p2["enabled"] is True
    assert p2["max_vulnerabilities"] == 4  # overridden from base 5


def test_get_stage_retry_policy_unknown_uses_base():
    p99 = _get_stage_retry_policy(99)
    assert p99["enabled"] is False  # base default
    assert p99["max_vulnerabilities"] == 5


def test_stage1_constants_smoke():
    assert STAGE1_MAX_PASSES == 5
    assert STAGE1_SOFT_MAX_BATCHES == 8

"""M3b per-module tests: code_parser_pkg._constants (shared tables + strategy fingerprint)."""

from __future__ import annotations

from services.code_parser_pkg._constants import (
    CODE_EXTENSIONS,
    RISK_KEYWORDS,
    RULE_HIT_KEYWORDS,
    RULE_HIT_MIN_HITS,
    RULE_HIT_MIN_WEIGHTED,
    RULE_HIT_TIERS,
    RULE_LABEL_STAGE_MAP,
    SKIP_DIRS,
    _build_analysis_strategy_fingerprint,
)


def test_code_extensions_is_set_of_source_suffixes():
    assert isinstance(CODE_EXTENSIONS, set)
    assert ".py" in CODE_EXTENSIONS
    assert ".java" in CODE_EXTENSIONS
    assert ".js" in CODE_EXTENSIONS


def test_skip_dirs_is_set_of_noise_dirs():
    assert isinstance(SKIP_DIRS, set)
    assert "node_modules" in SKIP_DIRS
    assert ".git" in SKIP_DIRS


def test_rule_tables_are_dicts():
    for table in (RISK_KEYWORDS, RULE_LABEL_STAGE_MAP, RULE_HIT_KEYWORDS, RULE_HIT_MIN_HITS, RULE_HIT_TIERS, RULE_HIT_MIN_WEIGHTED):
        assert isinstance(table, dict)
    # RISK_KEYWORDS keyed by vuln family
    for fam in ("rce", "injection", "xss"):
        assert fam in RISK_KEYWORDS
    # RULE_HIT_TIERS values expose strong/medium tiers
    sample = next(iter(RULE_HIT_TIERS.values()))
    assert "strong" in sample and "medium" in sample


def test_build_analysis_strategy_fingerprint_stable():
    a = _build_analysis_strategy_fingerprint()
    b = _build_analysis_strategy_fingerprint()
    assert isinstance(a, str)
    assert a == b  # deterministic given config + tables
    assert a  # non-empty manifest

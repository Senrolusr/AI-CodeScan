"""M3 per-module tests: ai_engine.severity (pure normalization + SQL order expr)."""

from __future__ import annotations

from sqlalchemy import Column, String
from sqlalchemy.dialects import sqlite

from services.ai_engine.severity import (
    CONFIDENCE_RANK,
    SEVERITY_ALIASES,
    VALID_SEVERITIES,
    _normalize_confidence,
    _normalize_severity,
    _severity_match_values,
    _severity_order_expr,
    _severity_rank,
)


def test_normalize_severity_empty_and_exact():
    assert _normalize_severity("") == "Medium"
    assert _normalize_severity(None) == "Medium"  # type: ignore[arg-type]
    assert _normalize_severity("High") == "High"
    assert _normalize_severity("Critical") == "Critical"


def test_normalize_severity_aliases_en_zh():
    assert _normalize_severity("critical") == "Critical"
    assert _normalize_severity("严重") == "Critical"
    assert _normalize_severity("高危") == "High"
    assert _normalize_severity("高") == "High"
    assert _normalize_severity("信息") == "Info"
    assert _normalize_severity("informational") == "Info"


def test_normalize_severity_unknown_falls_back_medium():
    assert _normalize_severity("bogus") == "Medium"


def test_severity_match_values_includes_normalized_and_aliases():
    vals = _severity_match_values("critical")
    assert "Critical" in vals
    assert "critical" in vals
    assert "严重" in vals
    # High aliases do not leak in
    assert "High" not in vals


def test_severity_order_expr_compiles_with_case():
    col = Column("severity", String)
    expr = _severity_order_expr(col)
    sql = str(expr.compile(dialect=sqlite.dialect(), compile_kwargs={"literal_binds": True}))
    assert "CASE" in sql.upper()
    # each severity bucket appears
    assert "Critical" in sql and "High" in sql and "Medium" in sql


def test_normalize_confidence():
    assert _normalize_confidence(None) == "medium"
    assert _normalize_confidence("high") == "high"
    assert _normalize_confidence("HIGH") == "high"  # case-insensitive
    assert _normalize_confidence("low") == "low"
    assert _normalize_confidence("garbage") == "medium"


def test_severity_rank():
    assert _severity_rank("Critical") == 5
    assert _severity_rank("High") == 4
    assert _severity_rank("Medium") == 3
    assert _severity_rank("") == 0
    assert _severity_rank("weird") == 0


def test_module_constants():
    assert VALID_SEVERITIES == {"Critical", "High", "Medium", "Low", "Info"}
    assert CONFIDENCE_RANK["high"] == 3
    assert SEVERITY_ALIASES["critical"] == "Critical"

"""M3 per-module tests: ai_engine.findings (coerce, risk hints, severity stats)."""

from __future__ import annotations

from types import SimpleNamespace

from services.ai_engine.findings import (
    STAGE1_RISK_HINT_LIMIT,
    _build_task_severity_stats,
    _coerce_stage_findings,
    _collect_stage1_risk_hints,
    _normalize_stage1_risk_hint,
    _stage1_response_with_risk_hints,
)


def test_coerce_stage_findings():
    d = {"a": 1}
    assert _coerce_stage_findings(d) is d
    assert _coerce_stage_findings([1, 2]) == {"vulnerabilities": [1, 2]}
    assert _coerce_stage_findings(None) == {}


def test_collect_stage1_risk_hints_from_various_keys():
    out = _collect_stage1_risk_hints({"risk_hints": ["一条线索"], "vulnerability_hints": [{"title": "x"}]})
    titles = [h["title"] for h in out]
    assert "一条线索" in titles
    assert "x" in titles


def test_collect_stage1_risk_hints_from_list_and_empty():
    assert len(_collect_stage1_risk_hints(["a", "b"])) == 2
    assert _collect_stage1_risk_hints(None) == []


def test_normalize_stage1_risk_hint_string():
    hint = _normalize_stage1_risk_hint("可能的越权")
    assert hint["title"] == "可能的越权"
    assert hint["source"] == "stage1_architecture"
    assert hint["validation_status"] == "unverified"
    assert hint["is_formal_vulnerability"] is False


def test_normalize_stage1_risk_hint_dict_normalizes_severity():
    hint = _normalize_stage1_risk_hint({"title": "SQLi", "severity": "critical"})
    assert hint["severity"] == "Critical"
    assert hint["confidence"] in {"high", "medium", "low"}


def test_stage1_response_with_risk_hints_resets_vulns():
    out = _stage1_response_with_risk_hints({"risk_hints": ["x"], "vulnerabilities": [{"title": "should-drop"}]})
    assert out["vulnerabilities"] == []
    assert any(h["title"] == "x" for h in out["risk_hints"])


def test_build_task_severity_stats():
    vulns = [SimpleNamespace(severity="Critical"), SimpleNamespace(severity="High"), SimpleNamespace(severity="High"), SimpleNamespace(severity="Bogus")]
    stats = _build_task_severity_stats(vulns)
    assert stats["Critical"] == 1
    assert stats["High"] == 2
    assert stats["Medium"] == 0


def test_stage1_risk_hint_limit_constant():
    assert STAGE1_RISK_HINT_LIMIT == 40

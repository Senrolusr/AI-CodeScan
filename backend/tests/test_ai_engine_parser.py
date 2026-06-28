"""M3 per-module tests: ai_engine.parser (parse, salvage, merge reducers)."""

from __future__ import annotations

from services.ai_engine.parser import (
    _coerce_incomplete_stage_response,
    _coerce_stage_summary,
    _extract_best_json_candidate,
    _merge_architecture_info,
    _merge_compact_stage_summary,
    _merge_stage_vulnerability_response,
    _normalize_llm_json_text,
    _parse_structured_response,
    _response_meta_indicates_truncation,
    _salvage_partial_structured_response,
    _score_stage_response,
)


# ── text normalization ──
def test_normalize_llm_json_text_strips_fence_and_curly_quotes():
    fenced = "```json\n{\"a\":1}\n```"
    assert _normalize_llm_json_text(fenced) == '{"a":1}'
    assert _normalize_llm_json_text("﻿“x”") == '"x"'
    assert _normalize_llm_json_text("  plain  ") == "plain"


def test_extract_best_json_candidate_from_prose():
    text = 'Here is the result: {"stage_summary": "ok", "n": 2} trailing'
    assert '"stage_summary"' in _extract_best_json_candidate(text)
    assert _extract_best_json_candidate("no json here") == ""


# ── truncation meta ──
def test_response_meta_indicates_truncation():
    assert _response_meta_indicates_truncation({"finish_reason": "length"}) is True
    assert _response_meta_indicates_truncation({"finish_reason": "max_tokens"}) is True
    assert _response_meta_indicates_truncation({"response_status": "incomplete"}) is True
    assert _response_meta_indicates_truncation({"finish_reason": "stop"}) is False
    assert _response_meta_indicates_truncation(None) is False


# ── structured parse: clean / fenced / garbage / truncated ──
def test_parse_structured_response_clean():
    out = _parse_structured_response('{"stage_summary":"x","vulnerabilities":[]}')
    assert isinstance(out, dict)
    assert out["stage_summary"] == "x"


def test_parse_structured_response_fenced():
    out = _parse_structured_response('```json\n{"a": 1}\n```')
    assert out == {"a": 1}


def test_parse_structured_response_garbage():
    out = _parse_structured_response("not json at all")
    assert out.get("parse_error")
    assert out["vulnerabilities"] == []


def test_parse_structured_response_truncated_salvages_vuln():
    raw = '{"stage_summary":"x","vulnerabilities":[{"title":"A","severity":"High"},{"title":"B"'
    out = _parse_structured_response(raw)
    assert isinstance(out, dict)
    titles = [v.get("title") for v in out.get("vulnerabilities", []) if isinstance(v, dict)]
    assert "A" in titles


def test_parse_structured_response_truncation_meta_annotates():
    raw = '{"stage_summary":"x"}'
    out = _parse_structured_response(raw, meta={"finish_reason": "length"})
    assert out.get("response_incomplete") is True


# ── scoring ──
def test_score_stage_response_list():
    assert _score_stage_response([1, 2, 3]) == 13  # 10 + len


def test_score_stage_response_clean_dict_beats_parse_error():
    clean = {"vulnerabilities": [{"poc_raw": "x"}]}
    broken = {"parse_error": "bad", "vulnerabilities": []}
    assert _score_stage_response(clean) > _score_stage_response(broken)


# ── coerce stage summary ──
def test_coerce_stage_summary_empty_returns_default():
    out = _coerce_stage_summary(None)
    assert out["stage_summary"] == ""
    assert "coverage" in out
    assert out["coverage"]["passes_completed"] == 0


def test_coerce_stage_summary_dict_passthrough():
    d = {"stage_summary": "hi", "extra": 1}
    assert _coerce_stage_summary(d) is d


# ── merges ──
def test_merge_compact_stage_summary_dedup_and_truncate():
    assert _merge_compact_stage_summary("same", "same", 100) == "same"
    long_a = "a" * 90
    merged = _merge_compact_stage_summary(long_a, "bbb", 100)
    assert len(merged) <= 100


def test_merge_architecture_info_singular_and_list():
    base = {"tech_stack": "py"}
    inc = {"tech_stack": "ignored", "framework": "fastapi", "routes": [{"path": "/a"}]}
    merged = _merge_architecture_info(base, inc)
    assert merged["tech_stack"] == "py"  # existing wins for singular
    assert merged["framework"] == "fastapi"
    assert merged["routes"] == [{"path": "/a"}]


def test_merge_stage_vulnerability_response_dedup():
    base = {"stage_summary": "", "architecture_info": {}, "vulnerabilities": [{"title": "A", "file_path": "a.py", "line_start": 1}]}
    inc = {"vulnerabilities": [{"title": "A", "file_path": "a.py", "line_start": 1}, {"title": "B", "file_path": "b.py", "line_start": 2}]}
    merged = _merge_stage_vulnerability_response(base, inc)
    titles = sorted(v["title"] for v in merged["vulnerabilities"])
    assert titles == ["A", "B"]


# ── coerce incomplete ──
def test_coerce_incomplete_stage_response_caps_vulns():
    resp = {
        "parse_error": "bad",
        "vulnerabilities": [{"title": f"v{i}"} for i in range(20)],
    }
    out, changed = _coerce_incomplete_stage_response(stage_num=2, response=resp, retry_policy={"max_vulnerabilities": 3})
    assert changed is True
    assert out["_recovered_from_incomplete_response"] is True
    assert len(out["vulnerabilities"]) == 3
    assert out["stage_summary"]  # fallback summary present


def test_coerce_incomplete_stage_response_clean_passthrough():
    resp = {"stage_summary": "ok", "vulnerabilities": []}
    out, changed = _coerce_incomplete_stage_response(stage_num=2, response=resp)
    assert changed is False
    assert out is resp


# ── salvage direct ──
def test_salvage_partial_returns_none_when_empty():
    assert _salvage_partial_structured_response("nothing useful", "nothing useful") is None

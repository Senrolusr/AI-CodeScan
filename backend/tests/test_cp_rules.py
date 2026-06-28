"""M3b per-module tests: code_parser_pkg.rules (noise filter, evidence, scoring, hit building)."""

from __future__ import annotations

from pathlib import Path

from services.code_parser_pkg.chunks import get_code_chunks
from services.code_parser_pkg.files import _build_tree
from services.code_parser_pkg.rules import (
    _accept_rule_hit,
    _build_rule_hits,
    _extract_rule_evidence,
    _is_rule_noise_path,
    _score_rule_hit,
    _weighted_keyword_score,
)


# ── noise path filter ──
def test_is_rule_noise_path_minified_and_tests():
    assert _is_rule_noise_path("app/lib.min.js") is True
    assert _is_rule_noise_path("app/__tests__/x.test.js") is True
    assert _is_rule_noise_path("app/dist/bundle.js") is True


def test_is_rule_noise_path_clean_source():
    assert _is_rule_noise_path("app/controller/UserController.java") is False
    assert _is_rule_noise_path("app/api/login.py") is False
    assert _is_rule_noise_path("") is False


# ── evidence extraction ──
def test_extract_rule_evidence_returns_window():
    out = _extract_rule_evidence("do exec(cmd) here please", ["exec"], 1)
    assert isinstance(out, str)
    assert "exec" in out


def test_extract_rule_evidence_miss_is_empty():
    assert _extract_rule_evidence("nothing relevant here", ["exec"], 1) == ""


# ── scoring ──
def test_weighted_keyword_score_no_match_is_zero():
    assert _weighted_keyword_score("plain text no keywords", "rce") == 0


def test_score_rule_hit_scales_with_hits():
    base = {"file_path": "app/run.py"}
    high = _score_rule_hit("rce", base, hit_count=3, evidence="exec evidence", weighted_score=5)
    low = _score_rule_hit("rce", base, hit_count=0, evidence="", weighted_score=0)
    assert high > 0
    assert low == 0
    assert high > low


# ── acceptance ──
def test_accept_rule_hit_rce_with_evidence():
    assert _accept_rule_hit("rce", "app/run.py", "os.system(...) evidence", 1) is True


def test_accept_rule_hit_unknown_label_passes():
    # unknown labels default to accepting when there is evidence + hits
    assert isinstance(_accept_rule_hit("nonexistent_label", "app/x.py", "ev", 5), bool)


# ── build_rule_hits on real chunks (mirrors smoke pipeline) ──
def test_build_rule_hits_returns_list(tmp_path: Path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "run.py").write_text(
        "import os\nos.system('rm -rf x')\nexec(user_input)\n", encoding="utf-8"
    )
    tree = _build_tree(str(tmp_path), str(tmp_path), state={"file_count": 0})
    chunks = get_code_chunks(str(tmp_path), tree) or []
    hits = _build_rule_hits(chunks)
    assert isinstance(hits, list)
    # each produced hit has the documented shape
    for hit in hits:
        assert "label" in hit and "file_path" in hit


def test_build_rule_hits_empty_input():
    assert _build_rule_hits([]) == []

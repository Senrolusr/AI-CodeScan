"""M3 per-module tests: ai_engine._utils (generic helpers + project source read)."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

from services.ai_engine._utils import (
    _SOURCE_TEXT_CACHE,
    _incremental_submit_stage_nums,
    _merge_unique_items,
    _normalize_match_path,
    _normalize_stage_num_list,
    _read_project_source_text,
    _resolve_project_source_path,
    _safe_positive_int,
    _summarize_pre_discovery,
    _truncate_text,
)


def test_normalize_stage_num_list_filters_range_and_dedups():
    assert _normalize_stage_num_list(2, [3, 4], None, 1, 10, "5") == [2, 3, 4, 5]
    assert _normalize_stage_num_list() == []


def test_normalize_match_path():
    assert _normalize_match_path("A\\B/C/") == "a/b/c"
    assert _normalize_match_path(None) == ""  # type: ignore[arg-type]
    assert _normalize_match_path("/X/Y/") == "x/y"


def test_safe_positive_int():
    assert _safe_positive_int("5") == 5
    assert _safe_positive_int("garbage", 7) == 7
    assert _safe_positive_int(None, 9) == 9  # type: ignore[arg-type]
    assert _safe_positive_int(-3) == 0
    assert _safe_positive_int(0) == 0


def test_merge_unique_items_dict_and_scalar():
    out = _merge_unique_items([{"a": 1}], [{"a": 1}, {"b": 2}])
    assert out == [{"a": 1}, {"b": 2}]
    assert _merge_unique_items([1, 2], [2, 3, ""]) == [1, 2, 3]


def test_truncate_text():
    short = "abc"
    assert _truncate_text(short, 10) == short
    long = "x" * 200
    out = _truncate_text(long, 50)
    assert out.endswith("\n... (truncated)\n")
    assert len(out) <= 50 + len("\n... (truncated)\n")


def test_summarize_pre_discovery_none():
    assert _summarize_pre_discovery(None) is None
    assert _summarize_pre_discovery({}) is None


def test_summarize_pre_discovery_truncates_lists():
    pd = {
        "tech_profile": {"frameworks": ["a", "b", "c"]},
        "dir_structure": {"pattern": "mvc", "noise": "x"},
        "security_files": {"total_critical_count": "3", "must_cover_files": list(range(100))},
        "middleware_map": {"middleware_chain": list(range(50))},
    }
    s = _summarize_pre_discovery(pd)
    assert s is not None
    assert s["tech_profile"]["frameworks"] == ["a", "b", "c"]
    assert s["dir_structure"]["pattern"] == "mvc"
    assert "noise" not in s["dir_structure"]
    assert s["security_files"]["total_critical_count"] == 3
    assert len(s["security_files"]["must_cover_files"]) == 60
    assert len(s["middleware_map"]["middleware_chain"]) == 30


def test_incremental_submit_stage_nums_returns_set():
    assert isinstance(_incremental_submit_stage_nums(), set)


def test_resolve_and_read_project_source(tmp_path: Path):
    # build a fake project root with one source file
    (tmp_path / "app").mkdir()
    src = tmp_path / "app" / "api.py"
    src.write_text("print('hi')\n", encoding="utf-8")

    project = SimpleNamespace(id=987654321, upload_path=str(tmp_path))
    rel = "app/api.py"

    resolved = _resolve_project_source_path(project, rel)
    assert resolved
    assert os.path.isfile(resolved)
    assert resolved.endswith(os.path.join("app", "api.py"))

    # reading caches by (id, normalized path)
    _SOURCE_TEXT_CACHE.pop((987654321, _normalize_match_path(rel)), None)
    text = _read_project_source_text(project, rel)
    assert "print('hi')" in text

    # missing file resolves to empty and caches empty
    assert _resolve_project_source_path(project, "nope/missing.py") == ""

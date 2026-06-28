"""M3b per-module tests: code_parser_pkg.chunks (file selection, splitting, chunk build/risk, oversized)."""

from __future__ import annotations

from pathlib import Path

from services.code_parser_pkg.chunks import (
    _build_chunk,
    _build_oversized_file_chunks,
    _compute_chunk_risk,
    _select_audit_source_files,
    _split_file,
    get_code_chunks,
)
from services.code_parser_pkg.files import _build_tree


# ── chunk construction ──
def test_build_chunk_shape():
    chunk = _build_chunk("app/run.py", "x = 1")
    assert {"file_path", "base_file_path", "chunk_type", "content", "risk_score", "risk_labels"} <= set(
        chunk.keys()
    )
    assert chunk["file_path"] == "app/run.py"
    assert chunk["chunk_type"] == "full"


def test_compute_chunk_risk_scales_with_content():
    risky = _compute_chunk_risk("a.py", "os.system(cmd)\nexec(user)")
    clean = _compute_chunk_risk("a.py", "x = 1\ny = 2")
    assert {"risk_score", "risk_labels"} <= set(risky.keys())
    assert risky["risk_score"] > clean["risk_score"]
    assert risky["risk_labels"]  # non-empty for dangerous content


def test_compute_chunk_risk_labels_rce():
    out = _compute_chunk_risk("a.py", "os.system('rm -rf x')")
    assert "rce" in out["risk_labels"]


# ── splitting ──
def test_split_file_returns_multiple_chunks_when_oversized():
    content = ("x = 1\n") * 500  # well over any small max
    chunks = _split_file("big.py", content, 100)
    assert isinstance(chunks, list)
    assert len(chunks) > 1


def test_split_file_small_content_single_or_few():
    chunks = _split_file("small.py", "x = 1\ny = 2\n", 3000)
    assert isinstance(chunks, list)
    assert len(chunks) >= 1


# ── audit source selection ──
def test_select_audit_source_files_returns_tuple():
    files = [
        {"file_path": "app/controller/UserController.java", "content": "@GetMapping x"},
        {"file_path": "app/util/Helper.java", "content": "x = 1"},
    ]
    selected, stats = _select_audit_source_files(files)
    assert isinstance(selected, list)
    assert isinstance(stats, dict)
    assert len(selected) <= len(files)


# ── oversized signal windows ──
def test_build_oversized_file_chunks_returns_list():
    out = _build_oversized_file_chunks("huge.py", "A" * 200_000)
    assert isinstance(out, list)
    assert out  # large content yields at least one signal window


# ── get_code_chunks on a real (synthetic) project ──
def test_get_code_chunks_returns_list(tmp_path: Path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "run.py").write_text(
        "import os\nos.system('rm -rf x')\nexec(user_input)\n", encoding="utf-8"
    )
    tree = _build_tree(str(tmp_path), str(tmp_path), state={"file_count": 0})
    chunks = get_code_chunks(str(tmp_path), tree)
    assert isinstance(chunks, list)
    for chunk in chunks:
        assert "file_path" in chunk and "content" in chunk

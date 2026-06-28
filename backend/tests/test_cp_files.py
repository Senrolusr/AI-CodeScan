"""M3b per-module tests: code_parser_pkg.files (file-tree, flatten, fingerprint, file role)."""

from __future__ import annotations

from pathlib import Path

from services.code_parser_pkg.files import (
    _build_project_fingerprint,
    _build_tree,
    _flatten_files,
    _infer_file_role,
    _read_source_text,
)


def _make_project(tmp_path: Path) -> Path:
    (tmp_path / "app").mkdir()
    (tmp_path / "requirements.txt").write_text("fastapi\nsqlalchemy\n", encoding="utf-8")
    (tmp_path / "app" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/users')\ndef users():\n    return []\n",
        encoding="utf-8",
    )
    (tmp_path / "app" / "auth.py").write_text("def login(user, pwd):\n    return token\n", encoding="utf-8")
    return tmp_path


def test_build_tree_returns_nested_entries(tmp_path: Path):
    _make_project(tmp_path)
    tree = _build_tree(str(tmp_path), str(tmp_path), state={"file_count": 0})
    assert isinstance(tree, list)
    assert tree, "tree should be non-empty"
    entry = tree[0]
    assert {"name", "type", "path", "children"} <= set(entry.keys())


def test_flatten_files_returns_list(tmp_path: Path):
    _make_project(tmp_path)
    tree = _build_tree(str(tmp_path), str(tmp_path), state={"file_count": 0})
    flat = _flatten_files(tree)
    assert isinstance(flat, list)
    assert len(flat) >= len(tree)  # flatten includes nested entries


def test_build_project_fingerprint_stable(tmp_path: Path):
    _make_project(tmp_path)
    tree = _build_tree(str(tmp_path), str(tmp_path), state={"file_count": 0})
    fp1 = _build_project_fingerprint(tree)
    fp2 = _build_project_fingerprint(tree)
    assert isinstance(fp1, str) and fp1
    assert fp1 == fp2  # stable hash


def test_build_project_fingerprint_changes_with_tree(tmp_path: Path):
    _make_project(tmp_path)
    tree = _build_tree(str(tmp_path), str(tmp_path), state={"file_count": 0})
    fp_before = _build_project_fingerprint(tree)
    # mutate the tree shape
    tree.append({"name": "extra.py", "type": "file", "path": "extra.py", "children": []})
    fp_after = _build_project_fingerprint(tree)
    assert fp_before != fp_after


def test_infer_file_role_returns_optional_str():
    # returns a role string or None depending on content/path heuristics
    out = _infer_file_role("app/auth.py", "def login(user, pwd):")
    assert out is None or isinstance(out, str)


def test_read_source_text_reads_file(tmp_path: Path):
    _make_project(tmp_path)
    text = _read_source_text(str(tmp_path / "app" / "auth.py"))
    assert "def login" in text


def test_read_source_text_missing_file_raises(tmp_path: Path):
    # _read_source_text does not swallow FileNotFoundError — locks actual behavior
    import pytest

    with pytest.raises(FileNotFoundError):
        _read_source_text(str(tmp_path / "does_not_exist.py"))

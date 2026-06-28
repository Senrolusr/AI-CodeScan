"""M3b per-module tests: code_parser_pkg.project (parse_project + filesystem cache round-trip).

Cache is keyed by an integer project_id and persisted under CACHE_ROOT. Tests use a
high, collision-unlikely id and clear before+after to stay isolated.
"""

from __future__ import annotations

from pathlib import Path

from services.code_parser_pkg.files import _build_tree
from services.code_parser_pkg.project import (
    _project_cache_dir,
    _project_cache_path,
    clear_project_cache,
    get_or_build_project_cache,
    load_project_cache,
    parse_project,
    warm_project_cache,
)

# collision-unlikely id; cleared around every test below
_PID = 777777


def _make_project(tmp_path: Path) -> Path:
    (tmp_path / "app").mkdir()
    (tmp_path / "requirements.txt").write_text("flask\n", encoding="utf-8")
    (tmp_path / "app" / "main.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n"
        "@app.route('/users')\ndef users(): return []\n",
        encoding="utf-8",
    )
    return tmp_path


def test_parse_project_returns_tree_and_stack(tmp_path: Path):
    _make_project(tmp_path)
    file_tree, tech_stack = parse_project(str(tmp_path))
    assert isinstance(file_tree, list) and file_tree
    assert isinstance(tech_stack, str) and tech_stack


def test_project_cache_path_shapes():
    clear_project_cache(_PID)
    d = _project_cache_dir(_PID)
    p = _project_cache_path(_PID)
    assert isinstance(d, str) and isinstance(p, str)
    assert p.startswith(d)
    clear_project_cache(_PID)


def test_warm_then_load_round_trip(tmp_path: Path):
    _make_project(tmp_path)
    tree = _build_tree(str(tmp_path), str(tmp_path), state={"file_count": 0})
    try:
        clear_project_cache(_PID)
        warmed = warm_project_cache(_PID, str(tmp_path), tree)
        assert isinstance(warmed, dict)
        loaded = load_project_cache(_PID)
        assert loaded is not None
        assert loaded.get("fingerprint") == warmed.get("fingerprint")
    finally:
        clear_project_cache(_PID)


def test_get_or_build_creates_then_reuses(tmp_path: Path):
    _make_project(tmp_path)
    tree = _build_tree(str(tmp_path), str(tmp_path), state={"file_count": 0})
    try:
        clear_project_cache(_PID)
        built = get_or_build_project_cache(_PID, str(tmp_path), tree)
        assert isinstance(built, dict)
        # second call loads the persisted cache (same fingerprint)
        reused = get_or_build_project_cache(_PID, str(tmp_path), tree)
        assert reused.get("fingerprint") == built.get("fingerprint")
    finally:
        clear_project_cache(_PID)


def test_clear_project_cache_invalidates(tmp_path: Path):
    _make_project(tmp_path)
    tree = _build_tree(str(tmp_path), str(tmp_path), state={"file_count": 0})
    warm_project_cache(_PID, str(tmp_path), tree)
    assert load_project_cache(_PID) is not None
    clear_project_cache(_PID)
    assert load_project_cache(_PID) is None


def test_load_project_cache_missing_is_none():
    clear_project_cache(_PID)
    assert load_project_cache(_PID) is None

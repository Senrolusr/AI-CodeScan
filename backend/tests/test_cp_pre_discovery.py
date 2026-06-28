"""M3b per-module tests: code_parser_pkg.pre_discovery (tech-stack, structure, imports, middleware, security)."""

from __future__ import annotations

from pathlib import Path

from services.code_parser_pkg.chunks import get_code_chunks
from services.code_parser_pkg.files import _build_tree
from services.code_parser_pkg.pre_discovery import (
    _build_import_graph,
    _build_middleware_map,
    _build_tech_stack_profile,
    _classify_directory_structure,
    _detect_tech_stack,
    _identify_security_critical_files,
    run_pre_discovery,
)


def _make_project(tmp_path: Path) -> str:
    (tmp_path / "app").mkdir()
    (tmp_path / "requirements.txt").write_text("fastapi\nsqlalchemy\n", encoding="utf-8")
    (tmp_path / "app" / "main.py").write_text(
        "from fastapi import FastAPI\nfrom app.auth import login\n"
        "app = FastAPI()\n@app.get('/users')\ndef users():\n    return []\n",
        encoding="utf-8",
    )
    (tmp_path / "app" / "auth.py").write_text(
        "def login(user, pwd):\n    return token\n", encoding="utf-8"
    )
    return str(tmp_path)


def _tree(tmp_path: Path) -> list:
    return _build_tree(str(tmp_path), str(tmp_path), state={"file_count": 0})


def test_detect_tech_stack_returns_string(tmp_path: Path):
    _make_project(tmp_path)
    stack = _detect_tech_stack(str(tmp_path), _tree(tmp_path))
    assert isinstance(stack, str)
    assert "Python" in stack or "FastAPI" in stack


def test_build_tech_stack_profile_returns_dict(tmp_path: Path):
    _make_project(tmp_path)
    profile = _build_tech_stack_profile(str(tmp_path), _tree(tmp_path))
    assert isinstance(profile, dict)


def test_classify_directory_structure_shape(tmp_path: Path):
    _make_project(tmp_path)
    out = _classify_directory_structure(_tree(tmp_path))
    assert {"pattern", "directory_roles", "detected_roles"} <= set(out.keys())


def test_build_import_graph_shape(tmp_path: Path):
    _make_project(tmp_path)
    graph = _build_import_graph(str(tmp_path), _tree(tmp_path))
    assert {"imports", "hub_scores", "file_roles"} <= set(graph.keys())


def test_build_middleware_map_returns_dict(tmp_path: Path):
    _make_project(tmp_path)
    chunks = get_code_chunks(str(tmp_path), _tree(tmp_path)) or []
    out = _build_middleware_map(str(tmp_path), _tree(tmp_path), chunks)
    assert isinstance(out, dict)


def test_identify_security_critical_files_returns_dict(tmp_path: Path):
    _make_project(tmp_path)
    tree = _tree(tmp_path)
    ig = _build_import_graph(str(tmp_path), tree)
    tp = _build_tech_stack_profile(str(tmp_path), tree)
    out = _identify_security_critical_files(str(tmp_path), tree, ig, tp)
    assert isinstance(out, dict)


def test_run_pre_discovery_returns_dict(tmp_path: Path):
    _make_project(tmp_path)
    tree = _tree(tmp_path)
    chunks = get_code_chunks(str(tmp_path), tree) or []
    out = run_pre_discovery(str(tmp_path), tree, chunks, [])
    assert isinstance(out, dict)

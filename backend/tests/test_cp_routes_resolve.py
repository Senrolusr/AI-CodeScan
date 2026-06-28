"""M3b per-module tests: code_parser_pkg.routes_resolve (prefix builders, python import resolution)."""

from __future__ import annotations

from pathlib import Path

from services.code_parser_pkg.files import _build_tree, _flatten_files
from services.code_parser_pkg.routes_resolve import (
    _build_fastapi_router_prefixes,
    _build_flask_blueprint_prefixes,
    _python_module_to_relpath,
    _resolve_python_import_target,
)


# ── prefix builders (structural — return a dict, possibly empty on synthetic input) ──
def test_build_flask_blueprint_prefixes_returns_dict(tmp_path: Path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "bp.py").write_text(
        "from flask import Blueprint\napi = Blueprint('api', __name__, url_prefix='/api/v1')\n",
        encoding="utf-8",
    )
    tree = _build_tree(str(tmp_path), str(tmp_path), state={"file_count": 0})
    out = _build_flask_blueprint_prefixes(str(tmp_path), _flatten_files(tree))
    assert isinstance(out, dict)


def test_build_fastapi_router_prefixes_returns_dict(tmp_path: Path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "fa.py").write_text(
        "from fastapi import APIRouter\nr = APIRouter(prefix='/api/v2')\n", encoding="utf-8"
    )
    tree = _build_tree(str(tmp_path), str(tmp_path), state={"file_count": 0})
    out = _build_fastapi_router_prefixes(str(tmp_path), _flatten_files(tree))
    assert isinstance(out, dict)


# ── python import → relpath resolution ──
def test_python_module_to_relpath_dotted():
    assert _python_module_to_relpath("app.auth") == "app/auth.py"
    assert _python_module_to_relpath("app.services.users") == "app/services/users.py"


def test_resolve_python_import_target_returns_py_path():
    # without existing_paths it still converts dotted module → relpath (no existence check)
    out = _resolve_python_import_target("app.auth")
    assert isinstance(out, str)
    assert out.replace("\\", "/").endswith("app/auth.py")


def test_resolve_python_import_target_deep_module():
    out = _resolve_python_import_target("some.deep.module.name")
    assert out.replace("\\", "/").endswith("some/deep/module/name.py")

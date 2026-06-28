"""M3b per-module tests: code_parser_pkg.routes (dispatch + project-level route extraction)."""

from __future__ import annotations

from pathlib import Path

from services.code_parser_pkg.files import _build_tree
from services.code_parser_pkg.routes import (
    _extract_routes_from_content,
    extract_project_routes,
)

_ROUTE_KEYS = {"method", "path", "file_path"}


# ── dispatch over multiple languages ──
def test_extract_routes_from_content_fastapi():
    content = (
        "from fastapi import APIRouter\nrouter = APIRouter()\n"
        '@router.get("/items")\ndef items(): pass\n'
    )
    out = _extract_routes_from_content("main.py", content)
    assert isinstance(out, list) and out
    assert "/items" in {r["path"] for r in out}
    for route in out:
        assert _ROUTE_KEYS <= set(route.keys())


def test_extract_routes_from_content_django():
    content = (
        "from django.urls import path\nurlpatterns = [\n"
        '  path("users", views.users),\n  path("posts/<int:pk>", views.posts),\n]\n'
    )
    out = _extract_routes_from_content("urls.py", content)
    assert isinstance(out, list) and out
    paths = {r["path"] for r in out}
    assert "/users" in paths


def test_extract_routes_from_content_flask():
    content = (
        "from flask import Flask\napp = Flask(__name__)\n"
        "@app.route('/users')\ndef users(): pass\n"
    )
    out = _extract_routes_from_content("app.py", content)
    assert isinstance(out, list) and out
    assert "/users" in {r["path"] for r in out}


def test_extract_routes_from_content_empty_returns_list():
    out = _extract_routes_from_content("readme.md", "no routes here at all")
    assert isinstance(out, list)


# ── project-level extraction over a real (synthetic) project ──
def test_extract_project_routes_returns_list(tmp_path: Path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n"
        "@app.route('/users')\ndef users(): pass\n@app.route('/posts')\ndef posts(): pass\n",
        encoding="utf-8",
    )
    tree = _build_tree(str(tmp_path), str(tmp_path), state={"file_count": 0})
    routes = extract_project_routes(str(tmp_path), tree)
    assert isinstance(routes, list)
    assert routes  # found at least one endpoint
    for route in routes:
        assert _ROUTE_KEYS <= set(route.keys())

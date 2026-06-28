"""M3b per-module tests: code_parser_pkg.routes_extract (multi-language route extractors)."""

from __future__ import annotations

from services.code_parser_pkg.routes_extract import (
    _extract_flask_routes,
    _extract_gin_routes,
    _extract_spring_routes,
)

# raw extractors return a list of route dicts with at least {method, path, file_path}
_ROUTE_KEYS = {"method", "path", "file_path"}


def _paths(out):
    return {r["path"] for r in out}


# ── Flask ──
def test_extract_flask_routes_finds_endpoints():
    content = (
        "from flask import Flask\napp = Flask(__name__)\n"
        "@app.route('/users')\ndef users(): pass\n"
        "@app.route('/exec')\ndef exec_cmd(): pass\n"
    )
    out = _extract_flask_routes("app.py", content)
    assert isinstance(out, list) and out
    assert "/users" in _paths(out)
    for route in out:
        assert _ROUTE_KEYS <= set(route.keys())


# ── Spring ──
def test_extract_spring_routes_returns_list():
    content = (
        '@RestController\n@RequestMapping("/api")\n'
        "public class C {\n  @GetMapping(\"/items\")\n  public void items() {}\n}\n"
    )
    out = _extract_spring_routes("C.java", content)
    assert isinstance(out, list) and out  # regex-driven; locks structural shape


# ── Gin (Go) ──
def test_extract_gin_routes_finds_endpoints():
    content = (
        'package main\nimport "github.com/gin-gonic/gin"\n'
        "func main() {\n  r := gin.Default()\n"
        '  r.GET("/health", h)\n  r.POST("/login", h)\n}\n'
    )
    out = _extract_gin_routes("main.go", content)
    assert isinstance(out, list) and out
    assert "/health" in _paths(out)

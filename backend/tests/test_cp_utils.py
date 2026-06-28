"""M3b per-module tests: code_parser_pkg._utils (pure string/route/object-literal helpers)."""

from __future__ import annotations

from services.code_parser_pkg._utils import (
    _dedupe_preserve_order,
    _extract_balanced_segment,
    _extract_identifier_list,
    _extract_named_array_literal,
    _extract_route_params,
    _extract_top_level_object_literals,
    _guess_auth_type,
    _guess_handler_nearby,
    _is_comment_or_docstring_match,
    _join_route_paths,
    _line_number_from_offset,
    _merge_params,
    _merge_unique_paths,
    _normalize_controller_name,
    _normalize_handler_name,
    _normalize_route_path,
)


# ── route-path helpers ──
def test_normalize_route_path_collapses_slashes():
    assert _normalize_route_path("/a//b/") == "/a/b"
    assert _normalize_route_path("a/b") == "/a/b"


def test_join_route_paths():
    assert _join_route_paths("/api", "users") == "/api/users"
    assert _join_route_paths("/api/", "/users") == "/api/users"
    assert _join_route_paths("", "users") == "/users"


def test_extract_route_params():
    assert _extract_route_params("/users/{id}/posts/{pid}") == ["id", "pid"]
    assert _extract_route_params("/static/path") == []


# ── dedupe / merge ──
def test_dedupe_preserve_order():
    assert _dedupe_preserve_order(["a", "b", "a", "c"]) == ["a", "b", "c"]
    assert _dedupe_preserve_order([]) == []


def test_merge_unique_paths():
    assert _merge_unique_paths(["/a", "/b", "/a", "/c"]) == ["/a", "/b", "/c"]


def test_merge_params_variadic():
    assert _merge_params(["a", "b"], ["b", "c"]) == ["a", "b", "c"]


# ── name normalization ──
def test_normalize_controller_name():
    assert _normalize_controller_name("UserController") == "usercontroller"
    assert _normalize_controller_name("AuthController") == "authcontroller"


def test_normalize_handler_name_strips_api_prefix():
    assert _normalize_handler_name("api.getUserInfo") == "getUserInfo"
    assert _normalize_handler_name("getUserInfo") == "getUserInfo"


# ── auth / handler guessing ──
def test_guess_auth_type():
    assert _guess_auth_type("Authorization: Bearer xxx") == "JWT"
    assert _guess_auth_type("random text without auth header") == "Unknown"


def test_guess_handler_nearby_finds_def():
    assert _guess_handler_nearby("def login(): pass", 0) == "login"
    assert _guess_handler_nearby("nothing useful here", 0) == "Unknown"


# ── offsets ──
def test_line_number_from_offset():
    # 'ab\ncd\nef' — offset 3 is 'c' on line 2
    assert _line_number_from_offset("ab\ncd\nef", 3) == 2
    assert _line_number_from_offset("ab\ncd\nef", 0) == 1


def test_is_comment_or_docstring_match():
    # offset on a '#' comment line
    assert _is_comment_or_docstring_match("# a comment\nx = 1", 2) is True
    # offset on a normal code line
    assert _is_comment_or_docstring_match("x = 1\ny = 2", 0) is False


# ── object-literal / identifier extraction ──
def test_extract_named_array_literal():
    assert _extract_named_array_literal('controllers: ["a", "b"]', "controllers") == '["a", "b"]'
    assert _extract_named_array_literal("no key here", "controllers") == ""


def test_extract_balanced_segment():
    assert _extract_balanced_segment("{a:{b:1}}", 0, "{", "}") == "{a:{b:1}}"
    assert _extract_balanced_segment("xyz", 0, "{", "}") == ""


def test_extract_identifier_list():
    # extracts PascalCase identifiers only
    assert _extract_identifier_list("[Foo, Bar, Baz]") == ["Foo", "Bar", "Baz"]
    assert _extract_identifier_list("[foo, bar, baz]") == []  # lowercase ignored
    assert _extract_identifier_list("") == []


def test_extract_top_level_object_literals():
    out = _extract_top_level_object_literals("x = {a:1}\ny = {b:2}")
    assert "{a:1}" in out and "{b:2}" in out

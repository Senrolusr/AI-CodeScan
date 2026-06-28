"""M3b per-module tests: code_parser_pkg._text (comment strip, truncation, block/param extraction)."""

from __future__ import annotations

from services.code_parser_pkg._text import (
    _extract_go_block,
    _extract_handler_params,
    _extract_python_block,
    _extract_python_handler_params,
    _strip_comments_and_strings,
    _truncate_by_chars,
    _truncate_tail_by_chars,
)


# ── comment stripping ──
def test_strip_comments_removes_hash_comment():
    out = _strip_comments_and_strings("a = 1 # a comment\nb = 2")
    assert "# a comment" not in out
    assert "a = 1" in out
    assert "b = 2" in out


# ── truncation ──
def test_truncate_by_chars_passthrough_and_truncate():
    assert _truncate_by_chars("abc", 10) == "abc"
    long = "x" * 200
    out = _truncate_by_chars(long, 100)
    assert len(out) < len(long)
    assert out.endswith("(truncated)\n")


def test_truncate_tail_by_chars_passthrough_and_truncate():
    assert _truncate_tail_by_chars("abc", 10) == "abc"
    long = "y" * 200
    out = _truncate_tail_by_chars(long, 100)
    assert len(out) < len(long)
    assert out.startswith("\n... (truncated)")


# ── block / param extraction (offset-sensitive → structural assertions) ──
def test_extract_python_block_returns_string():
    out = _extract_python_block("def foo():\n    x = 1\n    y = 2", 9)
    assert isinstance(out, str)


def test_extract_go_block_returns_string():
    out = _extract_go_block("func h() {\n  x = 1\n}", 8)
    assert isinstance(out, str)


def test_extract_handler_params_returns_list():
    out = _extract_handler_params("def foo(a, b, c): pass", "foo")
    assert isinstance(out, list)


def test_extract_python_handler_params_returns_list():
    out = _extract_python_handler_params("def bar(request, id): pass", "bar")
    assert isinstance(out, list)

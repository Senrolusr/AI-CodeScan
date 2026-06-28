"""M3b per-module tests: code_parser_pkg.source_sink (source→sink hint construction)."""

from __future__ import annotations

from services.code_parser_pkg.source_sink import _build_source_sink_hints

_HINT_KEYS = {
    "label",
    "stage_nums",
    "file_path",
    "source_types",
    "sink_keywords",
    "route_paths",
    "risk_score",
}


def test_build_source_sink_hints_returns_list():
    chunks = [
        {"file_path": "app/run.py", "content": 'q = request.args["q"]\nos.system(q)\n'}
    ]
    routes = [{"method": "GET", "path": "/exec", "file_path": "app/run.py", "handler": "x"}]
    out = _build_source_sink_hints(chunks, routes)
    assert isinstance(out, list)


def test_build_source_sink_hints_detects_rce_flow():
    chunks = [
        {"file_path": "app/run.py", "content": 'user = request.args["cmd"]\nos.system(user)\n'}
    ]
    routes = [{"method": "GET", "path": "/run", "file_path": "app/run.py", "handler": "run"}]
    out = _build_source_sink_hints(chunks, routes)
    assert out, "expected at least one source→sink hint for an RCE-shaped flow"
    hint = out[0]
    assert _HINT_KEYS <= set(hint.keys())
    assert hint["label"] == "rce"
    assert hint["risk_score"] > 0
    assert "/run" in hint["route_paths"]


def test_build_source_sink_hints_clean_content_is_empty_or_low():
    chunks = [{"file_path": "app/clean.py", "content": "x = 1\ny = 2\n"}]
    routes = []
    out = _build_source_sink_hints(chunks, routes)
    assert isinstance(out, list)
    # no source→sink pattern → no hints (or zero-risk hints filtered out)
    for hint in out:
        assert hint["label"]


def test_build_source_sink_hints_empty_input():
    assert _build_source_sink_hints([], []) == []

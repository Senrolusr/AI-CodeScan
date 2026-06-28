"""M3 per-module tests: ai_engine.prompt_budget + prompt_builders.

`_build_stage_user_prompt` suffix/budget behaviour is already locked by
``test_incremental_submit``; here we cover the budget appliers, audit memory
builders, and a prompt-builder smoke test.
"""

from __future__ import annotations

from types import SimpleNamespace

from services.ai_engine.prompt_budget import (
    _apply_exploit_stage_prompt_budget,
    _apply_lightweight_stage_prompt_budget,
    _apply_stage5_prompt_budget,
    _apply_stage6_prompt_budget,
    _apply_stage9_prompt_budget,
)
from services.ai_engine.prompt_builders import (
    _build_audit_memory,
    _build_prev_context,
    _build_stage_focus_compact_context,
    _build_stage_user_prompt,
    _incremental_submit_stage_nums,
    _select_stage_focus_routes,
)


# ── incremental submit flag ──
def test_incremental_submit_stage_nums_returns_set():
    assert isinstance(_incremental_submit_stage_nums(), set)


# ── budget appliers ──
def test_apply_exploit_stage_prompt_budget_truncates_and_sets_mode():
    long_code = "x" * 30000
    long_prev = "p" * 5000
    ctx, code, prev = _apply_exploit_stage_prompt_budget(
        {"route_lines": list(range(50)), "focus_files": list(range(50))},
        long_code,
        long_prev,
        stage_num=2,
    )
    assert ctx["response_mode"] == "index_first"
    assert len(code) < len(long_code)   # truncated to ~18000
    assert len(prev) < len(long_prev)   # truncated to ~1200
    assert len(ctx["route_lines"]) == 8
    assert len(ctx["focus_files"]) == 24
    # stage-2 guidance injected
    assert "阶段二" in ctx["extra_guidance"]


def test_apply_exploit_stage_prompt_budget_aggressive_truncates_more():
    long_code = "y" * 30000
    _, code_normal, _ = _apply_exploit_stage_prompt_budget({}, long_code, "", stage_num=3)
    _, code_aggressive, _ = _apply_exploit_stage_prompt_budget({}, long_code, "", stage_num=3, aggressive=True)
    assert len(code_aggressive) < len(code_normal)


def test_apply_stage5_prompt_budget_caps_and_guidance():
    ctx, code, prev = _apply_stage5_prompt_budget({"route_lines": list(range(50))}, "code", "prev")
    assert ctx["response_mode"] == "index_first"
    assert len(ctx["route_lines"]) == 6
    assert "阶段五" in ctx["extra_guidance"]
    # short inputs pass through unchanged
    assert code == "code"
    assert prev == "prev"


def test_apply_stage6_prompt_budget_smoke():
    ctx, _, _ = _apply_stage6_prompt_budget({}, "c", "p")
    assert "阶段六" in ctx["extra_guidance"]


def test_apply_stage9_prompt_budget_smoke():
    ctx, _, _ = _apply_stage9_prompt_budget({}, "c", "p")
    assert ctx["response_mode"] == "index_first"
    assert "阶段九" in ctx["extra_guidance"]


def test_apply_lightweight_stage_prompt_budget_stage_label():
    ctx, _, _ = _apply_lightweight_stage_prompt_budget({}, "c", "p", stage_num=7)
    assert ctx["response_mode"] == "index_first"
    assert "阶段7" in ctx["extra_guidance"]


# ── audit memory + prev context ──
def test_build_audit_memory_empty_shape():
    mem = _build_audit_memory([], current_stage_num=3)
    expected_keys = {
        "architecture_info", "audited_route_inventory", "completed_stage_count",
        "data_flows", "entry_points", "evidence_files", "modules",
        "output_points", "route_inventory", "stages", "vulnerability_hints",
    }
    assert expected_keys.issubset(mem.keys())


def test_build_prev_context_empty_is_blank():
    assert _build_prev_context({}) == ""


def test_build_audit_memory_and_prev_context_with_stage():
    stage = SimpleNamespace(
        stage_num=5,
        stage_name="Auth",
        findings={"vulnerabilities": [{"title": "A", "file_path": "a.py", "line_start": 1}]},
        compressed_summary={"_stage_coverage": {}},
        stage_summary="ok",
    )
    mem = _build_audit_memory([stage], current_stage_num=5)
    prev = _build_prev_context(mem)
    assert isinstance(prev, str)
    assert len(prev) > 0


# ── prompt builder smoke ──
def test_select_stage_focus_routes_prioritizes_forced_routes():
    routes = [
        {"method": "GET", "path": "/api/a", "handler": "a", "file_path": "a.py"},
        {"method": "POST", "path": "/api/forced", "handler": "forced", "file_path": "forced.py"},
        {"method": "GET", "path": "/api/b", "handler": "b", "file_path": "b.py"},
    ]

    selected = _select_stage_focus_routes(
        3,
        routes,
        audit_memory={},
        focus_files=[],
        forced_routes=["POST /api/forced"],
    )

    assert selected[0]["path"] == "/api/forced"


def test_select_stage_focus_routes_spreads_stage_shards():
    routes = [
        {"method": "GET", "path": f"/api/r{i:02d}", "handler": f"h{i}", "file_path": f"f{i}.py"}
        for i in range(32)
    ]

    stage2 = _select_stage_focus_routes(2, routes, audit_memory={}, focus_files=[])
    stage3 = _select_stage_focus_routes(3, routes, audit_memory={}, focus_files=[])

    assert stage2[0]["path"] == "/api/r00"
    assert stage3[0]["path"] == "/api/r01"
    assert stage2[:6] != stage3[:6]


def test_select_stage_focus_routes_inventory_does_not_override_shards():
    routes = [
        {"method": "GET", "path": f"/api/r{i:02d}", "handler": f"h{i}", "file_path": f"f{i}.py"}
        for i in range(32)
    ]
    audit_memory = {"route_inventory": list(routes)}

    stage2 = _select_stage_focus_routes(2, routes, audit_memory=audit_memory, focus_files=[])
    stage3 = _select_stage_focus_routes(3, routes, audit_memory=audit_memory, focus_files=[])

    assert stage2[0]["path"] == "/api/r00"
    assert stage3[0]["path"] == "/api/r01"


def test_build_stage_focus_context_uses_forced_route_targets():
    stage = SimpleNamespace(stage_num=6, stage_name="Authz")
    project = SimpleNamespace(file_tree=[])
    routes = [
        {"method": "GET", "path": "/api/user/list", "handler": "list", "file_path": "user.py"},
        {"method": "POST", "path": "/api/role/delete", "handler": "delete", "file_path": "role.py"},
    ]

    context = _build_stage_focus_compact_context(
        stage=stage,
        project=project,
        static_routes=routes,
        selected_chunks=[],
        audit_memory={},
        forced_routes=["POST /api/role/delete"],
    )

    assert context["focus_routes"][0]["path"] == "/api/role/delete"
    assert any("route_id=" in line and "/api/role/delete" in line for line in context["route_lines"])


def test_build_stage_user_prompt_smoke():
    stage = SimpleNamespace(stage_num=3, stage_name="Injection", findings={}, compressed_summary={})
    project = SimpleNamespace(id=1, name="demo", file_tree=[], tech_stack="Python")
    out = _build_stage_user_prompt(
        stage, project,
        stage_prompt="STAGE PROMPT MARKER XYZ",
        code_text="code snippet here",
        prev_context="",
        static_routes=[],
        compact_context=None,
        audit_memory=None,
    )
    assert isinstance(out, str)
    assert "STAGE PROMPT MARKER XYZ" in out
    assert "code snippet here" in out

"""M3 per-module tests: ai_engine.routes (identity, merge, coverage status, endpoint hydration)."""

from __future__ import annotations

from types import SimpleNamespace

from services.ai_engine.routes import (
    ROUTE_COVERAGE_AUDITED_STATUSES,
    ROUTE_COVERAGE_GAP_STATUSES,
    _extract_route_ids_from_lines,
    _hydrate_vulnerability_endpoints,
    _is_route_coverage_status_audited,
    _is_route_coverage_status_gap,
    _merge_routes_by_id,
    _normalize_route_coverage_status,
    _normalize_route_method,
    _normalize_route_path,
    _resolve_vulnerability_endpoint,
    _route_endpoint_keys,
    _route_id,
    _route_identity,
    _route_match_path,
    _route_priority_score,
    _resolve_vuln_route_id,
    _route_with_id,
    _select_best_route_candidate,
    _status_summary_for_route,
    _build_task_route_coverage_summary,
    _vulnerability_endpoint_keys,
)


# ── status normalization ──
def test_normalize_route_coverage_status_aliases_and_default():
    assert _normalize_route_coverage_status("covered") == "audited_no_finding"
    assert _normalize_route_coverage_status("audited") == "audited_no_finding"
    assert _normalize_route_coverage_status("vulnerable") == "finding"
    assert _normalize_route_coverage_status("finding_confirmed") == "confirmed_finding"
    assert _normalize_route_coverage_status("need_followup") == "needs_followup"
    assert _normalize_route_coverage_status("") == "audited_no_finding"
    # dashes/spaces collapsed to underscores before lookup
    assert _normalize_route_coverage_status("audited-no-finding") == "audited_no_finding"


def test_coverage_status_audited_and_gap_sets():
    assert "audited_no_finding" in ROUTE_COVERAGE_AUDITED_STATUSES
    assert "finding" in ROUTE_COVERAGE_AUDITED_STATUSES
    assert "needs_followup" in ROUTE_COVERAGE_GAP_STATUSES
    assert _is_route_coverage_status_audited("covered") is True
    assert _is_route_coverage_status_gap("missing") is True
    assert _is_route_coverage_status_gap("audited") is False


# ── method / path normalization ──
def test_normalize_route_method_and_path():
    assert _normalize_route_method("get") == "GET"
    assert _normalize_route_method(None) == "UNKNOWN"
    assert _normalize_route_path("/a /b") == "/a/b"
    assert _normalize_route_path("") == ""


# ── identity / id ──
def test_route_identity_and_id_stable():
    route = {"method": "GET", "path": "/api/login", "handler": "login", "file_path": "App\\Auth.py"}
    ident = _route_identity(route)
    assert ident[0] == "GET"
    assert ident[1] == "/api/login"
    assert ident[2] == "login"
    assert ident[3] == "app/auth.py"  # normalized match path
    # stable across calls
    assert _route_id(route) == _route_id(dict(route))
    assert _route_id(route).startswith("rt_")


def test_route_id_passthrough_existing():
    assert _route_id({"route_id": "rt_fixed", "method": "GET"}) == "rt_fixed"


def test_route_with_id_populates_fields():
    out = _route_with_id({"method": "post", "path": "  /x  "})
    assert out["method"] == "POST"
    assert out["path"] == "/x"
    assert out["route_id"].startswith("rt_")


# ── merge by id ──
def test_merge_routes_by_id_dedupes():
    a = {"method": "GET", "path": "/a", "handler": "h1", "file_path": "f1"}
    a_dup = {"method": "GET", "path": "/a", "handler": "h1", "file_path": "f1", "auth": "JWT"}
    b = {"method": "POST", "path": "/b"}
    merged = _merge_routes_by_id([a], [a_dup, b])
    assert len(merged) == 2
    paths = {r["path"] for r in merged}
    assert paths == {"/a", "/b"}


def test_merge_routes_by_id_ignores_non_lists():
    out = _merge_routes_by_id(None, "nope", [{"method": "GET", "path": "/a"}])
    assert len(out) == 1


# ── route id extraction from prompt lines ──
def test_extract_route_ids_from_lines_dedup():
    lines = ["foo route_id=rt_a bar", "route_id=rt_b", "route_id=rt_a again"]
    assert _extract_route_ids_from_lines(lines) == ["rt_a", "rt_b"]
    assert _extract_route_ids_from_lines("not a list") == []  # type: ignore[arg-type]


# ── path / endpoint key normalization ──
def test_route_match_path_collapses_params_and_ids():
    assert _route_match_path("/users/123/posts/:id") == "/users/{id}/posts/{id}"
    assert _route_match_path("/items/<itemId>") == "/items/{id}"


def test_route_endpoint_keys_variants():
    keys = _route_endpoint_keys({"method": "GET", "path": "/api/login"})
    assert "GET /api/login" in keys
    assert "ANY /api/login" in keys


def test_vulnerability_endpoint_keys_variants():
    keys = _vulnerability_endpoint_keys("GET /api/users/1")
    assert "GET /api/users/{id}" in keys
    assert "ANY /api/users/{id}" in keys
    assert _vulnerability_endpoint_keys("") == set()


# ── status summary precedence ──
def test_status_summary_for_route_precedence():
    assert _status_summary_for_route(["audited_no_finding", "confirmed_finding"]) == "confirmed_finding"
    assert _status_summary_for_route(["audited_no_finding", "finding"]) == "finding"
    assert _status_summary_for_route(["audited_no_finding"]) == "audited_no_finding"
    assert _status_summary_for_route(["insufficient_context"]) == "needs_followup"
    assert _status_summary_for_route([]) == "missing"


# ── priority score ──
def test_route_priority_score_ranks_critical_higher():
    assert _route_priority_score({"path": "/admin", "method": "POST"}) > _route_priority_score({"path": "/foo", "method": "GET"})
    assert _route_priority_score({"path": "/foo", "method": "GET"}) > 0  # auth-default bonus


# ── candidate selection + endpoint resolution ──
def test_select_best_route_candidate_exact_match():
    candidates = [
        {"method": "GET", "path": "/api/login", "file_path": "app/auth.py"},
        {"method": "POST", "path": "/api/other", "file_path": "app/other.py"},
    ]
    best = _select_best_route_candidate(candidates, file_path="app/auth.py", method="GET", path="/api/login")
    assert best is not None
    assert best["path"] == "/api/login"


def test_resolve_vulnerability_endpoint_matches_route():
    vuln = {"endpoint": "GET /api/login", "file_path": "app/authcontroller.java"}
    candidates = [{"method": "GET", "path": "/api/login", "file_path": "app/authcontroller.java"}]
    assert _resolve_vulnerability_endpoint(vuln, candidates) == "GET /api/login"


# ── hydration ──
def test_hydrate_vulnerability_endpoints_non_dict():
    out = _hydrate_vulnerability_endpoints(response="nope")  # type: ignore[arg-type]
    assert out == {"vulnerabilities": []}


def test_hydrate_vulnerability_endpoints_keeps_existing():
    response = {
        "vulnerabilities": [
            {"endpoint": "GET /api/login", "file_path": "app/authcontroller.java"},
            {"endpoint": "POST /x", "file_path": "app/x.py"},
        ]
    }
    out = _hydrate_vulnerability_endpoints(response=response, static_routes=[{"method": "GET", "path": "/api/login"}])
    endpoints = [v["endpoint"] for v in out["vulnerabilities"]]
    assert "GET /api/login" in endpoints
    assert "POST /x" in endpoints


# ── M4a：route_id 回填 ──
def test_hydrate_backfills_route_id_when_matched():
    response = {"vulnerabilities": [
        {"endpoint": "GET /api/login", "file_path": "app/auth.py"}
    ]}
    static_routes = [{"method": "GET", "path": "/api/login", "handler": "login", "file_path": "app/auth.py"}]
    out = _hydrate_vulnerability_endpoints(response=response, static_routes=static_routes)
    v = out["vulnerabilities"][0]
    # route_id + 冗余路由字段从 matched route 回填
    assert v["route_id"].startswith("rt_")
    assert v["route_method"] == "GET"
    assert v["route_path"] == "/api/login"
    assert v["route_handler"] == "login"


def test_hydrate_leaves_no_route_fields_when_no_candidates():
    response = {"vulnerabilities": [{"endpoint": "GET /x", "file_path": "a.py"}]}
    out = _hydrate_vulnerability_endpoints(response=response, static_routes=[])
    v = out["vulnerabilities"][0]
    # 无候选 → 不回填 route 字段
    assert not v.get("route_id")
    assert not v.get("route_path")


# ── M4b：route_coverage 的 vuln→route 匹配优先 route_id ──
def test_resolve_vuln_route_id_prefers_route_id_over_endpoint():
    vuln = SimpleNamespace(route_id="rt_1", endpoint="GET /other")
    route_by_id = {"rt_1": {"path": "/api/a"}, "rt_2": {"path": "/other"}}
    route_by_endpoint = {"GET /other": "rt_2"}
    # route_id 命中 canonical → 直接用，不看 endpoint
    assert _resolve_vuln_route_id(vuln, route_by_id, route_by_endpoint) == "rt_1"


def test_resolve_vuln_route_id_falls_back_to_endpoint_for_legacy_vuln():
    vuln = SimpleNamespace(route_id="", endpoint="GET /api/login")
    route_by_id = {"rt_9": {"path": "/api/login"}}
    route_by_endpoint = {"GET /api/login": "rt_9"}
    # 无 route_id（旧 vuln）→ endpoint 模糊匹配
    assert _resolve_vuln_route_id(vuln, route_by_id, route_by_endpoint) == "rt_9"


def test_resolve_vuln_route_id_stale_route_id_falls_back_to_endpoint():
    vuln = SimpleNamespace(route_id="rt_stale", endpoint="GET /api/login")
    route_by_id = {"rt_9": {"path": "/api/login"}}  # rt_stale 已不在（路由被删/重建）
    route_by_endpoint = {"GET /api/login": "rt_9"}
    # route_id stale → 回退 endpoint
    assert _resolve_vuln_route_id(vuln, route_by_id, route_by_endpoint) == "rt_9"


def test_resolve_vuln_route_id_no_match_returns_empty():
    vuln = SimpleNamespace(route_id="", endpoint="GET /nope")
    route_by_id = {"rt_1": {"path": "/api/a"}}
    route_by_endpoint = {"GET /api/a": "rt_1"}
    assert _resolve_vuln_route_id(vuln, route_by_id, route_by_endpoint) == ""


def test_task_route_coverage_summary_explains_gap_reasons():
    route_a = _route_with_id({"method": "GET", "path": "/api/a", "handler": "a", "file_path": "a.py"})
    route_b = _route_with_id({"method": "POST", "path": "/api/b", "handler": "b", "file_path": "b.py"})
    route_c = _route_with_id({"method": "DELETE", "path": "/api/c", "handler": "c", "file_path": "c.py"})
    stage = SimpleNamespace(
        id=1,
        stage_num=3,
        stage_name="Injection",
        findings={
            "route_coverage": [
                {"route_id": route_a["route_id"], "status": "audited_no_finding", "reason": "checked"},
                {"route_id": route_b["route_id"], "status": "insufficient_context", "reason": "needs service trace"},
            ]
        },
        compressed_summary={
            "_stage_coverage": {
                "focus_routes": [route_a, route_b],
                "focus_route_ids": [route_a["route_id"], route_b["route_id"]],
            }
        },
    )

    summary = _build_task_route_coverage_summary(
        [stage],
        static_routes=[route_a, route_b, route_c],
        scan_stats={"route_count": 3},
        vulns=[],
    )

    assert summary["total_routes"] == 3
    assert summary["inventory_route_count"] == 3
    assert summary["canonical_route_count"] == 3
    assert summary["scan_reported_route_count"] == 3
    assert summary["model_derived_route_count"] == 0
    assert summary["audited_route_count"] == 1
    assert summary["missing_route_count"] == 2
    assert summary["unattested_route_count"] == 1
    assert summary["attested_gap_route_count"] == 1
    assert summary["gap_reason_counts"]["not_model_attested"] == 1
    assert summary["gap_reason_counts"]["attested_but_not_audited"] == 1
    assert summary["stage_coverage"][0]["unattested_focus_route_count"] == 0
    assert summary["stage_coverage"][0]["gap_focus_route_count"] == 1
    reasons = {route["path"]: route["gap_reason"] for route in summary["missing_routes"]}
    assert reasons["/api/b"] == "attested_but_not_audited"
    assert reasons["/api/c"] == "not_model_attested"

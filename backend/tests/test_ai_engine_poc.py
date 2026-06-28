"""M3 per-module tests: ai_engine.poc (HTTP parse, endpoint match, PoC classify/validate)."""

from __future__ import annotations

from services.ai_engine.poc import (
    _build_route_derived_raw_http_artifacts,
    _classify_poc_requirement,
    _endpoint_matches_packet,
    _looks_like_cli_or_config_poc,
    _looks_like_stepwise_poc,
    _materialize_route_path,
    _normalize_http_path,
    _parse_endpoint_hint,
    _parse_raw_http_request,
    _sample_poc_value,
    _split_route_params,
    _validate_vulnerability_poc,
)


# ── path / endpoint hints ──
def test_normalize_http_path():
    assert _normalize_http_path("http://h.com/a/b/?x=1") == "/a/b"
    assert _normalize_http_path("https://h.com//a//b") == "/a/b"
    assert _normalize_http_path("a/b/") == "/a/b"
    assert _normalize_http_path("") == ""


def test_parse_endpoint_hint():
    assert _parse_endpoint_hint("GET /api/x") == ("GET", "/api/x")
    assert _parse_endpoint_hint("") == ("UNKNOWN", "")
    assert _parse_endpoint_hint("plainword")[0] == "UNKNOWN"


def test_materialize_route_path_replaces_params():
    assert _materialize_route_path("/users/{id}/posts/{pid}") == "/users/1/posts/1"
    assert _materialize_route_path("/u/<uid>") == "/u/1"
    assert _materialize_route_path("/u/:uid") == "/u/1"


# ── raw http parse + match ──
def test_parse_raw_http_request_valid():
    pkt = _parse_raw_http_request("GET /a/b?x=1 HTTP/1.1\nHost: example.com")
    assert pkt["valid"] is True
    assert pkt["method"] == "GET"
    assert pkt["target"] == "/a/b?x=1"
    assert pkt["headers"]["host"] == "example.com"


def test_parse_raw_http_request_missing_host():
    pkt = _parse_raw_http_request("GET /a HTTP/1.1\nX-Other: 1")
    assert pkt["valid"] is False
    assert "host" in pkt["reason"].lower()


def test_parse_raw_http_request_bad_request_line():
    assert _parse_raw_http_request("not a request line")["valid"] is False
    assert _parse_raw_http_request("")["valid"] is False


def test_endpoint_matches_packet():
    pkt = {"method": "GET", "target": "/api/users/1"}
    assert _endpoint_matches_packet("GET /api/users/1", pkt) is True
    assert _endpoint_matches_packet("ANY /api/users/1", pkt) is True
    # method mismatch (non-ANY endpoint)
    assert _endpoint_matches_packet("POST /api/users/1", pkt) is False


# ── classify ──
def test_classify_poc_requirement_by_marker():
    assert _classify_poc_requirement(8, {"title": "硬编码 API key"}) == "none"
    assert _classify_poc_requirement(8, {"title": "SQL 注入", "vuln_type": "sqli"}) == "raw_http"
    assert _classify_poc_requirement(6, {"title": "信息泄露 debug"}) == "cli"
    assert _classify_poc_requirement(6, {"title": "业务逻辑 越权"}) == "stepwise"


def test_classify_poc_requirement_stage_fallback():
    # no markers -> stage-based fallback
    assert _classify_poc_requirement(2, {"title": "x"}) == "raw_http"
    assert _classify_poc_requirement(5, {"title": "x"}) == "stepwise"
    assert _classify_poc_requirement(7, {"title": "x"}) == "cli"
    assert _classify_poc_requirement(1, {"title": "x"}) == "none"


# ── shape heuristics ──
def test_looks_like_stepwise_poc():
    assert _looks_like_stepwise_poc("1. 登录\n2. 修改密码\n3. 越权") is True
    assert _looks_like_stepwise_poc("single line") is False
    assert _looks_like_stepwise_poc("") is False


def test_looks_like_cli_or_config_poc():
    assert _looks_like_cli_or_config_poc("curl http://example.com/admin") is True
    assert _looks_like_cli_or_config_poc("nothing special here") is False


# ── sample value / params / auth ──
def test_sample_poc_value():
    assert _sample_poc_value("user_id") == 1
    assert _sample_poc_value("email") == "audit@example.com"
    assert _sample_poc_value("enabled") is True
    assert _sample_poc_value("name") == "test"


def test_split_route_params():
    q, b, p = _split_route_params(["query.page", "body.name", "path.id", "raw"])
    assert "page" in q and "name" in b and "id" in p and "raw" in b


# ── validate ──
def test_validate_poc_none_requirement_accepted():
    res = _validate_vulnerability_poc(8, {"title": "硬编码 secret", "vuln_type": "hardcoded"})
    assert res["accepted"] is True
    assert res["reason"] == "code_evidence_only"


def test_validate_poc_raw_http_missing_endpoint():
    res = _validate_vulnerability_poc(
        2, {"title": "SQLi", "vuln_type": "sqli", "poc_raw": "GET /a HTTP/1.1\nHost: x"}
    )
    assert res["accepted"] is False
    assert "endpoint" in res["reason"]


def test_validate_poc_raw_http_ok():
    res = _validate_vulnerability_poc(
        2,
        {
            "title": "SQLi",
            "vuln_type": "sqli",
            "endpoint": "GET /api/login",
            "poc_raw": "GET /api/login?u=admin HTTP/1.1\nHost: example.com",
        },
    )
    assert res["accepted"] is True
    assert res["reason"] == "valid_raw_http"


# ── route-derived artifacts ──
def test_build_route_derived_raw_http_artifacts():
    route = {"method": "POST", "path": "/users/{id}", "params": ["body.name", "query.page"], "auth": "JWT"}
    summary, packet = _build_route_derived_raw_http_artifacts({"endpoint": ""}, route)
    assert summary.startswith("POST /users/1")
    assert "POST /users/1" in packet
    assert "Authorization: Bearer <JWT_TOKEN>" in packet
    assert "Host: example.com" in packet


def test_build_route_derived_raw_http_artifacts_empty_path():
    assert _build_route_derived_raw_http_artifacts({}, {"path": ""}) == ("", "")

"""PoC template backfill, HTTP request parsing, and PoC validation."""

from __future__ import annotations

import json
import re

from services.ai_engine._utils import _merge_unique_items

import logging

logger = logging.getLogger(__name__)

def _parse_endpoint_hint(endpoint_text: str) -> tuple[str, str]:
    endpoint_text = str(endpoint_text or "").strip()
    if not endpoint_text:
        return "UNKNOWN", ""
    match = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT|ANY|UNKNOWN)\s+(\S+)$", endpoint_text, re.I)
    if match:
        return match.group(1).upper(), _normalize_http_path(match.group(2).strip())
    return "UNKNOWN", _normalize_http_path(endpoint_text)

def _materialize_route_path(path: str) -> str:
    text = _normalize_http_path(path)
    if not text:
        return ""
    text = re.sub(r"\{[^}/]+\}", "1", text)
    text = re.sub(r"<[^>/]+>", "1", text)
    text = re.sub(r":[A-Za-z_][A-Za-z0-9_]*", "1", text)
    return text

def _sample_poc_value(name: str) -> str | int | bool:
    lowered = str(name or "").strip().lower()
    if any(token in lowered for token in ["id", "_id", "ids", "page", "limit", "offset", "count", "size"]):
        return 1
    if any(token in lowered for token in ["enabled", "active", "admin", "debug", "flag"]):
        return True
    if "email" in lowered:
        return "audit@example.com"
    if any(token in lowered for token in ["token", "jwt", "code", "key", "secret"]):
        return "test-token"
    return "test"

def _split_route_params(params: list) -> tuple[list[str], list[str], list[str]]:
    query_params: list[str] = []
    body_params: list[str] = []
    path_params: list[str] = []

    for item in params if isinstance(params, list) else []:
        name = str(item or "").strip()
        if not name:
            continue
        lowered = name.lower()
        if lowered.startswith("query."):
            query_params.append(name.split(".", 1)[1])
        elif lowered.startswith("body.") or lowered.startswith("json.") or lowered.startswith("form."):
            body_params.append(name.split(".", 1)[1])
        elif lowered.startswith("path.") or lowered.startswith("param.") or lowered.startswith("params."):
            path_params.append(name.split(".", 1)[1])
        else:
            body_params.append(name)

    return _merge_unique_items([], query_params), _merge_unique_items([], body_params), _merge_unique_items([], path_params)

def _build_route_auth_headers(auth: str) -> list[str]:
    auth_value = str(auth or "Unknown").strip()
    if auth_value == "JWT":
        return ["Authorization: Bearer <JWT_TOKEN>"]
    if auth_value == "OAuth":
        return ["Authorization: Bearer <OAUTH_TOKEN>"]
    if auth_value == "Session":
        return ["Cookie: session=<SESSION_ID>"]
    return []

def _build_route_derived_raw_http_artifacts(vuln: dict, route_candidate: dict | None) -> tuple[str, str]:
    endpoint_method, endpoint_path = _parse_endpoint_hint(str(vuln.get("endpoint", "") or ""))
    route_method = str((route_candidate or {}).get("method", "") or endpoint_method or "GET").upper()
    route_path = str((route_candidate or {}).get("path", "") or endpoint_path or "").strip()
    if not route_path:
        return "", ""

    params = (route_candidate or {}).get("params", []) if isinstance((route_candidate or {}).get("params"), list) else []
    auth = str((route_candidate or {}).get("auth", "Unknown") or "Unknown").strip()
    concrete_path = _materialize_route_path(route_path)
    query_params, body_params, _ = _split_route_params(params)
    query_string = "&".join(f"{name}={_sample_poc_value(name)}" for name in query_params[:8])
    request_target = concrete_path if not query_string else f"{concrete_path}?{query_string}"

    headers = ["Host: example.com"]
    headers.extend(_build_route_auth_headers(auth))
    body = ""

    if route_method in {"POST", "PUT", "PATCH", "DELETE"}:
        payload = {name: _sample_poc_value(name) for name in body_params[:8]}
        headers.append("Content-Type: application/json")
        body = json.dumps(payload or {"test": "value"}, ensure_ascii=False, indent=2)

    request_lines = [f"{route_method or 'GET'} {request_target} HTTP/1.1", *headers, ""]
    if body:
        request_lines.append(body)
    return f"{route_method} {concrete_path}".strip(), "\n".join(request_lines).strip()

def _validate_vulnerability_poc(stage_num: int, vuln: dict) -> dict:
    requirement = _classify_poc_requirement(stage_num, vuln)
    endpoint = str(vuln.get("endpoint", "") or "").strip()
    poc_raw = str(vuln.get("poc_raw", "") or "").strip()
    if requirement == "none":
        return {"accepted": True, "reason": "code_evidence_only"}
    if vuln.get("_poc_template_generated"):
        return {"accepted": False, "reason": "已根据静态路由生成请求模板，仍需补全真实参数和利用前提"}

    if not poc_raw:
        return {"accepted": False, "reason": "缺少 poc_raw"}

    if requirement == "raw_http":
        if not endpoint:
            return {"accepted": False, "reason": "缺少完整路由 endpoint"}
        packet = _parse_raw_http_request(poc_raw)
        if not packet["valid"]:
            return {"accepted": False, "reason": packet["reason"]}
        if not _endpoint_matches_packet(endpoint, packet):
            return {"accepted": False, "reason": "endpoint 与 poc_raw 中的请求行不一致"}
        return {"accepted": True, "reason": "valid_raw_http"}

    if requirement == "stepwise":
        if not endpoint:
            return {"accepted": False, "reason": "缺少完整路由 endpoint"}
        packet = _parse_raw_http_request(poc_raw)
        if packet["valid"]:
            if not _endpoint_matches_packet(endpoint, packet):
                return {"accepted": False, "reason": "endpoint 与 poc_raw 中的请求行不一致"}
            return {"accepted": True, "reason": "valid_raw_http"}
        if _looks_like_stepwise_poc(poc_raw):
            return {"accepted": True, "reason": "valid_stepwise_poc"}
        return {"accepted": False, "reason": "缺少可执行的步骤化 PoC 或合法 raw HTTP 请求包"}

    if requirement == "cli":
        packet = _parse_raw_http_request(poc_raw)
        if packet["valid"]:
            if endpoint and not _endpoint_matches_packet(endpoint, packet):
                return {"accepted": False, "reason": "endpoint 与 poc_raw 中的请求行不一致"}
            return {"accepted": True, "reason": "valid_raw_http"}
        if _looks_like_cli_or_config_poc(poc_raw):
            return {"accepted": True, "reason": "valid_cli_or_config_poc"}
        return {"accepted": False, "reason": "缺少可执行的命令行验证、配置 diff 或合法 raw HTTP 请求包"}

    return {"accepted": True, "reason": "requirement_unclassified"}

def _classify_poc_requirement(stage_num: int, vuln: dict) -> str:
    # 先按漏洞语义判断 PoC 形态，阶段号只作为兜底，避免业务逻辑类被误判成必须 raw HTTP。
    haystack = " ".join(
        [
            str(vuln.get("title", "") or ""),
            str(vuln.get("vuln_type", "") or ""),
            str(vuln.get("description", "") or ""),
            str(vuln.get("fix_suggestion", "") or ""),
            str(vuln.get("endpoint", "") or ""),
            str(vuln.get("file_path", "") or ""),
            str(vuln.get("poc_raw", "") or ""),
        ]
    ).lower()

    none_markers = [
        "硬编码",
        "hardcoded",
        "hard code",
        "hard-coded",
        "api key",
        "access key",
        "private key",
        "secret key",
        "hardcoded secret",
        "ak/sk",
        "弱密码哈希",
        "无盐",
        "无盐 md5",
        "无盐md5",
        "weak md5",
        "weak sha1",
        "密码哈希",
        "哈希算法",
        "无需 poc",
        "无需poc",
        "code evidence only",
    ]
    cli_markers = [
        "配置",
        "config",
        "信息泄露",
        "debug",
        "日志泄露",
        "目录索引",
        "directory listing",
        ".env",
        "env 泄露",
        "stack trace",
        "依赖",
        "dependency",
        "版本泄露",
    ]
    stepwise_markers = [
        "业务逻辑",
        "logic bypass",
        "竞态",
        "race",
        "会话固定",
        "session fixation",
        "暴力破解",
        "brute force",
        "越权",
        "idor",
        "权限绕过",
        "水平越权",
        "垂直越权",
        "支付绕过",
        "下载绕过",
        "流程绕过",
        "状态机",
        "多步",
    ]
    raw_http_markers = [
        "sqli",
        "nosqli",
        "注入",
        "rce",
        "命令执行",
        "command execution",
        "ssrf",
        "xss",
        "文件上传",
        "文件下载",
        "路径穿越",
        "目录遍历",
        "任意文件",
        "反序列化",
        "模板注入",
        "表达式注入",
    ]

    if any(marker in haystack for marker in none_markers):
        return "none"
    if any(marker in haystack for marker in cli_markers):
        return "cli"
    if any(marker in haystack for marker in stepwise_markers):
        return "stepwise"
    if any(marker in haystack for marker in raw_http_markers):
        return "raw_http"

    if stage_num in {2, 3, 4, 8}:
        return "raw_http"
    if stage_num in {5, 6, 9}:
        return "stepwise"
    if stage_num == 7:
        return "cli"
    return "none" if stage_num == 1 else "raw_http"

def _looks_like_stepwise_poc(poc_raw: str) -> bool:
    text = str(poc_raw or "").strip()
    if not text:
        return False
    lines = [line.strip() for line in text.replace("\r\n", "\n").split("\n") if line.strip()]
    if len(lines) < 2:
        return False
    step_pattern = re.compile(r"^(\d+[.)、]|步骤\s*[一二三四五六七八九十0-9]+[：:]?|step\s*\d+[：:]?)", re.I)
    if any(step_pattern.match(line) for line in lines):
        return True
    lowered = text.lower()
    step_markers = ["步骤", "复现", "攻击流程", "利用流程", "先 ", "然后", "再 ", "最后", "登录后"]
    return sum(1 for marker in step_markers if marker in lowered) >= 2

def _looks_like_cli_or_config_poc(poc_raw: str) -> bool:
    text = str(poc_raw or "").strip()
    if not text:
        return False
    lowered = text.lower()
    cli_markers = [
        "curl ",
        "wget ",
        "httpie ",
        "grep ",
        "findstr ",
        "cat ",
        "type ",
        "php ",
        "python ",
        "node ",
        "diff ",
        "git diff",
        "printenv",
        "set ",
        "export ",
        ".env",
        "配置",
        "环境变量",
        "日志",
        "堆栈",
    ]
    if any(marker in lowered for marker in cli_markers):
        return True
    return any(token in text for token in ["=>", "BEGIN", "END", "---", "+++", "@@"])

def _parse_raw_http_request(poc_raw: str) -> dict:
    lines = [line.rstrip() for line in str(poc_raw or "").replace("\r\n", "\n").split("\n")]
    lines = [line for line in lines if line.strip() or line == ""]
    if not lines:
        return {"valid": False, "reason": "poc_raw 为空"}

    request_line = lines[0].strip()
    match = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+(\S+)\s+HTTP/1\.[01]$", request_line, re.I)
    if not match:
        return {"valid": False, "reason": "缺少合法的 raw HTTP 请求行"}

    method = match.group(1).upper()
    target = match.group(2).strip()
    header_lines = []
    body_lines = []
    in_body = False
    for line in lines[1:]:
        if not in_body:
            if line == "":
                in_body = True
                continue
            if ":" not in line and header_lines:
                in_body = True
                body_lines.append(line)
                continue
            header_lines.append(line)
        else:
            body_lines.append(line)

    headers = {}
    for line in header_lines:
        if ":" not in line:
            return {"valid": False, "reason": "存在不合法的 HTTP Header 行"}
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()

    if "host" not in headers or not headers["host"]:
        return {"valid": False, "reason": "缺少 Host Header"}

    return {
        "valid": True,
        "method": method,
        "target": target,
        "headers": headers,
        "body": "\n".join(body_lines).strip(),
    }

def _endpoint_matches_packet(endpoint: str, packet: dict) -> bool:
    endpoint_text = str(endpoint or "").strip()
    endpoint_method = "ANY"
    endpoint_path = endpoint_text

    match = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT|ANY|UNKNOWN)\s+(\S+)$", endpoint_text, re.I)
    if match:
        endpoint_method = match.group(1).upper()
        endpoint_path = match.group(2).strip()

    packet_method = str(packet.get("method", "")).upper()
    packet_target = str(packet.get("target", "")).strip()
    if endpoint_method not in {"ANY", "UNKNOWN"} and endpoint_method != packet_method:
        return False

    packet_path = _normalize_http_path(packet_target)
    endpoint_path = _normalize_http_path(endpoint_path)
    if endpoint_path == packet_path:
        return True
    if endpoint_path and packet_path and (endpoint_path in packet_path or packet_path in endpoint_path):
        return True
    if endpoint_method == "ANY" and endpoint_path:
        endpoint_tail = endpoint_path.rsplit("/", 1)[-1]
        packet_tail = packet_path.rsplit("/", 1)[-1]
        if endpoint_tail and endpoint_tail == packet_tail:
            return True
    return False

def _normalize_http_path(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith("http://") or text.startswith("https://"):
        text = re.sub(r"^https?://[^/]+", "", text, flags=re.I) or "/"
    text = text.split("?", 1)[0].split("#", 1)[0].strip()
    if not text.startswith("/"):
        text = "/" + text.lstrip("/")
    text = re.sub(r"/{2,}", "/", text)
    if len(text) > 1 and text.endswith("/"):
        text = text.rstrip("/")
    return text

__all__ = [
    '_parse_endpoint_hint',
    '_materialize_route_path',
    '_sample_poc_value',
    '_split_route_params',
    '_build_route_auth_headers',
    '_build_route_derived_raw_http_artifacts',
    '_validate_vulnerability_poc',
    '_classify_poc_requirement',
    '_looks_like_stepwise_poc',
    '_looks_like_cli_or_config_poc',
    '_parse_raw_http_request',
    '_endpoint_matches_packet',
    '_normalize_http_path',
]

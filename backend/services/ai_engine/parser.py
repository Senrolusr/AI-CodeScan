"""Structured-response parsing, truncated-response salvage, and response merge reducers."""

from __future__ import annotations

import json
import re
from services.json_repair import decode_json_string_fragment as _decode_json_string_fragment, extract_balanced_json_value as _extract_balanced_json_value

from services.ai_engine._utils import _merge_unique_items
from services.ai_engine._constants import _get_stage_retry_policy
from services.ai_engine.findings import STAGE1_RISK_HINT_LIMIT, _collect_stage1_risk_hints, _stage1_response_with_risk_hints
from services.ai_engine.vulnerability_store import _merge_vulnerability_lists

import logging

logger = logging.getLogger(__name__)

def _response_meta_indicates_truncation(meta: dict | None) -> bool:
    if not isinstance(meta, dict):
        return False

    finish_reason = str(meta.get("finish_reason") or "").strip().lower()
    if finish_reason in {"length", "max_output_tokens", "max_tokens", "incomplete"}:
        return True

    response_status = str(meta.get("response_status") or "").strip().lower()
    if response_status == "incomplete":
        return True

    incomplete_details = meta.get("incomplete_details")
    if isinstance(incomplete_details, dict):
        reason = str(incomplete_details.get("reason") or incomplete_details.get("type") or "").strip().lower()
        if reason in {"max_output_tokens", "max_tokens", "length"}:
            return True

    return False

def _annotate_response_completion(response: dict | list, meta: dict | None) -> dict | list:
    if not isinstance(response, dict):
        return response

    annotated = dict(response)
    if _response_meta_indicates_truncation(meta):
        annotated["response_incomplete"] = True
        annotated["_meta_truncated"] = True
        if not annotated.get("parse_error"):
            annotated["parse_error"] = "模型响应因输出长度限制被截断"
    return annotated

def _parse_structured_response(raw: str, meta: dict | None = None) -> dict | list:
    text = _normalize_llm_json_text(raw)

    try:
        return _annotate_response_completion(json.loads(text), meta)
    except json.JSONDecodeError:
        extracted = _extract_best_json_candidate(text)
        if extracted:
            try:
                return _annotate_response_completion(json.loads(extracted), meta)
            except json.JSONDecodeError:
                pass

    salvaged = _salvage_partial_structured_response(text, raw)
    if salvaged is not None:
        return _annotate_response_completion(salvaged, meta)

    return _annotate_response_completion(
        {
            "raw_response": raw,
            "parse_error": "无法从模型响应中提取 JSON",
            "response_incomplete": _looks_like_truncated_response(text),
            "vulnerabilities": [],
        },
        meta,
    )

def _should_retry_incomplete_response(stage_num: int, response: dict | list) -> bool:
    policy = _get_stage_retry_policy(stage_num)
    if not policy.get("enabled"):
        return False
    if not isinstance(response, dict):
        return False
    return bool(response.get("parse_error") or response.get("response_incomplete") or response.get("_salvaged"))

def _describe_retry_reason(response: dict | list) -> str:
    if not isinstance(response, dict):
        return ""
    reasons = []
    if response.get("parse_error"):
        reasons.append("parse_error")
    if response.get("response_incomplete"):
        reasons.append("response_incomplete")
    if response.get("_salvaged"):
        reasons.append("salvaged")
    return ",".join(reasons)

def _build_retry_meta(response: dict | list, retry_policy: dict) -> dict:
    return {
        "triggered": False,
        "reason": "",
        "prompt_length": 0,
        "success": False,
        "selected_attempt": "initial",
        "initial_parse_error": bool(isinstance(response, dict) and response.get("parse_error")),
        "initial_response_incomplete": bool(isinstance(response, dict) and response.get("response_incomplete")),
        "initial_salvaged": bool(isinstance(response, dict) and response.get("_salvaged")),
        "policy": retry_policy,
    }

def _score_stage_response(response: dict | list) -> int:
    if isinstance(response, list):
        return 10 + len(response)
    if not isinstance(response, dict):
        return 0

    score = 0
    if not response.get("parse_error"):
        score += 40
    if not response.get("response_incomplete"):
        score += 30
    if not response.get("_salvaged"):
        score += 20

    vulnerabilities = response.get("vulnerabilities", [])
    if isinstance(vulnerabilities, list):
        score += min(len(vulnerabilities), 8) * 3
        for vuln in vulnerabilities[:8]:
            if isinstance(vuln, dict) and str(vuln.get("poc_raw", "")).strip():
                score += 1

    if str(response.get("stage_summary", "")).strip():
        score += 3
    if isinstance(response.get("architecture_info"), dict) and response.get("architecture_info"):
        score += 3
    return score

def _coerce_incomplete_stage_response(
    *,
    stage_num: int,
    response: dict | list,
    retry_policy: dict | None = None,
) -> tuple[dict | list, bool]:
    if isinstance(response, list):
        return {"stage_summary": "", "architecture_info": {}, "vulnerabilities": response}, True
    if not isinstance(response, dict):
        return {"stage_summary": "", "architecture_info": {}, "vulnerabilities": []}, True

    if not (response.get("parse_error") or response.get("response_incomplete") or response.get("_salvaged")):
        return response, False

    retry_policy = retry_policy or {}
    max_vulnerabilities = max(1, int(retry_policy.get("max_vulnerabilities", 3) or 3))
    route_limit = min(8, max(2, max_vulnerabilities * 3))

    architecture_info = response.get("architecture_info", {})
    normalized_arch = {}
    if isinstance(architecture_info, dict):
        for key in ["tech_stack", "framework", "database", "auth_mechanism"]:
            value = architecture_info.get(key)
            if value:
                normalized_arch[key] = str(value)[:200]
        routes = architecture_info.get("routes")
        if isinstance(routes, list) and routes:
            normalized_routes = []
            for route in routes[:route_limit]:
                if not isinstance(route, dict):
                    continue
                path = str(route.get("path", "") or "").strip()
                if not path:
                    continue
                normalized_routes.append(
                    {
                        "method": str(route.get("method", "UNKNOWN") or "UNKNOWN").upper(),
                        "path": path,
                        "handler": str(route.get("handler", "") or "")[:160],
                        "file_path": str(route.get("file_path", "") or "")[:260],
                        "auth": str(route.get("auth", "Unknown") or "Unknown")[:40],
                        "params": route.get("params", [])[:6] if isinstance(route.get("params"), list) else [],
                        "notes": str(route.get("notes", "") or "")[:200],
                    }
                )
            if normalized_routes:
                normalized_arch["routes"] = normalized_routes

    normalized_vulns = []
    vulnerabilities = response.get("vulnerabilities", [])
    if isinstance(vulnerabilities, list):
        for vuln in vulnerabilities[:max_vulnerabilities]:
            if not isinstance(vuln, dict):
                continue
            normalized_vulns.append(
                {
                    "title": str(vuln.get("title", "") or "")[:160],
                    "severity": str(vuln.get("severity", "") or "")[:20],
                    "vuln_type": str(vuln.get("vuln_type", "") or "")[:120],
                    "file_path": str(vuln.get("file_path", "") or "")[:260],
                    "line_start": int(vuln.get("line_start", 0) or 0),
                    "line_end": int(vuln.get("line_end", 0) or 0),
                    "code_snippet": str(vuln.get("code_snippet", "") or "")[:1200],
                    "endpoint": str(vuln.get("endpoint", "") or "")[:260],
                    "poc_raw": str(vuln.get("poc_raw", "") or "")[:1500],
                    "description": str(vuln.get("description", "") or "")[:1200],
                    "fix_suggestion": str(vuln.get("fix_suggestion", "") or "")[:800],
                    "confidence": str(vuln.get("confidence", "medium") or "medium")[:20],
                }
            )

    stage_summary = str(response.get("stage_summary", "") or "").strip()
    if not stage_summary:
        stage_summary = f"阶段{stage_num} 模型响应出现截断，系统已根据可恢复字段整理为完整 JSON。"

    normalized = {
        "stage_summary": stage_summary[:1200],
        "architecture_info": normalized_arch,
        "vulnerabilities": normalized_vulns,
        "_recovered_from_incomplete_response": True,
    }
    if response.get("parse_error"):
        normalized["_recovery_reason"] = str(response.get("parse_error"))[:200]
    return normalized, True

def _normalize_llm_json_text(raw: str) -> str:
    text = (raw or "").strip()
    text = text.replace("\ufeff", "").replace("\u200b", "")
    text = text.replace("“", '"').replace("”", '"').replace("‘", "'").replace("’", "'")
    if text.startswith("```"):
        lines = text.split("\n")
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text

def _extract_best_json_candidate(text: str) -> str:
    for start_char in ["{", "["]:
        start_idx = text.find(start_char)
        if start_idx == -1:
            continue
        object_text, _ = _extract_balanced_json_value(text, start_idx)
        if object_text:
            return object_text

    for start_char, end_char in [("{", "}"), ("[", "]")]:
        start_idx = text.find(start_char)
        end_idx = text.rfind(end_char)
        if start_idx != -1 and end_idx > start_idx:
            return text[start_idx : end_idx + 1]
    return ""

def _salvage_partial_structured_response(text: str, raw: str) -> dict | None:
    stage_summary = _extract_partial_json_string_field(text, "stage_summary") or ""
    architecture_info = _extract_partial_architecture_info(text)
    vulnerabilities = _extract_partial_vulnerabilities(text)
    if not vulnerabilities and not stage_summary and not architecture_info:
        return None

    for vuln in vulnerabilities:
        if isinstance(vuln, dict):
            vuln["_salvaged"] = True

    if not stage_summary and architecture_info:
        stage_summary = _generate_fallback_stage_summary(architecture_info)

    return {
        "_salvaged": True,
        "raw_response": raw,
        "parse_error": "模型响应 JSON 不完整，已从截断内容中恢复部分漏洞数据",
        "response_incomplete": _looks_like_truncated_response(text),
        "stage_summary": stage_summary,
        "architecture_info": architecture_info,
        "vulnerabilities": vulnerabilities,
    }

def _generate_fallback_stage_summary(architecture_info: dict) -> str:
    parts = []
    tech_stack = architecture_info.get("tech_stack", "")
    framework = architecture_info.get("framework", "")
    database = architecture_info.get("database", "")
    auth = architecture_info.get("auth_mechanism", "")
    routes = architecture_info.get("routes", [])
    if isinstance(routes, list):
        route_count = len(routes)
    else:
        route_count = 0
    modules = architecture_info.get("modules", [])
    if isinstance(modules, list):
        module_count = len(modules)
    else:
        module_count = 0

    if tech_stack:
        parts.append(f"技术栈：{tech_stack}")
    if framework:
        parts.append(f"框架：{framework}")
    if database:
        parts.append(f"数据库：{database}")
    if auth:
        parts.append(f"认证方式：{auth}")
    if route_count:
        parts.append(f"识别到 {route_count} 条路由")
    if module_count:
        parts.append(f"{module_count} 个功能模块")

    if parts:
        return "项目架构概要（从截断响应中恢复）：" + "；".join(parts) + "。"
    return "模型响应被截断，架构信息不完整，已恢复部分数据。"

def _looks_like_truncated_response(text: str) -> bool:
    stripped = (text or "").rstrip()
    if not stripped:
        return False
    return not stripped.endswith(("}", "]"))

def _extract_partial_architecture_info(text: str) -> dict:
    marker = '"architecture_info"'
    marker_index = text.find(marker)
    if marker_index == -1:
        return {}

    object_start = text.find("{", marker_index)
    if object_start == -1:
        return {}

    object_text, _ = _extract_balanced_json_value(text, object_start)
    if object_text:
        try:
            value = json.loads(object_text)
            return value if isinstance(value, dict) else {}
        except json.JSONDecodeError:
            pass

    data = {}
    for key in ["tech_stack", "framework", "database", "auth_mechanism"]:
        value = _extract_partial_json_string_field(text[object_start:], key)
        if value:
            data[key] = value
    return data

def _extract_partial_vulnerabilities(text: str) -> list[dict]:
    marker = '"vulnerabilities"'
    marker_index = text.find(marker)
    if marker_index == -1:
        return []

    array_start = text.find("[", marker_index)
    if array_start == -1:
        return []

    decoder = json.JSONDecoder()
    items: list[dict] = []
    index = array_start + 1
    length = len(text)

    while index < length:
        while index < length and text[index] in " \r\n\t,":
            index += 1
        if index >= length:
            break
        if text[index] == "]":
            break
        if text[index] != "{":
            next_object = text.find("{", index)
            if next_object == -1:
                break
            index = next_object

        try:
            obj, next_index = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            object_text, next_index = _extract_balanced_json_object(text, index)
            if not object_text:
                trailing = _extract_partial_object_fragment(text[index:])
                vuln = _extract_partial_vulnerability_fields(trailing)
                if vuln:
                    items.append(vuln)
                break
            try:
                obj = json.loads(object_text)
            except json.JSONDecodeError:
                vuln = _extract_partial_vulnerability_fields(object_text)
                if vuln:
                    items.append(vuln)
                break
            index = next_index
        else:
            index += next_index

        if isinstance(obj, dict):
            items.append(obj)

    if items:
        return items

    return _extract_vulnerabilities_by_field_patterns(text[array_start + 1 :])

def _extract_vulnerabilities_by_field_patterns(text: str) -> list[dict]:
    object_segments = _split_partial_object_segments(text)
    items: list[dict] = []

    for segment in object_segments[:20]:
        vuln = _extract_partial_vulnerability_fields(segment)
        if vuln:
            items.append(vuln)

    return items

def _split_partial_object_segments(text: str) -> list[str]:
    segments: list[str] = []
    cursor = 0
    length = len(text)

    while cursor < length:
        start = text.find("{", cursor)
        if start == -1:
            break
        object_text, next_index = _extract_balanced_json_object(text, start)
        if object_text:
            segments.append(object_text)
            cursor = next_index
            continue

        fragment = _extract_partial_object_fragment(text[start:])
        if fragment:
            segments.append(fragment)
        break

    if not segments and text.strip():
        segments.append(text)
    return segments

def _extract_partial_object_fragment(text: str) -> str:
    if not text:
        return ""
    start = text.find("{")
    if start == -1:
        return text

    in_string = False
    escaped = False
    depth = 0

    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
            continue
        if char == "{":
            depth += 1
            continue
        if char == "}":
            depth = max(0, depth - 1)
            continue
        if depth == 1 and char == ",":
            lookahead = text[index + 1 : index + 80]
            if re.match(r'\s*\{', lookahead):
                return text[start:index].rstrip()
            if re.match(r'\s*\]', lookahead):
                return text[start:index].rstrip()
    return text[start:].rstrip()

def _extract_partial_vulnerability_fields(segment: str) -> dict | None:
    keys = [
        "title",
        "severity",
        "vuln_type",
        "file_path",
        "line_start",
        "line_end",
        "code_snippet",
        "endpoint",
        "poc_raw",
        "description",
        "fix_suggestion",
    ]
    data: dict = {}

    for key in keys:
        if key in {"line_start", "line_end"}:
            value = _extract_partial_json_number_field(segment, key)
        else:
            value = _extract_partial_json_string_field(segment, key)
        if value not in (None, ""):
            data[key] = value

    if not any(data.get(key) for key in ("title", "vuln_type", "file_path", "endpoint", "description")):
        return None

    data.setdefault("title", "未命名漏洞")
    data.setdefault("severity", "Medium")
    data.setdefault("vuln_type", "未分类漏洞")
    data.setdefault("file_path", "")
    data.setdefault("code_snippet", "")
    data.setdefault("endpoint", "")
    data.setdefault("poc_raw", "未提供可复现 POC，请结合代码补充复现步骤。")
    data.setdefault("description", "")
    data.setdefault("fix_suggestion", "")
    data["_salvaged"] = True
    return data

def _extract_partial_json_string_field(segment: str, field: str) -> str | None:
    complete_match = re.search(rf'"{re.escape(field)}"\s*:\s*"((?:\\.|[^"\\])*)"', segment, re.S)
    if complete_match:
        return _decode_json_string_fragment(complete_match.group(1))

    partial_match = re.search(rf'"{re.escape(field)}"\s*:\s*"([^\r\n]*)', segment)
    if partial_match:
        return _decode_json_string_fragment(partial_match.group(1)).strip()

    return None

def _extract_partial_json_number_field(segment: str, field: str) -> int | None:
    match = re.search(rf'"{re.escape(field)}"\s*:\s*(-?\d+)', segment)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None

def _extract_balanced_json_object(text: str, start_index: int) -> tuple[str, int]:
    return _extract_balanced_json_value(text, start_index, "{", "}")

def _coerce_stage_summary(value) -> dict:
    if isinstance(value, dict) and value:
        return value
    return {
        "stage_summary": "",
        "architecture_info": {},
        "vulnerability_hints": [],
        "coverage": {
            "passes_completed": 0,
            "scanned_chunk_count": 0,
            "total_chunk_count": 0,
            "covered_paths": [],
            "compacted_chunk_count": 0,
            "signal_window_chunk_count": 0,
            "compacted_paths": [],
            "audit_scope_label": "审计集覆盖率",
            "audit_scope_type": "selected_high_value_chunks",
            "audit_scope_note": "仅统计纳入阶段一审计集的高价值代码块，不代表全仓源码 100% 覆盖。",
            "audit_scope_file_count": 0,
            "audit_scope_chunk_count": 0,
        },
    }

def _extract_stage1_delta(response: dict | list) -> dict:
    if isinstance(response, list):
        return {
            "stage_summary": "",
            "architecture_info": {},
            "vulnerability_hints": _collect_stage1_risk_hints(response)[:6],
        }
    if not isinstance(response, dict):
        return {"stage_summary": "", "architecture_info": {}, "vulnerability_hints": []}
    return {
        "stage_summary": str(response.get("stage_summary", "")).strip()[:900],
        "architecture_info": _compact_stage1_architecture_info(response.get("architecture_info")),
        "vulnerability_hints": _collect_stage1_risk_hints(response)[:6],
    }

def _compact_stage1_architecture_info(architecture_info: dict | None) -> dict:
    if not isinstance(architecture_info, dict):
        return {}

    compact = {}
    for key in ["tech_stack", "framework", "database", "auth_mechanism"]:
        value = architecture_info.get(key)
        if value:
            compact[key] = str(value)[:200]

    routes = architecture_info.get("routes")
    if isinstance(routes, list) and routes:
        normalized_routes = []
        for route in routes[:24]:
            if not isinstance(route, dict):
                continue
            path = str(route.get("path", "")).strip()
            if not path:
                continue
            normalized_routes.append(
                {
                    "method": str(route.get("method", "UNKNOWN")).upper(),
                    "path": path,
                    "handler": str(route.get("handler", "Unknown"))[:160],
                    "file_path": str(route.get("file_path", ""))[:260],
                    "auth": str(route.get("auth", "Unknown"))[:40],
                    "params": route.get("params", [])[:8] if isinstance(route.get("params"), list) else [],
                    "notes": str(route.get("notes", ""))[:240],
                }
            )
        if normalized_routes:
            compact["routes"] = normalized_routes
        compact["route_count"] = len(routes)

    for key, limit in [("entry_points", 12), ("output_points", 12), ("modules", 12), ("data_flows", 12)]:
        value = architecture_info.get(key)
        if isinstance(value, list) and value:
            compact[key] = value[:limit]

    for key in ["middleware_chain", "database_models", "security_boundaries", "external_integrations"]:
        value = architecture_info.get(key)
        if value:
            compact[key] = value if isinstance(value, list) else value

    return compact

def _merge_compressed_summary(
    base: dict,
    delta: dict,
    chunk_batch: list[dict],
    total_chunk_count: int,
    total_selected_file_count: int | None = None,
    compression_stats: dict | None = None,
) -> dict:
    merged = _coerce_stage_summary(base)

    stage_summary = str(delta.get("stage_summary", "")).strip()
    if stage_summary:
        merged["stage_summary"] = _merge_compact_stage_summary(
            merged.get("stage_summary", ""),
            stage_summary,
            max_chars=1400,
        )

    merged["architecture_info"] = _merge_architecture_info(
        merged.get("architecture_info"),
        delta.get("architecture_info"),
    )
    merged["vulnerability_hints"] = _merge_vulnerability_lists(
        merged.get("vulnerability_hints"),
        delta.get("vulnerability_hints"),
    )[:18]

    coverage = merged.get("coverage", {}) if isinstance(merged.get("coverage"), dict) else {}
    covered_paths = _merge_unique_items(
        coverage.get("covered_paths"),
        [chunk.get("file_path", "") for chunk in chunk_batch if chunk.get("file_path")],
    )
    covered_chunk_keys = _merge_unique_items(
        coverage.get("covered_chunks"),
        [
            str(chunk.get("file_path", "") or chunk.get("base_file_path", "") or "").strip()
            for chunk in chunk_batch
            if str(chunk.get("file_path", "") or chunk.get("base_file_path", "") or "").strip()
        ],
    )
    coverage["passes_completed"] = int(coverage.get("passes_completed", 0)) + 1
    coverage["scanned_chunk_count"] = min(total_chunk_count, len(covered_chunk_keys))
    coverage["total_chunk_count"] = total_chunk_count
    coverage["covered_paths"] = covered_paths[:500]
    coverage["covered_chunks"] = covered_chunk_keys[:2000]
    coverage["audit_scope_label"] = "审计集覆盖率"
    coverage["audit_scope_type"] = "selected_high_value_chunks"
    coverage["audit_scope_note"] = "仅统计纳入阶段一审计集的高价值代码块，不代表全仓源码 100% 覆盖。"
    coverage["audit_scope_file_count"] = max(0, int(total_selected_file_count or len(covered_paths)))
    coverage["audit_scope_chunk_count"] = total_chunk_count
    compression_stats = compression_stats or {}
    coverage["compacted_chunk_count"] = max(
        0,
        int(coverage.get("compacted_chunk_count", 0)) + int(compression_stats.get("compacted_chunk_count", 0)),
    )
    coverage["signal_window_chunk_count"] = max(
        0,
        int(coverage.get("signal_window_chunk_count", 0)) + int(compression_stats.get("signal_window_chunk_count", 0)),
    )
    coverage["compacted_paths"] = _merge_unique_items(
        coverage.get("compacted_paths"),
        compression_stats.get("compacted_paths"),
    )[:400]
    merged["coverage"] = coverage

    return merged

def _summarize_stage1_pass_outputs(pass_outputs: list[dict]) -> dict:
    if not isinstance(pass_outputs, list) or not pass_outputs:
        return {
            "executed_pass_count": 0,
            "total_prompt_length": 0,
            "total_code_length": 0,
            "max_coverage_ratio": 0.0,
            "avg_signal_gain": 0.0,
            "peak_signal_gain": 0,
            "new_path_total": 0,
            "compacted_chunk_total": 0,
        }

    coverage_values = [
        float((item.get("progress") or {}).get("coverage_ratio", 0.0) or 0.0)
        for item in pass_outputs
        if isinstance(item, dict)
    ]
    signal_values = [
        int((item.get("progress") or {}).get("signal_gain", 0) or 0)
        for item in pass_outputs
        if isinstance(item, dict)
    ]
    return {
        "executed_pass_count": len(pass_outputs),
        "last_pass_index": int(pass_outputs[-1].get("pass_index", len(pass_outputs)) or len(pass_outputs)),
        "total_prompt_length": sum(int(item.get("user_prompt_length", 0) or 0) for item in pass_outputs if isinstance(item, dict)),
        "total_code_length": sum(int(item.get("code_text_length", 0) or 0) for item in pass_outputs if isinstance(item, dict)),
        "max_coverage_ratio": round(max(coverage_values) if coverage_values else 0.0, 4),
        "avg_signal_gain": round((sum(signal_values) / len(signal_values)) if signal_values else 0.0, 2),
        "peak_signal_gain": max(signal_values) if signal_values else 0,
        "new_path_total": sum(int((item.get("progress") or {}).get("new_path_count", 0) or 0) for item in pass_outputs if isinstance(item, dict)),
        "compacted_chunk_total": sum(int((item.get("microcompact") or {}).get("compacted_chunk_count", 0) or 0) for item in pass_outputs if isinstance(item, dict)),
    }

def _summarize_architecture_info(architecture_info: dict | None) -> dict:
    if not isinstance(architecture_info, dict):
        return {}
    summary = {}
    for key in ["tech_stack", "framework", "database", "auth_mechanism"]:
        value = architecture_info.get(key)
        if value:
            summary[key] = str(value)[:200]
    routes = architecture_info.get("routes")
    if isinstance(routes, list):
        summary["route_count"] = len(routes)
    for key in ["entry_points", "output_points", "modules", "data_flows"]:
        value = architecture_info.get(key)
        if isinstance(value, list) and value:
            summary[key] = value[:8]
    return summary

def _merge_stage1_pass_response(base: dict, response: dict | list) -> dict:
    response = _stage1_response_with_risk_hints(response)
    if not isinstance(response, dict):
        return base

    merged = {
        "stage_summary": str(base.get("stage_summary", "")).strip(),
        "architecture_info": dict(base.get("architecture_info", {})) if isinstance(base.get("architecture_info"), dict) else {},
        "risk_hints": list(base.get("risk_hints", [])) if isinstance(base.get("risk_hints"), list) else [],
        "vulnerabilities": [],
    }

    if response.get("stage_summary"):
        merged["stage_summary"] = _merge_compact_stage_summary(
            merged.get("stage_summary", ""),
            response.get("stage_summary", ""),
            max_chars=1200,
        )

    merged["architecture_info"] = _merge_architecture_info(merged["architecture_info"], response.get("architecture_info"))
    merged["risk_hints"] = _merge_vulnerability_lists(merged["risk_hints"], response.get("risk_hints"))[:STAGE1_RISK_HINT_LIMIT]

    for key, value in response.items():
        if key not in {"stage_summary", "architecture_info", "risk_hints", "vulnerabilities"} and key not in merged:
            merged[key] = value

    return merged

def _merge_stage_vulnerability_response(base: dict, incoming: dict | list) -> dict:
    if isinstance(incoming, list):
        incoming = {"stage_summary": "", "architecture_info": {}, "vulnerabilities": incoming}
    if not isinstance(base, dict):
        base = {"stage_summary": "", "architecture_info": {}, "vulnerabilities": []}
    if not isinstance(incoming, dict):
        return base

    merged = dict(base)
    merged["stage_summary"] = _merge_compact_stage_summary(
        merged.get("stage_summary", ""),
        incoming.get("stage_summary", ""),
        max_chars=1600,
    )
    merged["architecture_info"] = _merge_architecture_info(merged.get("architecture_info"), incoming.get("architecture_info"))
    merged["vulnerabilities"] = _merge_vulnerability_lists(
        merged.get("vulnerabilities"),
        incoming.get("vulnerabilities"),
    )

    for key, value in incoming.items():
        if key in {"stage_summary", "architecture_info", "vulnerabilities"}:
            continue
        if key not in merged and value not in (None, "", [], {}):
            merged[key] = value
    return merged

def _merge_compact_stage_summary(existing: str, addition: str, max_chars: int = 1200) -> str:
    existing = str(existing or "").strip()
    addition = str(addition or "").strip()
    if not addition:
        return existing[:max_chars]
    if not existing:
        return addition[:max_chars]
    if addition in existing:
        return existing[:max_chars]
    if len(existing) >= max_chars:
        return existing[:max_chars]

    merged = f"{existing}\n\n{addition}".strip()
    if len(merged) <= max_chars:
        return merged
    remaining = max(0, max_chars - len(existing) - 6)
    if remaining <= 80:
        return existing[:max_chars]
    return f"{existing}\n\n{addition[:remaining].rstrip()}...".strip()

def _merge_architecture_info(base: dict | None, incoming: dict | None) -> dict:
    result = dict(base) if isinstance(base, dict) else {}
    if not isinstance(incoming, dict):
        return result

    singular_fields = ["tech_stack", "framework", "database", "auth_mechanism"]
    list_fields = ["routes", "entry_points", "output_points", "modules", "data_flows"]

    for field in singular_fields:
        if not result.get(field) and incoming.get(field):
            result[field] = incoming.get(field)

    for field in list_fields:
        merged_list = _merge_unique_items(result.get(field), incoming.get(field))
        if merged_list:
            result[field] = merged_list

    for key, value in incoming.items():
        if key in singular_fields or key in list_fields:
            continue
        if key not in result and value not in (None, "", [], {}):
            result[key] = value

    return result

__all__ = [
    '_response_meta_indicates_truncation',
    '_annotate_response_completion',
    '_parse_structured_response',
    '_should_retry_incomplete_response',
    '_describe_retry_reason',
    '_build_retry_meta',
    '_score_stage_response',
    '_coerce_incomplete_stage_response',
    '_normalize_llm_json_text',
    '_extract_best_json_candidate',
    '_salvage_partial_structured_response',
    '_generate_fallback_stage_summary',
    '_looks_like_truncated_response',
    '_extract_partial_architecture_info',
    '_extract_partial_vulnerabilities',
    '_extract_vulnerabilities_by_field_patterns',
    '_split_partial_object_segments',
    '_extract_partial_object_fragment',
    '_extract_partial_vulnerability_fields',
    '_extract_partial_json_string_field',
    '_extract_partial_json_number_field',
    '_extract_balanced_json_object',
    '_coerce_stage_summary',
    '_extract_stage1_delta',
    '_compact_stage1_architecture_info',
    '_merge_compressed_summary',
    '_summarize_stage1_pass_outputs',
    '_summarize_architecture_info',
    '_merge_stage1_pass_response',
    '_merge_stage_vulnerability_response',
    '_merge_compact_stage_summary',
    '_merge_architecture_info',
]

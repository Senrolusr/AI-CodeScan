"""Prompt construction: stage user prompts, skeleton retry prompts, excerpt formatting."""

from __future__ import annotations

import json
from models import AuditStage
from prompts.stage_prompts import get_spec_label

from services.ai_engine._utils import _incremental_submit_stage_nums, _merge_unique_items, _normalize_stage_num_list, _truncate_text
from services.ai_engine._constants import STAGE1_LATER_PASS_CODE_MAX_LEN, STAGE1_PASS1_CODE_MAX_LEN, _get_stage_retry_policy
from services.ai_engine.parser import _normalize_llm_json_text, _summarize_architecture_info
from services.ai_engine.findings import _coerce_stage_findings, _collect_stage1_risk_hints
from services.ai_engine.routes import _route_id, _route_priority_score, _route_with_id
from services.ai_engine.vulnerability_store import _merge_vulnerability_lists
from services.ai_engine.chunk_selector import _estimate_chunks_prompt_len, _is_high_signal_stage1_chunk

import logging

logger = logging.getLogger(__name__)

def _build_incomplete_json_retry_prompt(
    stage,
    project,
    stage_prompt: str,
    code_text: str,
    prev_context: str,
    static_routes: list[dict],
    compact_context: dict | None,
    audit_memory: dict | None,
    previous_raw_response: str,
    retry_policy: dict | None = None,
) -> str:
    compact_context = dict(compact_context or {})
    retry_policy = retry_policy or _get_stage_retry_policy(stage.stage_num)
    extra_guidance = str(compact_context.get("extra_guidance", "") or "").strip()
    max_vulnerabilities = int(retry_policy.get("max_vulnerabilities", 5) or 5)
    code_limit = int(retry_policy.get("code_limit", 32000) or 32000)
    prev_context_limit = int(retry_policy.get("prev_context_limit", 2400) or 2400)
    route_limit = int(retry_policy.get("route_limit", 16) or 16)

    retry_guidance = [
        "上一轮响应中的 JSON 不完整，本轮必须优先返回完整闭合、可解析的 JSON。",
        f"请压缩输出体积：architecture_info 仅保留必要字段，vulnerabilities 最多保留 {max_vulnerabilities} 条。",
        "如果 PoC 很长，请只保留最小可复现请求、关键参数或关键触发步骤，不要展开冗长 raw HTTP。",
        "不要输出 Markdown、代码围栏、解释性前后缀或额外文本。",
        "如果确实没有发现漏洞，也必须返回完整 JSON，并使用 vulnerabilities: []。",
    ]
    if stage.stage_num == 3:
        retry_guidance.append("阶段三优先保留最强注入证据和最短 PoC，避免把输出预算耗尽在攻击链叙述上。")
    if stage.stage_num == 5:
        retry_guidance.append("阶段五不要展开完整认证流程，只保留最强认证/会话漏洞证据。")
        retry_guidance.append("阶段五的首要目标是先闭合 JSON，再补 title、severity、vuln_type、file_path、endpoint、description。")
        retry_guidance.append("阶段五首轮最多保留 2 到 3 条漏洞；若登录、注册、验证码、刷新令牌问题本质相同，优先合并为代表性结果。")
    if stage.stage_num == 8:
        retry_guidance.append("阶段八最多保留 3 到 4 条文件操作漏洞，同类路径遍历问题优先合并为代表性结果。")
        retry_guidance.append("阶段八的 architecture_info 只保留最小必要入口、文件读写点和路径校验结论。")
    if stage.stage_num == 9:
        retry_guidance.append("阶段九只保留最强业务逻辑漏洞索引，不要铺陈业务背景或交易流程叙述。")

    compact_context["extra_guidance"] = "\n".join([part for part in [extra_guidance, *retry_guidance] if part])
    compact_context["route_lines"] = (compact_context.get("route_lines") or [])[:route_limit]
    compact_context["route_text_limit"] = min(int(compact_context.get("route_text_limit", 5000) or 5000), 2500)
    if stage.stage_num == 5:
        compact_context["audit_memory_limit"] = min(int(compact_context.get("audit_memory_limit", 1800) or 1800), 1800)

    retry_prompt = _build_stage_user_prompt(
        stage,
        project,
        stage_prompt,
        _truncate_text(code_text or "", code_limit),
        _truncate_text(prev_context or "", prev_context_limit),
        static_routes,
        compact_context=compact_context,
        audit_memory=_compact_audit_memory_for_stage(stage.stage_num, audit_memory or {}),
    )
    previous_excerpt = _truncate_text(_normalize_llm_json_text(previous_raw_response or ""), 1500)
    return "\n".join(
        [
            retry_prompt,
            "",
            "[Previous incomplete response excerpt]",
            previous_excerpt or "N/A",
            "",
            "Return valid JSON only.",
        ]
    )

def _build_exploit_stage_skeleton_retry_prompt(
    *,
    stage,
    project,
    stage_prompt: str,
    code_text: str,
    prev_context: str,
    static_routes: list[dict],
    compact_context: dict | None,
    audit_memory: dict | None,
    previous_raw_response: str,
) -> str:
    compact_context = dict(compact_context or {})
    compact_context["response_mode"] = "index_first"
    extra_guidance = str(compact_context.get("extra_guidance", "") or "").strip()
    compact_context["route_lines"] = (compact_context.get("route_lines") or [])[:4]
    compact_context["route_text_limit"] = min(int(compact_context.get("route_text_limit", 1200) or 1200), 1200)
    compact_context["rule_hit_lines"] = (compact_context.get("rule_hit_lines") or [])[:4]
    compact_context["focus_files"] = (compact_context.get("focus_files") or [])[:12]
    compact_context["audit_memory_limit"] = min(int(compact_context.get("audit_memory_limit", 1200) or 1200), 1200)
    stage_label = "阶段二" if stage.stage_num == 2 else "阶段三/四/八"
    compact_context["extra_guidance"] = "\n".join(
        part for part in [
            extra_guidance,
            f"{stage_label} 进入骨架恢复模式：本次目标只有一个，先返回完整闭合 JSON。",
            "只输出最多 2 条最强漏洞结果。",
            "不要展开攻击面背景，不要输出长篇利用链叙述。",
            "每条 vulnerability 优先填写：title、severity、vuln_type、file_path、line_start、line_end、endpoint、description。",
            "code_snippet、poc_raw、fix_suggestion 可以先写短字符串或空字符串，后续再补齐。",
        ] if part
    )

    skeleton_prompt = _build_stage_user_prompt(
        stage,
        project,
        stage_prompt,
        _truncate_text(code_text or "", 9000),
        _truncate_text(prev_context or "", 500),
        static_routes,
        compact_context=compact_context,
        audit_memory=_compact_audit_memory_for_stage(stage.stage_num, audit_memory or {}),
    )
    previous_excerpt = _truncate_text(_normalize_llm_json_text(previous_raw_response or ""), 1000)
    return "\n".join(
        [
            skeleton_prompt,
            "",
            "[Exploit skeleton mode JSON schema]",
            "{",
            '  "stage_summary": "中文阶段结论，1到2句",',
            '  "architecture_info": {',
            '    "tech_stack": "",',
            '    "framework": "",',
            '    "database": "",',
            '    "auth_mechanism": "",',
            '    "routes": []',
            "  },",
            '  "vulnerabilities": [',
            "    {",
            '      "title": "",',
            '      "severity": "Critical|High|Medium|Low|Info",',
            '      "vuln_type": "",',
            '      "file_path": "",',
            '      "line_start": 0,',
            '      "line_end": 0,',
            '      "code_snippet": "",',
            '      "endpoint": "",',
            '      "poc_raw": "",',
            '      "description": "",',
            '      "fix_suggestion": ""',
            "    }",
            "  ]",
            "}",
            "",
            "[Previous incomplete response excerpt]",
            previous_excerpt or "N/A",
            "",
            "Return valid JSON only.",
        ]
    )

def _build_stage9_skeleton_retry_prompt(
    *,
    stage,
    project,
    stage_prompt: str,
    code_text: str,
    prev_context: str,
    static_routes: list[dict],
    compact_context: dict | None,
    audit_memory: dict | None,
    previous_raw_response: str,
) -> str:
    compact_context = dict(compact_context or {})
    compact_context["response_mode"] = "index_first"
    extra_guidance = str(compact_context.get("extra_guidance", "") or "").strip()
    compact_context["route_lines"] = (compact_context.get("route_lines") or [])[:4]
    compact_context["route_text_limit"] = min(int(compact_context.get("route_text_limit", 1200) or 1200), 1200)
    compact_context["rule_hit_lines"] = (compact_context.get("rule_hit_lines") or [])[:4]
    compact_context["focus_files"] = (compact_context.get("focus_files") or [])[:12]
    compact_context["extra_guidance"] = "\n".join(
        part
        for part in [
            extra_guidance,
            "阶段九进入骨架恢复模式：本次目标只有一个，先返回完整闭合 JSON。",
            "只输出最多 2 条最强业务逻辑漏洞。",
            "architecture_info 仅保留 tech_stack、framework，以及最多 3 条 routes。",
            "每条 vulnerability 仅优先填写：title、severity、vuln_type、file_path、line_start、line_end、endpoint、description。",
            "code_snippet、poc_raw、fix_suggestion 可以留空字符串，后续会单独补全。",
            "不要展开业务背景，不要写长段说明，不要为了完整叙述牺牲 JSON 闭合。",
        ]
        if part
    )

    skeleton_prompt = _build_stage_user_prompt(
        stage,
        project,
        stage_prompt,
        _truncate_text(code_text or "", 9000),
        _truncate_text(prev_context or "", 500),
        static_routes,
        compact_context=compact_context,
        audit_memory=_compact_audit_memory_for_stage(stage.stage_num, audit_memory or {}),
    )
    previous_excerpt = _truncate_text(_normalize_llm_json_text(previous_raw_response or ""), 1000)
    return "\n".join(
        [
            skeleton_prompt,
            "",
            "[Stage 9 skeleton mode JSON schema]",
            "{",
            '  "stage_summary": "中文阶段结论，1到2句",',
            '  "architecture_info": {',
            '    "tech_stack": "",',
            '    "framework": "",',
            '    "database": "",',
            '    "auth_mechanism": "",',
            '    "routes": []',
            "  },",
            '  "vulnerabilities": [',
            "    {",
            '      "title": "",',
            '      "severity": "Critical|High|Medium|Low|Info",',
            '      "vuln_type": "",',
            '      "file_path": "",',
            '      "line_start": 0,',
            '      "line_end": 0,',
            '      "code_snippet": "",',
            '      "endpoint": "",',
            '      "poc_raw": "",',
            '      "description": "",',
            '      "fix_suggestion": ""',
            "    }",
            "  ]",
            "}",
            "",
            "[Previous incomplete response excerpt]",
            previous_excerpt or "N/A",
            "",
            "Return valid JSON only.",
        ]
    )

def _build_stage5_skeleton_retry_prompt(
    *,
    stage,
    project,
    stage_prompt: str,
    code_text: str,
    prev_context: str,
    static_routes: list[dict],
    compact_context: dict | None,
    audit_memory: dict | None,
    previous_raw_response: str,
) -> str:
    compact_context = dict(compact_context or {})
    compact_context["response_mode"] = "index_first"
    extra_guidance = str(compact_context.get("extra_guidance", "") or "").strip()
    compact_context["route_lines"] = (compact_context.get("route_lines") or [])[:4]
    compact_context["route_text_limit"] = min(int(compact_context.get("route_text_limit", 1200) or 1200), 1200)
    compact_context["rule_hit_lines"] = (compact_context.get("rule_hit_lines") or [])[:4]
    compact_context["focus_files"] = (compact_context.get("focus_files") or [])[:12]
    compact_context["extra_guidance"] = "\n".join(
        part
        for part in [
            extra_guidance,
            "阶段五进入骨架恢复模式：本次先返回完整闭合 JSON。",
            "只输出最多 1 到 2 条最强认证与会话安全漏洞。",
            "不要展开登录、注册、找回密码、验证码、刷新令牌等完整流程背景。",
            "每条 vulnerability 优先填写：title、severity、vuln_type、file_path、line_start、line_end、endpoint、description。",
            "code_snippet、poc_raw、fix_suggestion 可以先留空字符串，后续再补全。",
        ]
        if part
    )

    skeleton_prompt = _build_stage_user_prompt(
        stage,
        project,
        stage_prompt,
        _truncate_text(code_text or "", 7000),
        _truncate_text(prev_context or "", 350),
        static_routes,
        compact_context=compact_context,
        audit_memory=_compact_audit_memory_for_stage(stage.stage_num, audit_memory or {}),
    )
    previous_excerpt = _truncate_text(_normalize_llm_json_text(previous_raw_response or ""), 1000)
    return "\n".join(
        [
            skeleton_prompt,
            "",
            "[Stage 5 skeleton mode JSON schema]",
            "{",
            '  "stage_summary": "中文阶段结论，1到2句",',
            '  "architecture_info": {',
            '    "tech_stack": "",',
            '    "framework": "",',
            '    "database": "",',
            '    "auth_mechanism": "",',
            '    "routes": []',
            "  },",
            '  "vulnerabilities": [',
            "    {",
            '      "title": "",',
            '      "severity": "Critical|High|Medium|Low|Info",',
            '      "vuln_type": "",',
            '      "file_path": "",',
            '      "line_start": 0,',
            '      "line_end": 0,',
            '      "code_snippet": "",',
            '      "endpoint": "",',
            '      "poc_raw": "",',
            '      "description": "",',
            '      "fix_suggestion": ""',
            "    }",
            "  ]",
            "}",
            "",
            "[Previous incomplete response excerpt]",
            previous_excerpt or "N/A",
            "",
            "Return valid JSON only.",
        ]
    )

def _build_lightweight_stage_skeleton_retry_prompt(
    *,
    stage,
    project,
    stage_prompt: str,
    code_text: str,
    prev_context: str,
    static_routes: list[dict],
    compact_context: dict | None,
    audit_memory: dict | None,
    previous_raw_response: str,
) -> str:
    compact_context = dict(compact_context or {})
    compact_context["response_mode"] = "index_first"
    extra_guidance = str(compact_context.get("extra_guidance", "") or "").strip()
    compact_context["route_lines"] = (compact_context.get("route_lines") or [])[:3]
    compact_context["route_text_limit"] = min(int(compact_context.get("route_text_limit", 1000) or 1000), 1000)
    compact_context["rule_hit_lines"] = (compact_context.get("rule_hit_lines") or [])[:3]
    compact_context["focus_files"] = (compact_context.get("focus_files") or [])[:10]
    compact_context["extra_guidance"] = "\n".join(
        part for part in [
            extra_guidance,
            f"阶段{stage.stage_num} 进入骨架恢复模式：本次先保证 JSON 完整闭合。",
            "只保留最必要的阶段结论和漏洞索引。",
            "每条 vulnerability 优先填写：title、severity、vuln_type、file_path、endpoint、description。",
            "code_snippet、poc_raw、fix_suggestion 可以留空字符串或极短说明。",
        ] if part
    )

    skeleton_prompt = _build_stage_user_prompt(
        stage,
        project,
        stage_prompt,
        _truncate_text(code_text or "", 8000),
        _truncate_text(prev_context or "", 400),
        static_routes,
        compact_context=compact_context,
        audit_memory=_compact_audit_memory_for_stage(stage.stage_num, audit_memory or {}),
    )
    previous_excerpt = _truncate_text(_normalize_llm_json_text(previous_raw_response or ""), 800)
    return "\n".join(
        [
            skeleton_prompt,
            "",
            "[Lightweight skeleton mode JSON schema]",
            "{",
            '  "stage_summary": "中文阶段结论，1到2句",',
            '  "architecture_info": {',
            '    "tech_stack": "",',
            '    "framework": "",',
            '    "database": "",',
            '    "auth_mechanism": "",',
            '    "routes": []',
            "  },",
            '  "vulnerabilities": [',
            "    {",
            '      "title": "",',
            '      "severity": "Critical|High|Medium|Low|Info",',
            '      "vuln_type": "",',
            '      "file_path": "",',
            '      "line_start": 0,',
            '      "line_end": 0,',
            '      "code_snippet": "",',
            '      "endpoint": "",',
            '      "poc_raw": "",',
            '      "description": "",',
            '      "fix_suggestion": ""',
            "    }",
            "  ]",
            "}",
            "",
            "[Previous incomplete response excerpt]",
            previous_excerpt or "N/A",
            "",
            "Return valid JSON only.",
        ]
    )

def _build_summary_stage_skeleton_retry_prompt(
    *,
    stage,
    project,
    stage_prompt: str,
    code_text: str,
    prev_context: str,
    static_routes: list[dict],
    compact_context: dict | None,
    audit_memory: dict | None,
    previous_raw_response: str,
) -> str:
    compact_context = dict(compact_context or {})
    compact_context["response_mode"] = "index_first"
    extra_guidance = str(compact_context.get("extra_guidance", "") or "").strip()
    compact_context["route_lines"] = []
    compact_context["route_text_limit"] = 0
    compact_context["rule_hit_lines"] = []
    compact_context["focus_files"] = (compact_context.get("focus_files") or [])[:10]
    compact_context["extra_guidance"] = "\n".join(
        part for part in [
            extra_guidance,
            "进入骨架恢复模式：先返回完整闭合 JSON，再考虑扩展说明。",
            "只保留综合结论、最关键架构摘要和最多 3 条代表性漏洞。",
            "architecture_info 保持最小化，vulnerabilities 仅保留核心字段。",
            "每条 vulnerability 优先填写：title、severity、vuln_type、file_path、endpoint、description。",
            "code_snippet、poc_raw、fix_suggestion 可以留空字符串或极短说明。",
        ] if part
    )

    skeleton_prompt = _build_stage_user_prompt(
        stage,
        project,
        stage_prompt,
        _truncate_text(code_text or "", 8000),
        _truncate_text(prev_context or "", 400),
        static_routes,
        compact_context=compact_context,
        audit_memory=_compact_audit_memory_for_stage(stage.stage_num, audit_memory or {}),
    )
    previous_excerpt = _truncate_text(_normalize_llm_json_text(previous_raw_response or ""), 800)
    return "\n".join(
        [
            skeleton_prompt,
            "",
            "[Summary skeleton mode JSON schema]",
            "{",
            '  "stage_summary": "中文阶段结论，1到2句",',
            '  "architecture_info": {',
            '    "tech_stack": "",',
            '    "framework": "",',
            '    "database": "",',
            '    "auth_mechanism": "",',
            '    "routes": []',
            "  },",
            '  "vulnerabilities": [',
            "    {",
            '      "title": "",',
            '      "severity": "Critical|High|Medium|Low|Info",',
            '      "vuln_type": "",',
            '      "file_path": "",',
            '      "line_start": 0,',
            '      "line_end": 0,',
            '      "code_snippet": "",',
            '      "endpoint": "",',
            '      "poc_raw": "",',
            '      "description": "",',
            '      "fix_suggestion": ""',
            "    }",
            "  ]",
            "}",
            "",
            "[Previous incomplete response excerpt]",
            previous_excerpt or "N/A",
            "",
            "Return valid JSON only.",
        ]
    )

def _format_chunks_for_prompt(chunks: list[dict], stage_num: int, max_len: int | None = None) -> str:
    parts = []
    total_len = 0
    max_len = max_len or (180000 if stage_num == 1 else 70000)

    for chunk in chunks:
        role_tags = chunk.get("risk_labels") or []
        role_prefix = f" [{', '.join(str(t) for t in role_tags[:3])}]" if role_tags else ""
        header = f"\n### File: {chunk['file_path']}{role_prefix}\n```\n"
        footer = "\n```\n"
        content = chunk["content"]
        entry = header + content + footer

        if total_len + len(entry) > max_len:
            remaining = max_len - total_len - len(header) - len(footer) - 50
            if remaining > 200:
                entry = header + content[:remaining] + "\n... (truncated)\n```\n"
                parts.append(entry)
            break

        parts.append(entry)
        total_len += len(entry)

    return "".join(parts)

def _format_stage1_chunks_for_prompt(chunk_batch: list[dict], compressed_summary: dict, pass_index: int) -> tuple[str, dict]:
    batch_max_len = STAGE1_PASS1_CODE_MAX_LEN if pass_index <= 1 else STAGE1_LATER_PASS_CODE_MAX_LEN
    estimated_len = _estimate_chunks_prompt_len(chunk_batch) + 2048
    if pass_index <= 1:
        return _format_chunks_for_prompt(chunk_batch, 1, max_len=batch_max_len), {
            "compacted_chunk_count": 1 if estimated_len > batch_max_len else 0,
            "compacted_paths": [],
            "input_estimated_length": estimated_len,
            "input_max_length": batch_max_len,
        }

    parts = []
    total_len = 0
    max_len = batch_max_len
    coverage = compressed_summary.get("coverage", {}) if isinstance(compressed_summary, dict) else {}
    covered_paths = set(coverage.get("covered_paths", []) if isinstance(coverage, dict) else [])
    seen_paths_in_pass: set[str] = set()
    compacted_paths: list[str] = []
    compacted_chunk_count = 0
    signal_window_chunk_count = 0

    for chunk in chunk_batch:
        file_path = str(chunk.get("file_path", ""))
        content = str(chunk.get("content", ""))
        revisit = file_path in covered_paths
        repeated_in_pass = file_path in seen_paths_in_pass
        high_signal = _is_high_signal_stage1_chunk(chunk)

        if (revisit or repeated_in_pass) and not high_signal:
            entry, excerpt_mode = _format_compacted_chunk_entry(
                file_path=file_path,
                content=content,
                revisit=revisit,
                repeated_in_pass=repeated_in_pass,
            )
            compacted_chunk_count += 1
            if excerpt_mode == "signal_windows":
                signal_window_chunk_count += 1
            if file_path:
                compacted_paths.append(file_path)
        else:
            entry = _format_prompt_chunk_entry(file_path, content)

        if total_len + len(entry) > max_len:
            remaining = max_len - total_len - 80
            if remaining > 200:
                parts.append(_truncate_text(entry, remaining))
            break

        parts.append(entry)
        total_len += len(entry)
        if file_path:
            seen_paths_in_pass.add(file_path)

    return "".join(parts), {
        "compacted_chunk_count": compacted_chunk_count,
        "compacted_paths": _merge_unique_items([], compacted_paths),
        "signal_window_chunk_count": signal_window_chunk_count,
        "input_estimated_length": estimated_len,
        "input_max_length": batch_max_len,
    }

def _format_non_stage1_chunks_for_prompt(
    chunks: list[dict],
    stage_num: int,
    audit_memory: dict | None = None,
) -> str:
    if not chunks:
        return ""

    audit_memory = audit_memory or {}
    focus_files = set(audit_memory.get("evidence_files", []) if isinstance(audit_memory.get("evidence_files"), list) else [])
    parts = []
    total_len = 0
    max_len = 40000 if stage_num == 6 else 70000
    topic_keywords = _get_stage_topic_keywords(stage_num)

    for chunk in chunks:
        file_path = str(chunk.get("file_path", ""))
        content = str(chunk.get("content", ""))
        if not content:
            continue

        if file_path in focus_files:
            entry = _format_prompt_chunk_entry(file_path, content)
        else:
            excerpt, excerpt_mode = _extract_stage_focus_excerpt(content, topic_keywords)
            compacted_body = (
                f"# compacted context for stage {stage_num}\n"
                f"# excerpt mode: {excerpt_mode}\n"
                f"{excerpt}"
            )
            entry = _format_prompt_chunk_entry(file_path, compacted_body)

        if total_len + len(entry) > max_len:
            remaining = max_len - total_len - 80
            if remaining > 200:
                parts.append(_truncate_text(entry, remaining))
            break

        parts.append(entry)
        total_len += len(entry)

    return "".join(parts)

def _format_prompt_chunk_entry(file_path: str, content: str) -> str:
    header = f"\n### File: {file_path}\n```\n"
    footer = "\n```\n"
    return header + content + footer

def _format_compacted_chunk_entry(file_path: str, content: str, revisit: bool, repeated_in_pass: bool) -> tuple[str, str]:
    reason_parts = []
    if revisit:
        reason_parts.append("previously covered in earlier pass")
    if repeated_in_pass:
        reason_parts.append("same file already appeared in this pass")
    reason_text = ", ".join(reason_parts) if reason_parts else "prompt compression"
    excerpt, excerpt_mode = _extract_compacted_excerpt(content)
    compacted_body = (
        f"# compacted context: {reason_text}\n"
        f"# excerpt mode: {excerpt_mode}\n"
        "# keep the file role, sink/source patterns, auth checks, and data flow in mind.\n"
        f"{excerpt}"
    )
    return _format_prompt_chunk_entry(file_path, compacted_body), excerpt_mode

def _extract_compacted_excerpt(content: str, head_limit: int = 700, tail_limit: int = 500) -> tuple[str, str]:
    if len(content) <= head_limit + tail_limit + 80:
        return content, "full"

    signal_excerpt = _extract_signal_excerpt(content)
    if signal_excerpt:
        return signal_excerpt, "signal_windows"

    head = content[:head_limit].rstrip()
    tail = content[-tail_limit:].lstrip()
    return head + "\n\n... (middle omitted for stage1 microcompact) ...\n\n" + tail, "head_tail"

def _extract_signal_excerpt(content: str, window_radius: int = 8, max_segments: int = 4, max_chars: int = 2200) -> str:
    lines = content.splitlines()
    if len(lines) < 20:
        return ""

    keywords = [
        "route", "router", "app.", "@app.", "@router.", "include_router", "apirouter",
        "auth", "login", "jwt", "token", "session", "cookie", "oauth", "permission", "authorize",
        "sql", "query", "cursor", "select ", "insert ", "update ", "delete ", "execute(", "raw(",
        "exec(", "eval(", "subprocess", "system(", "popen", "runtime.exec",
        "upload", "download", "open(", "path", "os.", "shutil", "zip", "tar",
        "request", "response", "body", "params", "header", "form", "json",
        "pickle.loads", "yaml.load(", "unserialize(", "deserialize(", "marshal.loads",
        ".extra(", "cursor.execute", "mysqli_query", "pg_query", "orm",
        "csrf", "xsrf", "_csrf", "verify_token", "authenticate",
        "md5(", "sha1(", "des", "rc4", "ecb",
        "requests.get(", "urlopen(", "fetch(", "axios",
        "xml.parse", "xml.etree", "saxparser", "fromstring(",
        "order", "payment", "amount", "price", "inventory", "coupon", "balance", "refund",
    ]

    matched_indexes = []
    for index, line in enumerate(lines):
        lowered = line.lower()
        if any(keyword in lowered for keyword in keywords):
            matched_indexes.append(index)

    if not matched_indexes:
        return ""

    windows = []
    for index in matched_indexes[:24]:
        start = max(0, index - window_radius)
        end = min(len(lines), index + window_radius + 1)
        windows.append((start, end))

    merged_windows = []
    for start, end in sorted(windows):
        if not merged_windows or start > merged_windows[-1][1] + 2:
            merged_windows.append([start, end])
        else:
            merged_windows[-1][1] = max(merged_windows[-1][1], end)

    segments = []
    total_chars = 0
    for start, end in merged_windows[:max_segments]:
        segment = "\n".join(lines[start:end]).strip()
        if not segment:
            continue
        labeled = f"# lines {start + 1}-{end}\n{segment}"
        next_size = total_chars + len(labeled)
        if segments and next_size > max_chars:
            break
        segments.append(labeled)
        total_chars = next_size

    if not segments:
        return ""

    return "\n\n... (non-matching regions omitted for stage1 microcompact) ...\n\n".join(segments)

def _extract_stage_focus_excerpt(content: str, topic_keywords: list[str]) -> tuple[str, str]:
    if len(content) <= 2600:
        return content, "full"

    excerpt = _extract_keyword_excerpt(content, topic_keywords, max_segments=5, max_chars=2600)
    if excerpt:
        return excerpt, "topic_windows"

    return _extract_compacted_excerpt(content)

def _extract_keyword_excerpt(
    content: str,
    keywords: list[str],
    window_radius: int = 10,
    max_segments: int = 5,
    max_chars: int = 2600,
) -> str:
    lines = content.splitlines()
    if len(lines) < 20 or not keywords:
        return ""

    matched_indexes = []
    for index, line in enumerate(lines):
        lowered = line.lower()
        if any(keyword in lowered for keyword in keywords):
            matched_indexes.append(index)
    if not matched_indexes:
        return ""

    windows = []
    for index in matched_indexes:
        windows.append((max(0, index - window_radius), min(len(lines), index + window_radius + 1)))
    windows.sort()

    merged_windows = []
    for start, end in windows:
        if not merged_windows or start > merged_windows[-1][1]:
            merged_windows.append([start, end])
        else:
            merged_windows[-1][1] = max(merged_windows[-1][1], end)

    segments = []
    total_chars = 0
    for start, end in merged_windows[:max_segments]:
        segment = "\n".join(lines[start:end]).strip()
        if not segment:
            continue
        labeled = f"# lines {start + 1}-{end}\n{segment}"
        next_size = total_chars + len(labeled)
        if segments and next_size > max_chars:
            break
        segments.append(labeled)
        total_chars = next_size

    if not segments:
        return ""
    return "\n\n... (non-topic regions omitted for stage focus compact) ...\n\n".join(segments)

def _build_stage_user_prompt(stage, project, stage_prompt: str, code_text: str, prev_context: str, static_routes: list[dict], compact_context: dict | None = None, audit_memory: dict | None = None) -> str:
    compact_context = compact_context or {}
    project_tree_summary = compact_context.get("project_tree_summary") or _summarize_project_tree(project.file_tree or [])
    route_lines_override = compact_context.get("route_lines")
    route_text_limit = int(compact_context.get("route_text_limit", 12000) or 12000)
    route_intro = compact_context.get("route_intro") or "以下为系统基于源码静态抽取得到的候选路由，供你补充、纠正和完善，不可机械照抄，需结合源码确认："
    extra_guidance = compact_context.get("extra_guidance")

    sections = [
        f"请严格执行根目录文档《{get_spec_label()}》中当前阶段的原文要求。",
        "不要改写阶段目标，不要跨阶段扩展主题；若文档原文与其他说明冲突，以文档原文为准。",
        "",
        "【当前阶段原文】",
        stage_prompt,
        "",
        "【项目基础信息】",
        f"项目技术栈线索：{project.tech_stack or 'Unknown'}",
        "项目文件树摘要：",
        project_tree_summary,
    ]

    route_lines: list[str] = []
    if isinstance(route_lines_override, list):
        route_lines = route_lines_override
    elif stage.stage_num == 1 and static_routes:
        route_lines = _format_static_route_lines(static_routes[:80], total_count=len(static_routes))
    if route_lines and (stage.stage_num == 1 or isinstance(route_lines_override, list)):
        route_section_title = "【静态提取路由线索】" if stage.stage_num == 1 else "【本阶段路由线索】"
        sections.extend([
            "",
            route_section_title,
            route_intro,
            _truncate_text("\n".join(route_lines), route_text_limit),
        ])

    if extra_guidance:
        sections.extend([
            "",
            "【本轮补充约束】",
            extra_guidance,
        ])

    if stage.stage_num > 1:
        sections.extend([
            "",
            "【前序阶段结果】",
            prev_context if prev_context else "暂无前序阶段结果",
        ])

    # M5b：开启增量提交的阶段，引导模型以伪工具协议提前提交 finding（默认关闭）
    if stage.stage_num in _incremental_submit_stage_nums():
        sections.extend([
            "",
            "【增量提交（重要）】",
            "为避免响应过长被截断导致 finding 丢失，请每确认一条漏洞就立即在响应顶部的 `actions` 数组中提交一次，"
            "不要等全部写完再统一输出。`actions` 必须放在响应最前面，结构如下：",
            '```json',
            '{',
            '  "actions": [',
            '    {',
            '      "type": "submit_finding",',
            '      "payload": { "title": "...", "severity": "...", "vuln_type": "...", "file_path": "...", "description": "...", "poc_raw": "...", "fix_suggestion": "..." }',
            '    }',
            '  ],',
            '  "vulnerabilities": [],',
            '  "final_summary": "本阶段结论简述"',
            '}',
            '```',
            "`payload` 字段与漏洞 schema 一致；已通过 actions 提交的漏洞无需再放进 `vulnerabilities`。"
            "`final_summary` 保持简短即可。即便后续内容被截断，已写入 `actions` 的 finding 也会被系统落盘。",
        ])

    sections.extend([
        "",
        "【待审计代码】",
        code_text or "未提取到代码片段",
        "",
        "请输出合法 JSON。",
    ])

    return "\n".join(sections)

def _build_stage1_microcompact_context(project, static_routes: list[dict], compressed_summary: dict, chunk_batch: list[dict], pass_index: int, total_passes: int, pre_discovery: dict | None = None) -> dict:
    focus_files = [chunk.get("file_path", "") for chunk in chunk_batch if chunk.get("file_path")]
    focus_files = _merge_unique_items([], focus_files)
    covered_paths = (
        compressed_summary.get("coverage", {}).get("covered_paths", [])
        if isinstance(compressed_summary.get("coverage"), dict)
        else []
    )
    confirmed_routes = []
    architecture_info = compressed_summary.get("architecture_info")
    if isinstance(architecture_info, dict) and isinstance(architecture_info.get("routes"), list):
        confirmed_routes = architecture_info.get("routes", [])

    project_tree_summary = (
        _summarize_project_tree(project.file_tree or [], limit=120)
        if pass_index == 1
        else _summarize_focus_files(focus_files, covered_paths)
    )
    route_lines = _select_route_delta_lines(
        static_routes=static_routes,
        focus_files=focus_files,
        confirmed_routes=confirmed_routes,
        pass_index=pass_index,
    )
    route_intro = (
        "以下为首轮高价值静态路由候选，请优先建立全局接口地图。"
        if pass_index == 1
        else "以下仅保留与本轮代码批次强相关、且尚未在压缩摘要中确认的静态路由 delta。"
    )
    stage1_output_contract = (
        "阶段一只允许输出架构索引和未验证风险线索："
        "stage_summary 不超过 180 字；architecture_info.routes 最多 12 条且 notes 每条不超过 40 字；"
        "risk_hints 最多 3 条且每条 description 不超过 120 字；"
        "vulnerabilities 必须固定为 []；不要输出 PoC、修复建议、最终漏洞评级或长篇背景。"
    )
    extra_guidance = (
        f"本轮聚焦 {len(focus_files)} 个文件。已覆盖文件数：{len(covered_paths)}。{stage1_output_contract}"
        if pass_index > 1
        else f"本轮为阶段一首轮扫描，共计划 {total_passes} 轮，请先建立项目骨架。{stage1_output_contract}"
    )

    pre_discovery_summary = ""
    if pass_index == 1 and pre_discovery:
        tp = pre_discovery.get("tech_profile") or {}
        ds = pre_discovery.get("dir_structure") or {}
        mm = pre_discovery.get("middleware_map") or {}
        sf = pre_discovery.get("security_files") or {}
        parts = []
        for key in ["language", "framework", "database", "orm", "auth_library"]:
            vals = tp.get(key, [])
            if vals:
                parts.append(f"{key}: {', '.join(vals[:5])}")
        if ds.get("pattern") and ds["pattern"] != "unknown":
            parts.append(f"project_pattern: {ds['pattern']}")
        if mm.get("middleware_chain"):
            parts.append(f"middleware_count: {len(mm['middleware_chain'])}")
        if mm.get("auth_decorators"):
            parts.append(f"auth_decorators: {', '.join(list(mm['auth_decorators'].keys())[:5])}")
        if sf.get("total_critical_count"):
            parts.append(f"security_critical_files: {sf['total_critical_count']}")
        if parts:
            pre_discovery_summary = "【静态预发现】" + "；".join(parts) + "。请优先识别以上技术栈特征，并在架构信息中标注。"

    return {
        "project_tree_summary": project_tree_summary,
        "route_lines": route_lines,
        "route_text_limit": 12000 if pass_index == 1 else 5000,
        "route_intro": route_intro,
        "extra_guidance": extra_guidance,
        "focus_files": focus_files[:50],
        "pre_discovery_summary": pre_discovery_summary,
    }

def _summarize_focus_files(focus_files: list[str], covered_paths: list[str]) -> str:
    lines = ["- 本轮重点文件："]
    for path in focus_files[:40]:
        marker = " (new)" if path not in covered_paths else " (revisit)"
        lines.append(f"  - {path}{marker}")
    if covered_paths:
        lines.append(f"- 累计已覆盖文件数：{len(covered_paths)}")
    return "\n".join(lines)

def _format_static_route_lines(routes: list[dict], total_count: int | None = None) -> list[str]:
    route_lines = []
    for route in routes:
        route = _route_with_id(route)
        params = ",".join(route.get("params", [])) if isinstance(route.get("params"), list) else ""
        route_lines.append(
            f"- route_id={route.get('route_id', '')} | {route.get('method', 'UNKNOWN')} {route.get('path', '')} | "
            f"handler={route.get('handler', 'Unknown')} | file={route.get('file_path', '')} | "
            f"auth={route.get('auth', 'Unknown')} | params={params}"
        )
    if total_count and total_count > len(routes):
        route_lines.append(f"- ... total static routes: {total_count}")
    return route_lines

def _select_route_delta_lines(static_routes: list[dict], focus_files: list[str], confirmed_routes: list[dict], pass_index: int) -> list[str]:
    confirmed_keys = set()
    for route in confirmed_routes:
        if not isinstance(route, dict):
            continue
        confirmed_keys.add(
            (
                str(route.get("method", "UNKNOWN")).upper(),
                route.get("path", ""),
                route.get("handler", "Unknown"),
                route.get("file_path", ""),
            )
        )

    focus_set = set(focus_files)
    filtered = []
    global_uncovered = []
    for route in static_routes:
        if not isinstance(route, dict):
            continue
        route_key = (
            str(route.get("method", "UNKNOWN")).upper(),
            route.get("path", ""),
            route.get("handler", "Unknown"),
            route.get("file_path", ""),
        )
        if pass_index > 1 and route_key in confirmed_keys:
            continue
        if pass_index > 1 and focus_set and route.get("file_path", "") not in focus_set:
            global_uncovered.append(route)
            continue
        filtered.append(route)

    if pass_index == 1:
        filtered = filtered[:60]
    else:
        filtered = filtered[:16]
        if len(filtered) < 24:
            filtered.extend(global_uncovered[: 24 - len(filtered)])

    if not filtered and focus_files:
        return [f"- 本轮批次文件未命中新静态路由；请重点从代码中补充 {', '.join(focus_files[:8])} 的模块职责与数据流。"]
    return _format_static_route_lines(filtered, total_count=len(filtered))

def _summarize_project_tree(tree: list, limit: int = 180) -> str:
    lines: list[str] = []

    def walk(nodes: list, level: int):
        for node in nodes:
            if len(lines) >= limit:
                return
            prefix = "  " * level
            lines.append(f"{prefix}- {node.get('path', node.get('name', ''))}")
            if node.get("type") == "directory" and node.get("children"):
                walk(node["children"], level + 1)

    walk(tree, 0)
    if not lines:
        return "- 无文件树信息"
    if len(lines) >= limit:
        lines.append("- ... (truncated)")
    return "\n".join(lines)

def _get_stage_topic_keywords(stage_num: int) -> list[str]:
    rules = {
        2: [
            "exec", "eval", "system(", "shell", "popen", "runtime.exec", "processbuilder",
            "command", "os.system", "subprocess", "child_process",
            "pickle", "unserialize", "yaml.load", "marshal", "deserialize",
            "proc_open", "pcntl_exec", "assert(", "compile(",
            "vm.run", "class.forname", "scriptengine", "objectinputstream",
            "os/exec", "exec.command", "spawn(",
            "jinja2", "freemarker", "velocity", "ognl", "spel", "mvel",
            "xstream", "xmldecoder", "invocationhandler",
        ],
        3: [
            "sql", "query", "cursor", "select ", "insert ", "update ", "delete ",
            "execute(", "raw(", "orm", "mongodb", "redis",
            "preparedstatement", "jdbctemplate", "hibernate",
            "sequelize", "knex", "typeorm", "prisma", "mongoose",
            "db.query", "db.exec", "gorm", "sqlx",
            "$where", "$gt", "$regex", "nosql",
            "ldap_search", "ldap_bind", "graphql",
            "executescript(", "rawsql", "raw_query",
            "statement", "createorreplace",
        ],
        4: [
            "xss", "html", "template", "render", "innerhtml", "v-html",
            "document.write", "escape", "sanitize", "encode",
            "outerhtml", "dangerouslysetinnerhtml", "domparser",
            "insertadjacenthtml", "contenteditable",
            "srcdoc", "javascript:", "postmessage(",
            "bypasssecuritytrust", "domsanitizer",
            "htmlspecialchars", "strip_tags",
            "onerror", "onclick", "onload",
        ],
        5: [
            "auth", "login", "jwt", "token", "session", "cookie", "oauth",
            "password", "signin", "signup",
            "bearer", "authenticate", "verify_token",
            "saml", "kerberos", "ntlm",
            "recaptcha", "hcaptcha", "totp", "mfa", "2fa",
            "bcrypt", "argon2", "pbkdf2",
            "refresh_token", "access_token",
            "rate_limit", "lockout", "login_attempts",
            "session_regenerate", "csrf",
        ],
        6: [
            "permission", "authorize", "acl", "role", "idor", "tenant",
            "owner", "resource_id", "user_id", "guard",
            "authorization", "policy", "scope", "preauthorize",
            "tenant_id", "account_id", "isadmin", "hasrole",
            "org_id", "project_id", "team_id", "customer_id",
            "current_user", "principal", "can_access",
            "ownership", "resource", "access_control",
        ],
        7: [
            "config", "secret", ".env", "yaml", "yml", "toml", "ini",
            "docker", "compose", "dependency", "package.json",
            "api_key", "private_key", "access_key", "credentials",
            "db_password", "database_url", "debug=true",
            "cors_origin", "allowed_hosts", "ssl", "tls",
            "aws_secret", "azure_key", "gcp_key",
            "kubernetes", "nginx", "apache",
            "requirements.txt", "go.mod", "pom.xml", "gemfile",
            "github_token", "slack_token", "stripe_key",
            "0.0.0.0", "verify=false",
        ],
        8: [
            "file", "upload", "download", "open(", "path", "shutil",
            "zip", "tar", "filesystem", "storage",
            "fopen", "readfile", "file_get_contents", "unlink",
            "mkdir", "rmdir", "copy(", "rename(", "scandir",
            "realpath", "basename", "dirname", "glob(",
            "tempfile", "symlink", "move_uploaded_file",
            "fs.readfile", "fs.writefile", "multipartfile",
            "filepath.join", "os.path",
            "../", "..\\", "extractto", "phar",
        ],
        9: [
            "order", "payment", "amount", "price", "inventory", "coupon",
            "workflow", "status", "balance", "logic",
            "refund", "withdraw", "deposit", "transfer",
            "invoice", "billing", "receipt", "tax",
            "discount", "promo", "voucher", "reward",
            "stock", "quantity", "merchant", "customer",
            "settlement", "commission", "profit",
            "approve", "reject", "cancel", "confirm",
            "points", "level", "vip", "membership",
            "quota", "threshold", "limit",
        ],
    }
    return rules.get(stage_num, [])

def _build_stage_focus_compact_context(
    stage,
    project,
    static_routes: list[dict],
    selected_chunks: list[dict],
    audit_memory: dict | None = None,
    rule_hits: list[dict] | None = None,
    source_sink_hints: list[dict] | None = None,
    forced_routes: list | None = None,
) -> dict:
    audit_memory = audit_memory or {}
    rule_hits = rule_hits or []
    source_sink_hints = source_sink_hints or []
    focus_file_limit = 32 if stage.stage_num == 6 else 40
    focus_files = _merge_unique_items([], [chunk.get("file_path", "") for chunk in selected_chunks if chunk.get("file_path")])[:focus_file_limit]
    topic_keywords = _get_stage_topic_keywords(stage.stage_num)
    focus_routes = [
        _route_with_id(route)
        for route in _select_stage_focus_routes(
            stage.stage_num,
            static_routes,
            audit_memory,
            focus_files,
            forced_routes=forced_routes,
        )
    ]
    route_lines = _format_static_route_lines(focus_routes, total_count=len(focus_routes))
    evidence_files = audit_memory.get("evidence_files", []) if isinstance(audit_memory.get("evidence_files"), list) else []
    route_inventory = audit_memory.get("route_inventory", []) if isinstance(audit_memory.get("route_inventory"), list) else []
    vulnerability_hints = audit_memory.get("vulnerability_hints", []) if isinstance(audit_memory.get("vulnerability_hints"), list) else []
    stage_vulnerability_hints = _select_stage_vulnerability_hints(stage.stage_num, vulnerability_hints)
    stage_rule_hits = _select_stage_rule_hits(stage.stage_num, rule_hits, focus_files)
    rule_hit_lines = _format_stage_rule_hit_lines(stage_rule_hits)
    stage_source_sink_hints = _select_stage_source_sink_hints(stage.stage_num, source_sink_hints, focus_files)
    source_sink_lines = _format_stage_source_sink_lines(stage_source_sink_hints)

    guidance = [
        f"当前阶段专题关键词：{', '.join(topic_keywords[:10])}" if topic_keywords else "当前阶段请严格聚焦本阶段目标，不要重复全局架构复述。",
        f"本轮重点文件数：{len(focus_files)}。",
        f"前序证据文件数：{len(evidence_files)}，路由库存数：{len(route_inventory)}，漏洞提示数：{len(vulnerability_hints)}。",
    ]
    if focus_routes:
        guidance.append(
            "本轮列出的每个 route_id 都必须在 route_coverage 数组中逐条回填。"
            "status 只能使用 audited_no_finding、finding、skipped_with_reason、insufficient_context 或 not_applicable；"
            "有漏洞时 status=finding，并确保 vulnerabilities[].endpoint 对应真实路由。"
        )
    if forced_routes:
        guidance.append(
            f"Forced route target count: {len(forced_routes)}. Prioritize these route targets when they appear in this stage route list and return route_coverage for each listed route_id."
        )
    if stage_rule_hits:
        guidance.append(f"规则预筛命中数：{len(stage_rule_hits)}，优先核查这些线索，再扩展到相邻调用链。")
    if stage_source_sink_hints:
        guidance.append(f"已注入轻量 source-sink 线索：{len(stage_source_sink_hints)}，优先验证这些可达路径，再扩展到相邻调用链。")
    if stage_vulnerability_hints:
        guidance.append(
            "阶段一未验证风险线索需强制复核："
            + "；".join(_format_stage_vulnerability_hint_lines(stage_vulnerability_hints))
            + "。请逐条给出 confirmed / ruled_out / insufficient_context 结论，不要只写笼统摘要。"
        )
    if stage.stage_num == 3:
        guidance.append(
            "阶段三需优先覆盖注入高风险链路：规则导入/规则变更、GORM Where/Raw/Exec、ClickHouse/Loki/PromQL 查询、LDAP SearchFilter、Redis/Lua/模板拼接、拨测创建参数。"
            "若只确认少量漏洞，也要在 stage_summary 中说明已排除的主要危险点和证据缺口。"
        )
    if stage.stage_num == 6:
        guidance.append("阶段六请只关注对象级授权、租户隔离、资源归属校验和越权访问链，不要重复展开登录认证流程。")
    if stage.stage_num == 9:
        guidance.append("阶段九请优先输出最强证据的业务逻辑漏洞，减少冗长背景描述，避免响应被截断。")
    if stage.stage_num == 3:
        guidance.append("阶段三请优先保证 JSON 完整闭合，再输出注入类漏洞细节。")
    if stage.stage_num == 8:
        guidance.append("阶段八请只保留证据最强的 3-4 个文件操作漏洞；若为同一路径遍历模式，合并为一条代表性结果。")
        guidance.append("阶段八的 architecture_info 仅保留最小必要入口、文件读写点和路径校验结论，不要展开冗长背景。")
        guidance.append("阶段八每条漏洞描述尽量精简，优先保留危险文件操作、可控参数、路径拼接方式和最小 PoC。")

    return {
        "project_tree_summary": _summarize_stage_focus_files(project.file_tree or [], focus_files, evidence_files),
        "route_lines": route_lines,
        "route_text_limit": 3600 if stage.stage_num == 6 else 5000,
        "route_intro": "以下仅保留与当前阶段专题高度相关的入口与路由证据，请结合源码核对，不要机械照抄。",
        "extra_guidance": "\n".join(guidance),
        "focus_files": focus_files,
        "focus_routes": focus_routes,
        "rule_hit_lines": rule_hit_lines[:12] if stage.stage_num == 6 else rule_hit_lines,
        "source_sink_lines": source_sink_lines,
    }

def _select_stage_source_sink_hints(stage_num: int, source_sink_hints: list[dict], focus_files: list[str], limit: int = 8) -> list[dict]:
    if not source_sink_hints:
        return []

    focus_set = {str(path).strip().lower() for path in focus_files if str(path).strip()}
    scored = []
    for hint in source_sink_hints:
        if not isinstance(hint, dict):
            continue
        stage_nums = hint.get("stage_nums", [])
        if isinstance(stage_nums, list) and stage_num not in stage_nums:
            continue
        file_path = str(hint.get("file_path", "") or "").strip()
        if not file_path:
            continue
        score = int(hint.get("risk_score", 0) or 0)
        if file_path.lower() in focus_set:
            score += 12
        scored.append((score, hint))

    scored.sort(key=lambda item: (-item[0], str(item[1].get("file_path", "")), str(item[1].get("label", ""))))
    return [hint for score, hint in scored[:limit] if score > 0]

def _format_stage_source_sink_lines(source_sink_hints: list[dict]) -> list[str]:
    lines = []
    for hint in source_sink_hints:
        if not isinstance(hint, dict):
            continue
        routes = ",".join((hint.get("route_paths") or [])[:3]) if isinstance(hint.get("route_paths"), list) else ""
        sources = ",".join((hint.get("source_types") or [])[:3]) if isinstance(hint.get("source_types"), list) else ""
        sinks = ",".join((hint.get("sink_keywords") or [])[:4]) if isinstance(hint.get("sink_keywords"), list) else ""
        lines.append(
            "- "
            + f"{hint.get('title', 'source-sink hint')} | file={hint.get('file_path', '')} | "
            + f"sources={sources} | sinks={sinks} | routes={routes} | "
            + f"evidence={str(hint.get('evidence', '')).replace(chr(10), ' / ')}"
        )
    return lines

def _select_stage_vulnerability_hints(stage_num: int, hints: list[dict], limit: int = 6) -> list[dict]:
    if not hints:
        return []

    topic_keywords = set(_get_stage_topic_keywords(stage_num))
    scored: list[tuple[int, dict]] = []
    for hint in hints:
        if not isinstance(hint, dict):
            continue
        stage_nums = _normalize_stage_num_list(hint.get("stage_nums"), hint.get("suggested_stage_nums"))
        if isinstance(stage_nums, list) and stage_nums and stage_num not in stage_nums:
            continue
        text = " ".join(
            str(hint.get(key, "") or "").lower()
            for key in ["title", "vuln_type", "description", "file_path", "endpoint"]
        )
        score = 0
        if stage_num in stage_nums:
            score += 20
        for keyword in topic_keywords:
            if keyword and keyword.lower() in text:
                score += 3
        if stage_num == 3 and any(marker in text for marker in ["sql", "query", "mybatis", "${", "queryparser", "queryinfo", "动态查询", "注入"]):
            score += 20
        if stage_num == 5 and any(marker in text for marker in ["captcha", "验证码", "jwt", "token", "login", "登录", "password"]):
            score += 20
        if stage_num == 6 and any(marker in text for marker in ["preauthorize", "enablemethodsecurity", "权限", "越权", "授权", "idor"]):
            score += 20
        if stage_num == 8 and any(marker in text for marker in ["file", "upload", "download", "path", "文件", "上传", "下载", "路径"]):
            score += 20
        if score > 0:
            scored.append((score, hint))

    scored.sort(
        key=lambda item: (
            -item[0],
            str(item[1].get("file_path", "")),
            str(item[1].get("title", "")),
        )
    )
    return [hint for _, hint in scored[:limit]]

def _format_stage_vulnerability_hint_lines(hints: list[dict]) -> list[str]:
    lines = []
    for hint in hints:
        if not isinstance(hint, dict):
            continue
        title = str(hint.get("title", "") or hint.get("vuln_type", "") or "未命名风险线索").strip()
        file_path = str(hint.get("file_path", "") or "").strip()
        description = str(hint.get("description", "") or "").strip().replace("\n", " ")
        line = title[:80]
        if file_path:
            line += f" | file={file_path[:140]}"
        if description:
            line += f" | evidence={description[:180]}"
        lines.append(line)
    return lines

def _compact_audit_memory_for_stage(stage_num: int, audit_memory: dict) -> dict:
    if not isinstance(audit_memory, dict):
        return {}
    if stage_num in {2, 3, 4}:
        return {
            "completed_stage_count": audit_memory.get("completed_stage_count", 0),
            "stages": audit_memory.get("stages", [])[-4:] if isinstance(audit_memory.get("stages"), list) else [],
            "evidence_files": (audit_memory.get("evidence_files") or [])[:20],
            "route_inventory": (audit_memory.get("route_inventory") or [])[:32] if isinstance(audit_memory.get("route_inventory"), list) else [],
            "entry_points": (audit_memory.get("entry_points") or [])[:16] if isinstance(audit_memory.get("entry_points"), list) else [],
            "modules": (audit_memory.get("modules") or [])[:16] if isinstance(audit_memory.get("modules"), list) else [],
            "data_flows": (audit_memory.get("data_flows") or [])[:12] if isinstance(audit_memory.get("data_flows"), list) else [],
            "vulnerability_hints": (audit_memory.get("vulnerability_hints") or [])[:8] if isinstance(audit_memory.get("vulnerability_hints"), list) else [],
        }
    if stage_num == 7:
        return {
            "completed_stage_count": audit_memory.get("completed_stage_count", 0),
            "stages": audit_memory.get("stages", [])[-4:] if isinstance(audit_memory.get("stages"), list) else [],
            "evidence_files": (audit_memory.get("evidence_files") or [])[:16],
            "route_inventory": (audit_memory.get("route_inventory") or [])[:24] if isinstance(audit_memory.get("route_inventory"), list) else [],
            "modules": (audit_memory.get("modules") or [])[:16] if isinstance(audit_memory.get("modules"), list) else [],
            "vulnerability_hints": (audit_memory.get("vulnerability_hints") or [])[:6] if isinstance(audit_memory.get("vulnerability_hints"), list) else [],
        }
    if stage_num == 5:
        return {
            "completed_stage_count": audit_memory.get("completed_stage_count", 0),
            "stages": audit_memory.get("stages", [])[-3:] if isinstance(audit_memory.get("stages"), list) else [],
            "evidence_files": (audit_memory.get("evidence_files") or [])[:12],
            "route_inventory": (audit_memory.get("route_inventory") or [])[:20] if isinstance(audit_memory.get("route_inventory"), list) else [],
            "entry_points": (audit_memory.get("entry_points") or [])[:10] if isinstance(audit_memory.get("entry_points"), list) else [],
            "modules": (audit_memory.get("modules") or [])[:10] if isinstance(audit_memory.get("modules"), list) else [],
            "data_flows": (audit_memory.get("data_flows") or [])[:8] if isinstance(audit_memory.get("data_flows"), list) else [],
            "vulnerability_hints": (audit_memory.get("vulnerability_hints") or [])[:5] if isinstance(audit_memory.get("vulnerability_hints"), list) else [],
        }
    if stage_num == 6:
        return {
            "completed_stage_count": audit_memory.get("completed_stage_count", 0),
            "stages": audit_memory.get("stages", [])[-5:] if isinstance(audit_memory.get("stages"), list) else [],
            "evidence_files": (audit_memory.get("evidence_files") or [])[:24],
            "route_inventory": (audit_memory.get("route_inventory") or [])[:40] if isinstance(audit_memory.get("route_inventory"), list) else [],
            "entry_points": (audit_memory.get("entry_points") or [])[:20] if isinstance(audit_memory.get("entry_points"), list) else [],
            "modules": (audit_memory.get("modules") or [])[:20] if isinstance(audit_memory.get("modules"), list) else [],
            "data_flows": (audit_memory.get("data_flows") or [])[:16] if isinstance(audit_memory.get("data_flows"), list) else [],
            "vulnerability_hints": (audit_memory.get("vulnerability_hints") or [])[:10] if isinstance(audit_memory.get("vulnerability_hints"), list) else [],
        }
    if stage_num == 8:
        return {
            "completed_stage_count": audit_memory.get("completed_stage_count", 0),
            "stages": audit_memory.get("stages", [])[-4:] if isinstance(audit_memory.get("stages"), list) else [],
            "evidence_files": (audit_memory.get("evidence_files") or [])[:20],
            "route_inventory": (audit_memory.get("route_inventory") or [])[:40] if isinstance(audit_memory.get("route_inventory"), list) else [],
            "modules": (audit_memory.get("modules") or [])[:20] if isinstance(audit_memory.get("modules"), list) else [],
            "data_flows": (audit_memory.get("data_flows") or [])[:20] if isinstance(audit_memory.get("data_flows"), list) else [],
            "vulnerability_hints": (audit_memory.get("vulnerability_hints") or [])[:12] if isinstance(audit_memory.get("vulnerability_hints"), list) else [],
        }
    compact = {
        "completed_stage_count": audit_memory.get("completed_stage_count", 0),
        "stages": audit_memory.get("stages", [])[-6:] if isinstance(audit_memory.get("stages"), list) else [],
        "evidence_files": (audit_memory.get("evidence_files") or [])[:30],
    }

    route_inventory = audit_memory.get("route_inventory", [])
    if isinstance(route_inventory, list):
        compact["route_inventory"] = route_inventory[:80]
    for key in ["modules", "data_flows", "entry_points", "output_points"]:
        value = audit_memory.get(key)
        if isinstance(value, list):
            compact[key] = value[:30]
    vulnerability_hints = audit_memory.get("vulnerability_hints")
    if isinstance(vulnerability_hints, list):
        compact["vulnerability_hints"] = vulnerability_hints[:20]
    return compact

def _route_key_for_focus(route: dict | None) -> tuple[str, str]:
    route = route if isinstance(route, dict) else {}
    method = str(route.get("method", "UNKNOWN") or "UNKNOWN").strip().upper()
    path = str(route.get("path", "") or "").strip()
    return method, path


def _route_target_sets(route_targets: list | None) -> dict[str, set]:
    target_ids: set[str] = set()
    method_paths: set[tuple[str, str]] = set()
    any_paths: set[str] = set()

    if not isinstance(route_targets, list):
        return {"ids": target_ids, "method_paths": method_paths, "any_paths": any_paths}

    for target in route_targets:
        if isinstance(target, dict):
            route_id = str(target.get("route_id", "") or "").strip()
            if route_id:
                target_ids.add(route_id)
            method, path = _route_key_for_focus(target)
            if path:
                if method and method != "UNKNOWN":
                    method_paths.add((method, path))
                any_paths.add(path)
            continue

        text = str(target or "").strip()
        if not text:
            continue
        parts = text.split(None, 1)
        if len(parts) == 2 and parts[0].upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ANY"}:
            method = parts[0].upper()
            path = parts[1].strip()
            if method == "ANY":
                any_paths.add(path)
            else:
                method_paths.add((method, path))
                any_paths.add(path)
        else:
            any_paths.add(text)

    return {"ids": target_ids, "method_paths": method_paths, "any_paths": any_paths}


def _matches_route_targets(route: dict, target_sets: dict[str, set]) -> bool:
    route_id = str(route.get("route_id", "") or _route_id(route)).strip()
    method, path = _route_key_for_focus(route)
    return (
        route_id in target_sets.get("ids", set())
        or (method, path) in target_sets.get("method_paths", set())
        or path in target_sets.get("any_paths", set())
    )


def _merge_routes_for_focus(*groups: list[dict], limit: int = 24) -> list[dict]:
    selected: list[dict] = []
    seen_ids: set[str] = set()
    seen_keys: set[tuple[str, str]] = set()

    for group in groups:
        for route in group or []:
            if not isinstance(route, dict):
                continue
            normalized = _route_with_id(route)
            if not str(normalized.get("path", "") or "").strip():
                continue
            route_id = str(normalized.get("route_id", "") or "").strip()
            route_key = _route_key_for_focus(normalized)
            if route_id in seen_ids or route_key in seen_keys:
                continue
            seen_ids.add(route_id)
            seen_keys.add(route_key)
            selected.append(normalized)
            if len(selected) >= limit:
                return selected

    return selected


def _select_stage_focus_routes(
    stage_num: int,
    static_routes: list[dict],
    audit_memory: dict,
    focus_files: list[str],
    forced_routes: list | None = None,
) -> list[dict]:
    if not static_routes:
        return []

    audit_memory = audit_memory if isinstance(audit_memory, dict) else {}
    topic_keywords = _get_stage_topic_keywords(stage_num)
    focus_set = {str(path or "").strip().lower() for path in focus_files if str(path or "").strip()}
    evidence_files = {
        str(path or "").strip().lower()
        for path in (audit_memory.get("evidence_files", []) if isinstance(audit_memory.get("evidence_files"), list) else [])
        if str(path or "").strip()
    }
    inventory_routes = audit_memory.get("route_inventory", []) if isinstance(audit_memory.get("route_inventory"), list) else []
    inventory_keys = {
        _route_key_for_focus(route)
        for route in inventory_routes
        if isinstance(route, dict) and str(route.get("path", "") or "").strip()
    }
    audited_routes = audit_memory.get("audited_route_inventory", []) if isinstance(audit_memory.get("audited_route_inventory"), list) else []
    audited_keys = {
        _route_key_for_focus(route)
        for route in audited_routes
        if isinstance(route, dict) and str(route.get("path", "") or "").strip()
    }
    audited_ids = {
        str(route.get("route_id", "") or _route_id(route)).strip()
        for route in audited_routes
        if isinstance(route, dict) and str(route.get("path", "") or "").strip()
    }
    forced_target_sets = _route_target_sets(forced_routes)

    scored: list[dict] = []
    for index, raw_route in enumerate(static_routes):
        if not isinstance(raw_route, dict):
            continue
        route = _route_with_id(raw_route)
        if not str(route.get("path", "") or "").strip():
            continue
        file_path = str(route.get("file_path", "") or "")
        normalized_file_path = file_path.strip().lower()
        haystack = "\n".join([
            str(route.get("method", "")),
            str(route.get("path", "")),
            str(route.get("handler", "")),
            file_path,
            str(route.get("auth", "")),
        ]).lower()
        evidence_score = 0
        stage_specific_score = 0
        if any(keyword in haystack for keyword in topic_keywords):
            evidence_score += 5
            stage_specific_score += 5
        if normalized_file_path in focus_set:
            evidence_score += 4
            stage_specific_score += 4
        if normalized_file_path in evidence_files:
            evidence_score += 3
            stage_specific_score += 3
        route_key = _route_key_for_focus(route)
        if route_key in inventory_keys:
            evidence_score += 2

        priority = _route_priority_score(route)
        route_id = str(route.get("route_id", "") or "").strip()
        is_audited = route_key in audited_keys or route_id in audited_ids
        is_forced = _matches_route_targets(route, forced_target_sets)
        shard_index = max(0, min(7, int(stage_num or 0) - 2))
        in_stage_shard = (index % 8) == shard_index
        scored.append(
            {
                "route": route,
                "evidence_score": evidence_score,
                "stage_specific_score": stage_specific_score,
                "priority": priority,
                "is_audited": is_audited,
                "is_forced": is_forced,
                "in_stage_shard": in_stage_shard,
            }
        )

    sort_key = lambda item: (
        -int(item["evidence_score"]),
        -int(item["priority"]),
        item["route"].get("path", ""),
        item["route"].get("method", ""),
    )
    forced = sorted([item["route"] for item in scored if item["is_forced"]], key=lambda route: (-_route_priority_score(route), route.get("path", ""), route.get("method", "")))
    relevant = [item["route"] for item in sorted(scored, key=sort_key) if item["stage_specific_score"] > 0 and not item["is_audited"]]
    shard_fill = [
        item["route"]
        for item in sorted(scored, key=lambda item: (-int(item["priority"]), item["route"].get("path", ""), item["route"].get("method", "")))
        if item["in_stage_shard"] and not item["is_audited"]
    ]
    unaudited_high = [
        item["route"]
        for item in sorted(scored, key=lambda item: (-int(item["priority"]), item["route"].get("path", ""), item["route"].get("method", "")))
        if not item["is_audited"]
    ]
    audited_high = [
        item["route"]
        for item in sorted(scored, key=lambda item: (-int(item["priority"]), item["route"].get("path", ""), item["route"].get("method", "")))
        if item["is_audited"]
    ]

    return _merge_routes_for_focus(
        forced[:8],
        relevant[:10],
        shard_fill[:10],
        unaudited_high[:24],
        audited_high[:12],
        limit=24,
    )

def _summarize_stage_focus_files(tree: list, focus_files: list[str], evidence_files: list[str]) -> str:
    if not focus_files:
        return _summarize_project_tree(tree, limit=100)
    lines = ["- 当前阶段重点文件："]
    for path in focus_files[:30]:
        marker = " [evidence]" if path in evidence_files else ""
        lines.append(f"  - {path}{marker}")
    if evidence_files:
        lines.append(f"- 前序证据文件数：{len(evidence_files)}")
    return "\n".join(lines)

def _select_stage_rule_hits(stage_num: int, rule_hits: list[dict], focus_files: list[str], limit: int = 10) -> list[dict]:
    if not rule_hits:
        return []

    focus_set = {str(path).strip().lower() for path in focus_files if str(path).strip()}
    scored = []
    for hit in rule_hits:
        if not isinstance(hit, dict):
            continue
        file_path = str(hit.get("file_path", "")).strip()
        if not file_path:
            continue
        score = int(hit.get("risk_score", 0) or 0)
        stage_nums = hit.get("stage_nums", [])
        if isinstance(stage_nums, list) and stage_num in stage_nums:
            score += 8
        if file_path.lower() in focus_set:
            score += 6
        if any(keyword in str(hit.get("label", "")).lower() for keyword in _get_stage_topic_keywords(stage_num)[:6]):
            score += 2
        scored.append((score, hit))

    scored.sort(key=lambda item: (-item[0], str(item[1].get("file_path", "")), str(item[1].get("label", ""))))
    return [hit for _, hit in scored[:limit] if _ > 0]

def _format_stage_rule_hit_lines(rule_hits: list[dict]) -> list[str]:
    lines = []
    for hit in rule_hits:
        if not isinstance(hit, dict):
            continue
        lines.append(
            "- "
            + f"{hit.get('title', '规则命中')} | file={hit.get('file_path', '')} | "
            + f"chunk={hit.get('chunk_path', '')} | score={hit.get('risk_score', 0)} | "
            + f"evidence={str(hit.get('evidence', '')).replace(chr(10), ' / ')}"
        )
    return lines

def _build_prev_context(audit_memory: dict) -> str:
    if not audit_memory:
        return ""
    return _truncate_text(json.dumps(audit_memory, ensure_ascii=False, indent=2), 12000)

def _build_audit_memory(stages: list[AuditStage], current_stage_num: int | None = None) -> dict:
    completed_stages = []
    route_inventory = []
    audited_route_inventory = []
    modules = []
    data_flows = []
    entry_points = []
    output_points = []
    vulnerability_hints = []
    evidence_files = []
    architecture_summary = {}

    for stage in sorted(stages, key=lambda item: item.stage_num):
        if current_stage_num is not None and stage.stage_num == current_stage_num:
            continue
        if stage.status != "completed":
            continue

        findings = _coerce_stage_findings(stage.findings)
        compressed = stage.compressed_summary if isinstance(stage.compressed_summary, dict) else {}
        architecture_info = findings.get("architecture_info") if isinstance(findings.get("architecture_info"), dict) else {}
        if not architecture_info and isinstance(compressed.get("architecture_info"), dict):
            architecture_info = compressed.get("architecture_info", {})
        stage_coverage = compressed.get("_stage_coverage", {}) if isinstance(compressed.get("_stage_coverage"), dict) else {}

        stage_vulns = findings.get("vulnerabilities", [])
        if not isinstance(stage_vulns, list):
            stage_vulns = []
        stage_risk_hints = []
        if stage.stage_num == 1:
            hint_payload = {"risk_hints": [], "vulnerability_hints": []}
            for source in [findings, compressed]:
                if not isinstance(source, dict):
                    continue
                for key in ["risk_hints", "vulnerability_hints"]:
                    value = source.get(key)
                    if isinstance(value, list):
                        hint_payload[key].extend(value)
            stage_risk_hints = _collect_stage1_risk_hints(hint_payload)

        stage_summary = str(
            compressed.get("stage_summary")
            or findings.get("stage_summary")
            or ""
        ).strip()

        stage_record = {
            "stage_num": stage.stage_num,
            "stage_name": stage.stage_name,
            "stage_summary": stage_summary[:1200],
            "vulnerability_count": len(stage_vulns),
            "high_severity_count": sum(
                1 for vuln in stage_vulns if str(vuln.get("severity", "")).strip() in {"Critical", "High"}
            ),
            "audited_route_count": len(stage_coverage.get("focus_routes", [])) if isinstance(stage_coverage.get("focus_routes"), list) else 0,
            "files": _merge_unique_items(
                [],
                [vuln.get("file_path", "") for vuln in stage_vulns if isinstance(vuln, dict) and vuln.get("file_path")]
                + [route.get("file_path", "") for route in architecture_info.get("routes", []) if isinstance(route, dict) and route.get("file_path")]
                + list((compressed.get("coverage", {}) or {}).get("covered_paths", []) if isinstance(compressed.get("coverage"), dict) else []),
            )[:20],
        }

        completed_stages.append(stage_record)
        if not architecture_summary and architecture_info:
            architecture_summary = _summarize_architecture_info(architecture_info)
        route_inventory = _merge_unique_items(route_inventory, architecture_info.get("routes"))
        if isinstance(route_inventory, list):
            route_inventory = sorted(
                [item for item in route_inventory if isinstance(item, dict)],
                key=lambda item: (-_route_priority_score(item), item.get("path", ""), item.get("method", ""), item.get("handler", "")),
            )
        audited_route_inventory = _merge_unique_items(audited_route_inventory, stage_coverage.get("focus_routes"))
        modules = _merge_unique_items(modules, architecture_info.get("modules"))
        data_flows = _merge_unique_items(data_flows, architecture_info.get("data_flows"))
        entry_points = _merge_unique_items(entry_points, architecture_info.get("entry_points"))
        output_points = _merge_unique_items(output_points, architecture_info.get("output_points"))
        vulnerability_hints = _merge_vulnerability_lists(
            vulnerability_hints,
            stage_risk_hints
            or (compressed.get("vulnerability_hints") if isinstance(compressed.get("vulnerability_hints"), list) else stage_vulns),
        )[:30]
        evidence_files = _merge_unique_items(evidence_files, stage_record["files"])[:40]

    return {
        "completed_stage_count": len(completed_stages),
        "stages": completed_stages[-8:],
        "architecture_info": architecture_summary,
        "route_inventory": route_inventory[:200],
        "audited_route_inventory": audited_route_inventory[:200],
        "modules": modules[:80],
        "data_flows": data_flows[:80],
        "entry_points": entry_points[:80],
        "output_points": output_points[:80],
        "vulnerability_hints": vulnerability_hints[:30],
        "evidence_files": evidence_files[:40],
    }

__all__ = [
    '_build_incomplete_json_retry_prompt',
    '_build_exploit_stage_skeleton_retry_prompt',
    '_build_stage9_skeleton_retry_prompt',
    '_build_stage5_skeleton_retry_prompt',
    '_build_lightweight_stage_skeleton_retry_prompt',
    '_build_summary_stage_skeleton_retry_prompt',
    '_format_chunks_for_prompt',
    '_format_stage1_chunks_for_prompt',
    '_format_non_stage1_chunks_for_prompt',
    '_format_prompt_chunk_entry',
    '_format_compacted_chunk_entry',
    '_extract_compacted_excerpt',
    '_extract_signal_excerpt',
    '_extract_stage_focus_excerpt',
    '_extract_keyword_excerpt',
    '_build_stage_user_prompt',
    '_build_stage1_microcompact_context',
    '_summarize_focus_files',
    '_format_static_route_lines',
    '_select_route_delta_lines',
    '_summarize_project_tree',
    '_get_stage_topic_keywords',
    '_build_stage_focus_compact_context',
    '_select_stage_source_sink_hints',
    '_format_stage_source_sink_lines',
    '_select_stage_vulnerability_hints',
    '_format_stage_vulnerability_hint_lines',
    '_compact_audit_memory_for_stage',
    '_select_stage_focus_routes',
    '_summarize_stage_focus_files',
    '_select_stage_rule_hits',
    '_format_stage_rule_hit_lines',
    '_build_prev_context',
    '_build_audit_memory',
]

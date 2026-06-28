"""Prompt-budget appliers per stage class."""

from __future__ import annotations

from services.ai_engine._utils import _truncate_text

import logging

logger = logging.getLogger(__name__)

def _apply_exploit_stage_prompt_budget(
    compact_context: dict | None,
    code_text: str,
    prev_context: str,
    stage_num: int,
    aggressive: bool = False,
) -> tuple[dict, str, str]:
    compact_context = dict(compact_context or {})
    compact_context["response_mode"] = "index_first"
    code_limit = 12000 if aggressive else 18000
    prev_limit = 700 if aggressive else 1200
    route_limit = 5 if aggressive else 8
    route_text_limit = 1400 if aggressive else 2200
    rule_hit_limit = 4 if aggressive else 6
    focus_file_limit = 16 if aggressive else 24

    compact_context["route_lines"] = (compact_context.get("route_lines") or [])[:route_limit]
    compact_context["route_text_limit"] = min(int(compact_context.get("route_text_limit", route_text_limit) or route_text_limit), route_text_limit)
    compact_context["rule_hit_lines"] = (compact_context.get("rule_hit_lines") or [])[:rule_hit_limit]
    compact_context["focus_files"] = (compact_context.get("focus_files") or [])[:focus_file_limit]

    extra_guidance = str(compact_context.get("extra_guidance", "") or "").strip()
    stage_label = "阶段二" if stage_num == 2 else "阶段三/四/八"
    budget_guidance = (
        f"{stage_label} 请优先压缩输出，先保证完整 JSON 闭合。"
        "architecture_info 仅保留最关键入口、框架和约束信息；"
        "vulnerabilities 优先保留 title、severity、vuln_type、file_path、endpoint、description 和可复现 PoC，压缩背景说明，不要压缩请求行、Host、必要 Header、请求体或关键复现步骤。"
    )
    compact_context["extra_guidance"] = "\n".join(part for part in [extra_guidance, budget_guidance] if part)

    return compact_context, _truncate_text(code_text or "", code_limit), _truncate_text(prev_context or "", prev_limit)

def _apply_stage5_prompt_budget(
    compact_context: dict | None,
    code_text: str,
    prev_context: str,
    aggressive: bool = False,
) -> tuple[dict, str, str]:
    compact_context = dict(compact_context or {})
    compact_context["response_mode"] = "index_first"
    code_limit = 9000 if aggressive else 14000
    prev_limit = 500 if aggressive else 900
    route_limit = 4 if aggressive else 6
    route_text_limit = 1000 if aggressive else 1600
    rule_hit_limit = 3 if aggressive else 5
    focus_file_limit = 12 if aggressive else 18
    audit_memory_limit = 1400 if aggressive else 2200

    compact_context["route_lines"] = (compact_context.get("route_lines") or [])[:route_limit]
    compact_context["route_text_limit"] = min(int(compact_context.get("route_text_limit", route_text_limit) or route_text_limit), route_text_limit)
    compact_context["rule_hit_lines"] = (compact_context.get("rule_hit_lines") or [])[:rule_hit_limit]
    compact_context["focus_files"] = (compact_context.get("focus_files") or [])[:focus_file_limit]
    compact_context["audit_memory_limit"] = min(int(compact_context.get("audit_memory_limit", audit_memory_limit) or audit_memory_limit), audit_memory_limit)

    extra_guidance = str(compact_context.get("extra_guidance", "") or "").strip()
    budget_guidance = (
        "阶段五请压缩认证与会话背景描述，先保证完整 JSON。"
        "architecture_info 只保留认证机制、令牌/会话线索和关键入口；"
        "vulnerabilities 优先保留 title、severity、vuln_type、file_path、endpoint、description 和可复现 PoC，压缩背景说明，不要压缩关键请求行或核心复现步骤。"
        "首轮不要展开登录、注册、找回密码、刷新令牌、验证码的完整链路。"
    )
    compact_context["extra_guidance"] = "\n".join(part for part in [extra_guidance, budget_guidance] if part)

    return compact_context, _truncate_text(code_text or "", code_limit), _truncate_text(prev_context or "", prev_limit)

def _apply_stage6_prompt_budget(
    compact_context: dict | None,
    code_text: str,
    prev_context: str,
    aggressive: bool = False,
) -> tuple[dict, str, str]:
    compact_context = dict(compact_context or {})
    code_limit = 16000 if aggressive else 24000
    prev_limit = 900 if aggressive else 1600
    route_limit = 6 if aggressive else 10
    route_text_limit = 1800 if aggressive else 2800
    rule_hit_limit = 6 if aggressive else 10
    focus_file_limit = 20 if aggressive else 28

    compact_context["route_lines"] = (compact_context.get("route_lines") or [])[:route_limit]
    compact_context["route_text_limit"] = min(int(compact_context.get("route_text_limit", route_text_limit) or route_text_limit), route_text_limit)
    compact_context["rule_hit_lines"] = (compact_context.get("rule_hit_lines") or [])[:rule_hit_limit]
    compact_context["focus_files"] = (compact_context.get("focus_files") or [])[:focus_file_limit]

    extra_guidance = str(compact_context.get("extra_guidance", "") or "").strip()
    budget_guidance = (
        "阶段六请优先保留对象级授权、资源归属校验、tenant 约束和可形成越权链的最强证据；"
        "不要展开登录、注册、找回密码、验证码等认证背景。"
    )
    compact_context["extra_guidance"] = "\n".join(part for part in [extra_guidance, budget_guidance] if part)

    return compact_context, _truncate_text(code_text or "", code_limit), _truncate_text(prev_context or "", prev_limit)

def _apply_stage9_prompt_budget(
    compact_context: dict | None,
    code_text: str,
    prev_context: str,
    aggressive: bool = False,
) -> tuple[dict, str, str]:
    compact_context = dict(compact_context or {})
    compact_context["response_mode"] = "index_first"
    code_limit = 12000 if aggressive else 18000
    prev_limit = 700 if aggressive else 1200
    route_limit = 5 if aggressive else 8
    route_text_limit = 1400 if aggressive else 2200
    rule_hit_limit = 4 if aggressive else 6
    focus_file_limit = 16 if aggressive else 24

    compact_context["route_lines"] = (compact_context.get("route_lines") or [])[:route_limit]
    compact_context["route_text_limit"] = min(int(compact_context.get("route_text_limit", route_text_limit) or route_text_limit), route_text_limit)
    compact_context["rule_hit_lines"] = (compact_context.get("rule_hit_lines") or [])[:rule_hit_limit]
    compact_context["focus_files"] = (compact_context.get("focus_files") or [])[:focus_file_limit]

    extra_guidance = str(compact_context.get("extra_guidance", "") or "").strip()
    budget_guidance = (
        "阶段九首轮只保留最强业务逻辑漏洞索引，不要铺陈业务背景。"
        "architecture_info 仅保留最关键入口、核心约束和受影响对象。"
        "vulnerabilities 优先保留 title、severity、vuln_type、file_path、endpoint、简短 description 和可复现 PoC，压缩背景说明，不要压缩关键复现步骤。"
    )
    compact_context["extra_guidance"] = "\n".join(part for part in [extra_guidance, budget_guidance] if part)

    return compact_context, _truncate_text(code_text or "", code_limit), _truncate_text(prev_context or "", prev_limit)

def _apply_lightweight_stage_prompt_budget(
    compact_context: dict | None,
    code_text: str,
    prev_context: str,
    stage_num: int,
    aggressive: bool = False,
) -> tuple[dict, str, str]:
    compact_context = dict(compact_context or {})
    compact_context["response_mode"] = "index_first"
    code_limit = 9000 if aggressive else 14000
    prev_limit = 500 if aggressive else 1000
    route_limit = 4 if aggressive else 6
    route_text_limit = 1200 if aggressive else 1800
    focus_file_limit = 12 if aggressive else 18

    compact_context["route_lines"] = (compact_context.get("route_lines") or [])[:route_limit]
    compact_context["route_text_limit"] = min(int(compact_context.get("route_text_limit", route_text_limit) or route_text_limit), route_text_limit)
    compact_context["rule_hit_lines"] = (compact_context.get("rule_hit_lines") or [])[:4]
    compact_context["focus_files"] = (compact_context.get("focus_files") or [])[:focus_file_limit]

    extra_guidance = str(compact_context.get("extra_guidance", "") or "").strip()
    stage_label = f"阶段{stage_num}"
    budget_guidance = (
        f"{stage_label} 请优先保证 JSON 完整闭合，减少背景铺陈。"
        "architecture_info 和 vulnerabilities 都只保留最小必要信息。"
    )
    compact_context["extra_guidance"] = "\n".join(part for part in [extra_guidance, budget_guidance] if part)

    return compact_context, _truncate_text(code_text or "", code_limit), _truncate_text(prev_context or "", prev_limit)

__all__ = [
    '_apply_exploit_stage_prompt_budget',
    '_apply_stage5_prompt_budget',
    '_apply_stage6_prompt_budget',
    '_apply_stage9_prompt_budget',
    '_apply_lightweight_stage_prompt_budget',
]

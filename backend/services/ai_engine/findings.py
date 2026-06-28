"""Finding coercion, Stage-1 risk-hint collection, and quality-gate text helpers."""

from __future__ import annotations

from models import Vulnerability
from vulnerability_normalization import is_unknown_placeholder, normalize_vulnerability_fields

from services.ai_engine._utils import _normalize_stage_num_list
from services.ai_engine.severity import SEVERITY_ORDER, _normalize_confidence, _normalize_severity
from services.ai_engine.vulnerability_store import _merge_vulnerability_lists

import logging

logger = logging.getLogger(__name__)

STAGE1_RISK_HINT_LIMIT = 40

def _coerce_stage_findings(findings):
    if isinstance(findings, dict):
        return findings
    if isinstance(findings, list):
        return {"vulnerabilities": findings}
    return {}

def _collect_stage1_risk_hints(response: dict | list | None) -> list[dict]:
    candidates = []
    if isinstance(response, list):
        candidates.extend(response)
    elif isinstance(response, dict):
        for key in ["risk_hints", "vulnerability_hints", "vulnerabilities"]:
            value = response.get(key)
            if isinstance(value, list):
                candidates.extend(value)

    hints = []
    for item in candidates:
        hint = _normalize_stage1_risk_hint(item)
        if hint:
            hints.append(hint)
    return _merge_vulnerability_lists([], hints)[:STAGE1_RISK_HINT_LIMIT]

def _normalize_stage1_risk_hint(item) -> dict | None:
    if isinstance(item, str):
        text = item.strip()
        if not text:
            return None
        return {
            "title": text[:160],
            "severity": "Info",
            "vuln_type": "未验证风险线索",
            "confidence": "low",
            "description": text[:1000],
            "source": "stage1_architecture",
            "validation_status": "unverified",
            "is_formal_vulnerability": False,
        }
    if not isinstance(item, dict):
        return None

    hint = normalize_vulnerability_fields(item)
    title = str(hint.get("title", "") or "").strip()
    vuln_type = str(hint.get("vuln_type", "") or "").strip()
    description = str(hint.get("description", "") or "").strip()
    if is_unknown_placeholder(title):
        title = vuln_type if not is_unknown_placeholder(vuln_type) else ""
    if is_unknown_placeholder(title) and description:
        title = description[:80]
    if is_unknown_placeholder(title):
        title = "未命名风险线索"
    if is_unknown_placeholder(vuln_type):
        vuln_type = "未验证风险线索"

    hint["title"] = title
    hint["vuln_type"] = vuln_type
    hint["severity"] = _normalize_severity(str(hint.get("severity", "Info") or "Info"))
    hint["confidence"] = _normalize_confidence(hint.get("confidence"))
    hint["source"] = "stage1_architecture"
    hint["validation_status"] = "unverified"
    hint["is_formal_vulnerability"] = False
    stage_nums = _normalize_stage_num_list(hint.get("stage_nums"), hint.get("suggested_stage_nums"))
    if stage_nums:
        hint["stage_nums"] = stage_nums
        hint["suggested_stage_nums"] = stage_nums
    hint.pop("_poc_validation", None)
    return hint

def _stage1_response_with_risk_hints(response: dict | list | None) -> dict:
    if isinstance(response, dict):
        normalized = dict(response)
    else:
        normalized = {
            "stage_summary": "",
            "architecture_info": {},
        }

    normalized["risk_hints"] = _collect_stage1_risk_hints(response)
    normalized["vulnerabilities"] = []
    normalized.pop("_invalid_poc_vulnerabilities", None)
    return normalized

def _build_task_severity_stats(vulns: list[Vulnerability]) -> dict:
    stats = {sev: 0 for sev in SEVERITY_ORDER}
    for vuln in vulns:
        severity = getattr(vuln, "severity", None)
        if severity in stats:
            stats[severity] += 1
    return stats

__all__ = [
    'STAGE1_RISK_HINT_LIMIT',
    '_coerce_stage_findings',
    '_collect_stage1_risk_hints',
    '_normalize_stage1_risk_hint',
    '_stage1_response_with_risk_hints',
    '_build_task_severity_stats',
]

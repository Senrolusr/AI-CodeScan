"""Severity / confidence normalization and SQL ordering helpers."""

from __future__ import annotations

from sqlalchemy import case

import logging

logger = logging.getLogger(__name__)

SEVERITY_ALIASES = {
    "critical": "Critical", "严重": "Critical",
    "high": "High", "高危": "High", "高": "High",
    "medium": "Medium", "中危": "Medium", "中": "Medium",
    "low": "Low", "低危": "Low", "低": "Low",
    "info": "Info", "提示": "Info", "信息": "Info", "informational": "Info",
}

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}

CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}

def _normalize_severity(severity: str) -> str:
    if not severity:
        return "Medium"
    stripped = severity.strip()
    if stripped in VALID_SEVERITIES:
        return stripped
    return SEVERITY_ALIASES.get(stripped.lower(), SEVERITY_ALIASES.get(stripped, "Medium"))

def _severity_match_values(severity: str) -> list[str]:
    normalized = _normalize_severity(severity)
    aliases = [k for k, v in SEVERITY_ALIASES.items() if v == normalized]
    return list(set([normalized] + aliases))

def _severity_order_expr(column):
    return case(
        (column.in_(_severity_match_values("Critical")), 5),
        (column.in_(_severity_match_values("High")), 4),
        (column.in_(_severity_match_values("Medium")), 3),
        (column.in_(_severity_match_values("Low")), 2),
        (column.in_(_severity_match_values("Info")), 1),
        else_=0,
    )

def _normalize_confidence(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in CONFIDENCE_RANK:
        return normalized
    return "medium"

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_RANK = {sev: len(SEVERITY_ORDER) - i for i, sev in enumerate(SEVERITY_ORDER)}  # 降序：Critical=5 … Info=1

def _severity_rank(severity: str) -> int:
    return SEVERITY_RANK.get(str(severity or "").strip(), 0)

__all__ = [
    'SEVERITY_ALIASES',
    'SEVERITY_ORDER',
    'SEVERITY_RANK',
    'VALID_SEVERITIES',
    'CONFIDENCE_RANK',
    '_normalize_severity',
    '_severity_match_values',
    '_severity_order_expr',
    '_normalize_confidence',
    '_severity_rank',
]

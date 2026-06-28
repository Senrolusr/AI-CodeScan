"""§10.2 阶段输出 schema 校验（quality gate）。

提供 ``validate_stage_output(stage_kind, raw) -> (normalized | None, error | None)``：
成功返归一化 dict（``model_dump(exclude_none=True)``，即 normalize 步骤），失败返
``(None, error_str)`` 供调用方降级。

schema 宽容（``extra="ignore"`` + 默认值）：容忍 LLM 漂移，只在结构严重错乱时降级。
**绝不因 validate 失败 crash**——调用方走原始 dict（+ degradation note），符合 §17.1
（状态/产物由后端掌控，schema 是质量门而非硬约束）。

对应文档管线：raw → JSON repair → **Pydantic validate** → normalize → quality gate → persist
（行 900-904）；本模块承担 validate + normalize，persist 由调用方完成。
"""
from __future__ import annotations

from typing import Any

from schemas import (
    Stage1ArchitectureOutput,
    SupervisorPlanOutput,
    SupervisorReviewOutput,
    VulnerabilityStageOutput,
)

_SCHEMAS = {
    "stage1": Stage1ArchitectureOutput,
    "vulnerability": VulnerabilityStageOutput,
    "plan": SupervisorPlanOutput,
    "review": SupervisorReviewOutput,
}


def validate_stage_output(stage_kind: str, raw: Any) -> tuple[dict | None, str | None]:
    """按 ``stage_kind`` 校验 ``raw``。

    Returns:
        成功 ``(归一化 dict, None)``；失败 ``(None, error_str)``。
    """
    schema = _SCHEMAS.get(stage_kind)
    if schema is None:
        return None, f"unknown stage_kind: {stage_kind}"
    if not isinstance(raw, dict):
        return None, f"expected dict, got {type(raw).__name__}"
    try:
        validated = schema.model_validate(raw)
    except Exception as exc:  # noqa: BLE001 - pydantic ValidationError，调用方降级
        return None, str(exc)
    return validated.model_dump(exclude_none=True), None

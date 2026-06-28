"""§10.2 阶段输出 schema quality gate 测试。

校验 ``validate_stage_output`` 的归一化/降级行为：合法输入归一化（extra=ignore 过滤噪声
+ 默认值补齐），非法/缺关键字段降级返 ``(None, err)``，供调用方保留原始 + 记 note。
"""

from __future__ import annotations

from services.ai_engine.stage_schema import validate_stage_output


def test_stage1_valid_filters_noise():
    raw = {"stage_summary": "s", "architecture_info": {"framework": "Flask"}, "risk_hints": [{"x": 1}], "extra_noise": "应被忽略"}
    validated, err = validate_stage_output("stage1", raw)
    assert err is None and validated is not None
    assert validated["stage_summary"] == "s"
    assert validated["architecture_info"] == {"framework": "Flask"}
    assert validated["risk_hints"] == [{"x": 1}]
    assert "extra_noise" not in validated  # extra=ignore


def test_vulnerability_valid():
    raw = {"stage_summary": "s", "vulnerabilities": [{"title": "x"}], "noise": 1}
    validated, err = validate_stage_output("vulnerability", raw)
    assert err is None and validated is not None
    assert validated["vulnerabilities"] == [{"title": "x"}]
    assert "noise" not in validated


def test_plan_valid_normalizes_agent_specs():
    raw = {
        "analysis_summary": "a",
        "selected_agents": [{"stage_num": 3, "focus_guidance": "g", "extra": "drop"}],
        "skipped_agents": [{"stage_num": 5}],
    }
    validated, err = validate_stage_output("plan", raw)
    assert err is None and validated is not None
    spec = validated["selected_agents"][0]
    assert spec["stage_num"] == 3
    assert spec["focus_guidance"] == "g"
    assert "extra" not in spec  # AgentSpecOutput extra=ignore
    assert spec["focus_files"] == []  # 默认值补齐


def test_plan_agent_missing_stage_num_fails():
    """agent spec 缺关键字段 stage_num → 整个 plan validate 失败（调用方降级）。"""
    raw = {"selected_agents": [{"focus_guidance": "g"}]}  # 无 stage_num
    validated, err = validate_stage_output("plan", raw)
    assert validated is None
    assert err


def test_review_valid():
    raw = {"review_summary": "r", "request_rerun": False, "rerun_agents": [], "findings_assessment": {"high_quality_count": 1}}
    validated, err = validate_stage_output("review", raw)
    assert err is None and validated is not None
    assert validated["findings_assessment"] == {"high_quality_count": 1}


def test_unknown_kind_fails():
    validated, err = validate_stage_output("bogus", {})
    assert validated is None
    assert "unknown" in err


def test_non_dict_fails():
    validated, err = validate_stage_output("stage1", [{"not": "a dict"}])
    assert validated is None
    assert err


def test_empty_dict_passes_with_defaults():
    """空 dict 仍 validate 通过（全默认值，宽容 LLM 漏字段）——降级只触发于结构错乱。"""
    for kind in ("stage1", "vulnerability", "plan", "review"):
        validated, err = validate_stage_output(kind, {})
        assert err is None, f"{kind}: {err}"
        assert validated is not None

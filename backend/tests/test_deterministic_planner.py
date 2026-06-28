"""§10.3 确定性 Planner 单元测试。

校验 ``_build_default_plan``（证据驱动选 stage + baseline 兜底）与
``_merge_plan_with_llm_focus``（确定性锁定 which stages，LLM 仅叠加 focus）的纯函数
契约——无需 DB/LLM。核心断言：**执行哪些阶段由后端证据决定，LLM 不能增删阶段**
（§17.1「执行计划由后端决定，不让模型跳过必须执行的阶段」）。
"""

from __future__ import annotations

from services.supervisor import _build_default_plan, _merge_plan_with_llm_focus


def _selected_nums(plan: dict) -> set[int]:
    return {a["stage_num"] for a in plan.get("selected_agents", []) if isinstance(a, dict)}


# ---- _build_default_plan：证据驱动 + baseline 兜底 ----

def test_evidence_drives_stage_selection():
    """stage 3 命中规则 → 确定性 planner 选 3��叠加 baseline 2/7/9。"""
    plan = _build_default_plan([{"stage_nums": [3]}], [])
    assert _selected_nums(plan) == {2, 3, 7, 9}


def test_no_evidence_falls_back_to_baseline_only():
    """零证据 → 仅 baseline 2/7/9（候选 = baseline）。"""
    plan = _build_default_plan([], [])
    assert _selected_nums(plan) == {2, 7, 9}


def test_source_sink_hints_also_drive_selection():
    """source-sink 线索与 rule_hits 同等计入证据。"""
    plan = _build_default_plan([], [{"stage_nums": [6]}])
    nums = _selected_nums(plan)
    assert 6 in nums
    assert {2, 7, 9} <= nums


def test_baseline_always_present_with_other_evidence():
    """多个非 baseline 阶段命中时，baseline 2/7/9 仍强制保留。"""
    plan = _build_default_plan([{"stage_nums": [4]}, {"stage_nums": [5]}], [], max_agents=7)
    nums = _selected_nums(plan)
    assert {2, 7, 9} <= nums
    assert {4, 5} <= nums


def test_budget_keeps_baseline_when_evidence_exceeds_budget():
    """证据阶段数超预算时，baseline 优先保留，总选定数不超 max_agents。"""
    hits = [{"stage_nums": [n]} for n in (3, 4, 5, 6, 8)]  # 5 个非 baseline 阶段
    plan = _build_default_plan(hits, [], max_agents=5)
    nums = _selected_nums(plan)
    assert {2, 7, 9} <= nums  # baseline 永不丢
    assert len(nums) <= 5


def test_budget_nine_allows_all_evidence_and_baseline_stages():
    """预算 9 足够覆盖 2-9 全部子审计阶段，不应让 baseline 挤掉业务阶段。"""
    hits = [{"stage_nums": [n]} for n in (3, 4, 5, 6, 8)]
    plan = _build_default_plan(hits, [], max_agents=9)
    nums = _selected_nums(plan)
    assert nums == {2, 3, 4, 5, 6, 7, 8, 9}
    assert not [item for item in plan.get("skipped_agents", []) if item.get("stage_num") in {3, 4, 5, 6, 8}]


def test_budget_trim_prefers_higher_evidence_non_baseline_stage():
    """预算不足时，非 baseline 按证据强度优先，而不是只按阶段号或插入顺序。"""
    hits = [{"stage_nums": [3]}, {"stage_nums": [4]}, {"stage_nums": [8]}, {"stage_nums": [8]}]
    plan = _build_default_plan(hits, [], max_agents=4)
    nums = _selected_nums(plan)
    assert {2, 7, 9} <= nums
    assert 8 in nums
    assert len(nums) <= 4


# ---- _merge_plan_with_llm_focus：LLM 仅 focus 增强，不增删 stage ----

def test_merge_overlays_llm_focus():
    """LLM 对候选 stage 的 focus 字段叠加到确定性计划。"""
    det = _build_default_plan([{"stage_nums": [3]}], [])
    llm = {
        "analysis_summary": "风险画像",
        "selected_agents": [{"stage_num": 3, "focus_guidance": "LLM 增强", "focus_files": ["a.py"], "focus_routes": ["/x"]}],
    }
    merged = _merge_plan_with_llm_focus(det, llm)
    s3 = next(s for s in merged["selected_agents"] if s["stage_num"] == 3)
    assert s3["focus_guidance"] == "LLM 增强"
    assert s3["focus_files"] == ["a.py"]
    assert s3["focus_routes"] == ["/x"]
    assert merged["analysis_summary"] == "风险画像"


def test_merge_ignores_llm_added_stage():
    """LLM 试图新增的 stage（不在确定性候选集）被丢弃——which stages 由后端锁。"""
    det = _build_default_plan([{"stage_nums": [3]}], [])  # {2,3,7,9}
    llm = {"selected_agents": [{"stage_num": 5, "focus_guidance": "bogus 新增"}]}
    merged = _merge_plan_with_llm_focus(det, llm)
    assert _selected_nums(merged) == {2, 3, 7, 9}
    assert 5 not in _selected_nums(merged)


def test_merge_keeps_deterministic_set_when_llm_partial():
    """LLM 只提到部分阶段时，确定性集合中的其余阶段（含 baseline）仍保留。"""
    det = _build_default_plan([{"stage_nums": [3]}], [])  # {2,3,7,9}
    llm = {"selected_agents": [{"stage_num": 3, "focus_guidance": "仅补 3"}]}
    merged = _merge_plan_with_llm_focus(det, llm)
    assert _selected_nums(merged) == {2, 3, 7, 9}


def test_merge_none_llm_returns_deterministic_intact():
    """LLM 缺失（解析失败/超时）→ 纯确定性计划原样返回。"""
    det = _build_default_plan([{"stage_nums": [3]}], [])
    merged = _merge_plan_with_llm_focus(det, None)
    assert _selected_nums(merged) == _selected_nums(det) == {2, 3, 7, 9}


def test_merge_empty_focus_keeps_deterministic_guidance():
    """LLM 对某 stage 未给 focus_guidance → 保留确定性默认 guidance，不置空。"""
    det = _build_default_plan([{"stage_nums": [3]}], [])
    det_s3 = next(s for s in det["selected_agents"] if s["stage_num"] == 3)
    llm = {"selected_agents": [{"stage_num": 3, "focus_files": ["only_files.py"]}]}
    merged = _merge_plan_with_llm_focus(det, llm)
    merged_s3 = next(s for s in merged["selected_agents"] if s["stage_num"] == 3)
    assert merged_s3["focus_guidance"] == det_s3["focus_guidance"]  # 默认值保留
    assert merged_s3["focus_files"] == ["only_files.py"]  # 仅 files 叠加

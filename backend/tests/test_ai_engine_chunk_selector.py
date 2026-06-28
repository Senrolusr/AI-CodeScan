"""M3 per-module tests: ai_engine.chunk_selector (scoring, selection, Stage-1 batching)."""

from __future__ import annotations

from services.ai_engine.chunk_selector import (
    _build_stage1_pass_context,
    _estimate_chunk_prompt_len,
    _estimate_chunks_prompt_len,
    _frontload_route_related_stage1_chunks,
    _is_high_signal_stage1_chunk,
    _is_stage1_entry_file,
    _is_stage1_low_value_chunk,
    _is_static_asset_chunk,
    _merge_stage1_batches_for_soft_cap,
    _score_stage4_chunk,
    _score_stage5_chunk,
    _score_stage6_chunk,
    _score_stage8_chunk,
    _select_stage1_skeleton_chunks,
    _select_stage_chunks,
    _shared_chunk_priority_boost,
    _split_chunks_for_stage1,
)


def _chunk(file_path: str, content: str = "") -> dict:
    return {"file_path": file_path, "content": content}


# ── static asset detection ──
def test_is_static_asset_chunk_extensions_and_markers():
    assert _is_static_asset_chunk("logo.png") is True
    assert _is_static_asset_chunk("app/assets/bundle.js") is True
    assert _is_static_asset_chunk("/static/main.css") is True
    assert _is_static_asset_chunk("") is False
    assert _is_static_asset_chunk("app/api/controller.py") is False


# ── per-stage keyword scoring ──
def test_score_stage4_ranks_xss_chunks_higher():
    high = _score_stage4_chunk(_chunk("view.vue", "innerHTML = userInput v-html"))
    plain = _score_stage4_chunk(_chunk("util.py", "print(1)"))
    assert high > 0
    assert plain == 0
    assert high > plain


def test_score_stage5_auth_keywords():
    score = _score_stage5_chunk(_chunk("auth/login.py", "jwt bearer authenticate password_verify"))
    assert score > 0


def test_score_stage6_authorization_keywords():
    score = _score_stage6_chunk(_chunk("perm/policy.py", "@PreAuthorize hasPermission role acl"))
    assert score > 0


def test_score_stage8_file_keywords():
    score = _score_stage8_chunk(_chunk("upload/handle.py", "move_uploaded_file realpath basename"))
    assert score > 0


# ── shared priority boost ──
def test_shared_chunk_priority_boost_route_and_risk():
    route_boost = _shared_chunk_priority_boost(_chunk("app/auth.py"), 5, route_files={"app/auth.py"})
    assert route_boost >= 8
    risk_boost = _shared_chunk_priority_boost({"file_path": "x.py", "risk_score": 10, "chunk_type": "oversized_signal_x"}, 2)
    assert risk_boost >= 15


def test_shared_chunk_priority_boost_stage_label_match():
    # stage 4 maps to {"xss"} risk label
    boost = _shared_chunk_priority_boost({"file_path": "v.vue", "risk_labels": ["xss"]}, 4)
    assert boost >= 8


# ── Stage-1 entry / low-value classification ──
def test_is_stage1_low_value_chunk():
    assert _is_stage1_low_value_chunk(_chunk("README.md")) is True
    assert _is_stage1_low_value_chunk(_chunk("docs/intro.css")) is True
    assert _is_stage1_low_value_chunk(_chunk("app/api/controller.py")) is False


def test_is_stage1_entry_file():
    assert _is_stage1_entry_file(_chunk("app/router.py")) is True
    assert _is_stage1_entry_file(_chunk("util/misc.py", "x = 1")) is False


def test_is_high_signal_stage1_chunk():
    assert _is_high_signal_stage1_chunk(_chunk("app/main.py", "@app.get")) is True
    assert _is_high_signal_stage1_chunk(_chunk("a/b/random.txt", "lorem ipsum")) is False


# ── prompt length estimation ──
def test_estimate_chunk_prompt_len_and_list():
    assert _estimate_chunk_prompt_len({"content": "abcd", "file_path": "f.py"}) == len("abcd") + len("f.py") + 32
    assert _estimate_chunks_prompt_len([{"content": "ab", "file_path": "f"}]) == 2 + 1 + 32


# ── dispatcher ──
def test_select_stage_chunks_dispatches_and_filters():
    # stage 4 filters static assets, keeps vue chunk
    sel = _select_stage_chunks(4, [_chunk("v.vue", "innerHTML v-html"), _chunk("x.png", "img")])
    assert [c["file_path"] for c in sel] == ["v.vue"]
    # stage 1 filters low-value (README), keeps router
    sel1 = _select_stage_chunks(1, [_chunk("app/router.py", "@app.get"), _chunk("README.md", "license")])
    assert "app/router.py" in [c["file_path"] for c in sel1]
    assert "README.md" not in [c["file_path"] for c in sel1]


def test_select_stage_chunks_generic_stage_returns_list():
    sel = _select_stage_chunks(9, [_chunk("order.py", "payment amount refund"), _chunk("util.py", "nothing")])
    assert isinstance(sel, list)
    assert len(sel) >= 1


# ── Stage-1 batching ──
def test_split_chunks_for_stage1_partitions_all_chunks():
    chunks = [_chunk(f"f{i}.py", "x" * 100) for i in range(5)]
    batches = _split_chunks_for_stage1(chunks, max_len=1000)
    assert isinstance(batches, list)
    # every chunk lands in exactly one batch
    flat = [c["file_path"] for batch in batches for c in batch]
    assert sorted(flat) == [f"f{i}.py" for i in range(5)]


def test_split_chunks_for_stage1_empty_returns_list_of_empty():
    assert _split_chunks_for_stage1([]) == [[]]


def test_merge_stage1_batches_for_soft_cap_collapses():
    batches = [[_chunk("a")], [_chunk("b")], [_chunk("c")], [_chunk("d")]]
    merged = _merge_stage1_batches_for_soft_cap(batches, soft_cap=2)
    assert len(merged) == 2
    # all chunks preserved
    flat = [c["file_path"] for batch in merged for c in batch]
    assert sorted(flat) == ["a", "b", "c", "d"]


def test_merge_stage1_batches_under_cap_passthrough():
    batches = [[_chunk("a")], [_chunk("b")]]
    assert len(_merge_stage1_batches_for_soft_cap(batches, soft_cap=5)) == 2


# ── skeleton selection ──
def test_select_stage1_skeleton_chunks_filters_and_orders():
    chunks = [
        _chunk("README.md", "license copyright"),
        _chunk("app/main.py", "@app.get include_router"),
        _chunk("util/misc.py", "x = 1"),
    ]
    selected = _select_stage1_skeleton_chunks(chunks)
    paths = [c["file_path"] for c in selected]
    assert "app/main.py" in paths
    assert "README.md" not in paths  # filtered as low-value


# ── route frontloading ──
def test_frontload_route_related_stage1_chunks_prioritizes_route_files():
    chunks = [_chunk("util/misc.py", "x=1"), _chunk("app/router.py", "@app.get")]
    routes = [{"file_path": "app/router.py"}]
    ordered = _frontload_route_related_stage1_chunks(chunks, routes)
    # router.py lands before the unrelated util file
    assert ordered[0]["file_path"] == "app/router.py"


# ── pass context ──
def test_build_stage1_pass_context_includes_markers():
    ctx = _build_stage1_pass_context("previous findings", {"k": 1}, pass_index=2, total_passes=3)
    assert "2/3" in ctx
    assert "Compressed Summary" in ctx
    assert "previous findings" in ctx

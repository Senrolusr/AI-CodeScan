"""§4.8 LLM 客户端：调用路径错误分类 + 瞬时错误重试策略。

聚焦 ``call_llm_with_meta`` 的重试决策（不碰连通性测试路径 ``_classify_error``）：
- 瞬时错误（timeout / 429 限流 / 5xx 上游错误 / 网络层）→ 线性退避重试，最多 LLM_MAX_RETRIES 次。
- 永久错误（鉴权 / 模型 / 客户端 4xx）→ 立即失败，不浪费审计时长。
全程 monkeypatch ``_call_with_mode`` 与 ``asyncio.sleep``，纯单元、无网络无 DB。
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import services.llm_client as llm_client
from services.llm_client import _classify_call_error, call_llm_with_meta


class _FakeHttpError(Exception):
    """模拟带 HTTP 状态码的上游异常（openai SDK 直接暴露 .status_code）。"""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


def _config() -> SimpleNamespace:
    # call_llm_with_meta 仅经 _get_api_mode 读 config.api_mode；_call_with_mode 被 mock。
    return SimpleNamespace(api_mode="chat_completions")


def _scripted_call(monkeypatch, behaviors):
    """按序消费 behaviors：Exception→raise，dict→作为结果返回；越���则重复最后一个。"""
    state = {"i": 0}

    async def fake(config, system_prompt, user_prompt, api_mode):
        idx = min(state["i"], len(behaviors) - 1)
        state["i"] += 1
        behavior = behaviors[idx]
        if isinstance(behavior, BaseException):
            raise behavior
        result = dict(behavior)
        result.setdefault("meta", {})
        return result

    monkeypatch.setattr(llm_client, "_call_with_mode", fake)
    return state


def _patch_sleep(monkeypatch):
    sleeps = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    return sleeps


# ── 分类器 ──


def test_classify_call_error_by_status_code():
    assert _classify_call_error(_FakeHttpError("rate limited", 429)) == "rate_limit"
    assert _classify_call_error(_FakeHttpError("boom", 503)) == "server_error"
    assert _classify_call_error(_FakeHttpError("bad gateway", 502)) == "server_error"
    assert _classify_call_error(_FakeHttpError("no key", 401)) == "auth"
    assert _classify_call_error(_FakeHttpError("forbidden", 403)) == "auth"
    assert _classify_call_error(_FakeHttpError("no model", 404)) == "model"
    assert _classify_call_error(_FakeHttpError("bad request", 400)) == "client_error"
    assert _classify_call_error(_FakeHttpError("too large", 413)) == "client_error"


def test_classify_call_error_by_message():
    # 无状态码的网络层异常走消息匹配；_format_exception_message 会把 timeout/超时 归一成中文。
    assert _classify_call_error(Exception("upstream timed out")) == "timeout"
    assert _classify_call_error(Exception("Connection error to host")) == "network"
    assert _classify_call_error(Exception("invalid api key supplied")) == "auth"
    assert _classify_call_error(Exception("model gpt-x not found")) == "model"
    assert _classify_call_error(Exception("content was blocked by policy")) == "blocked"


# ── 重试循环 ──


async def test_call_succeeds_first_try(monkeypatch):
    _scripted_call(monkeypatch, [{"success": True, "content": "ok"}])
    sleeps = _patch_sleep(monkeypatch)
    result = await call_llm_with_meta(_config(), "sys", "user")
    assert result["success"] is True
    assert result["meta"]["attempt"] == 1
    assert sleeps == []  # 成功不退避


async def test_retries_rate_limit_then_succeeds(monkeypatch):
    _scripted_call(
        monkeypatch,
        [_FakeHttpError("rate limited", 429), {"success": True, "content": "ok"}],
    )
    sleeps = _patch_sleep(monkeypatch)
    result = await call_llm_with_meta(_config(), "sys", "user")
    assert result["success"] is True
    assert result["meta"]["attempt"] == 2
    assert len(sleeps) == 1  # 首次失败后退避一次再重试


async def test_retries_server_error_and_network(monkeypatch):
    # 5xx → 网络抖动 → 成功：两次瞬时错误都应重试
    _scripted_call(
        monkeypatch,
        [
            _FakeHttpError("boom", 503),
            Exception("Connection error"),
            {"success": True, "content": "ok"},
        ],
    )
    sleeps = _patch_sleep(monkeypatch)
    result = await call_llm_with_meta(_config(), "sys", "user")
    assert result["success"] is True
    assert result["meta"]["attempt"] == 3
    assert len(sleeps) == 2


async def test_retries_timeout_until_max_then_fails(monkeypatch):
    monkeypatch.setattr(llm_client, "LLM_MAX_RETRIES", 2)
    monkeypatch.setattr(llm_client, "LLM_RETRY_BASE_DELAY_SECONDS", 1.0)
    _scripted_call(monkeypatch, [Exception("upstream timed out")])  # 恒超时
    sleeps = _patch_sleep(monkeypatch)
    result = await call_llm_with_meta(_config(), "sys", "user")
    assert result["success"] is False
    assert result["error"]["category"] == "timeout"
    assert result["error"]["attempt"] == 3  # 初始 1 + 2 次重试
    assert sleeps == [1.0, 2.0]  # 线性退避，最后一轮失败后不再睡


async def test_backoff_is_linear_and_capped(monkeypatch):
    monkeypatch.setattr(llm_client, "LLM_MAX_RETRIES", 4)
    monkeypatch.setattr(llm_client, "LLM_RETRY_BASE_DELAY_SECONDS", 3.0)
    monkeypatch.setattr(llm_client, "LLM_RETRY_DELAY_CAP_SECONDS", 7.0)
    _scripted_call(monkeypatch, [_FakeHttpError("boom", 503)])  # 恒 5xx
    sleeps = _patch_sleep(monkeypatch)
    result = await call_llm_with_meta(_config(), "sys", "user")
    assert result["error"]["attempt"] == 5
    # base*1=3, base*2=6, base*3=9→cap 7, base*4=12→cap 7；最后一轮（第 5 次尝试）失败后不睡
    assert sleeps == [3.0, 6.0, 7.0, 7.0]


async def test_no_retry_on_auth_error(monkeypatch):
    _scripted_call(monkeypatch, [_FakeHttpError("no key", 401)])
    sleeps = _patch_sleep(monkeypatch)
    result = await call_llm_with_meta(_config(), "sys", "user")
    assert result["success"] is False
    assert result["error"]["category"] == "auth"
    assert result["error"]["attempt"] == 1  # 永久错误立即失败
    assert sleeps == []


async def test_no_retry_on_model_not_found(monkeypatch):
    _scripted_call(monkeypatch, [_FakeHttpError("no model", 404)])
    sleeps = _patch_sleep(monkeypatch)
    result = await call_llm_with_meta(_config(), "sys", "user")
    assert result["success"] is False
    assert result["error"]["category"] == "model"
    assert result["error"]["attempt"] == 1
    assert sleeps == []




async def test_no_retry_on_client_error(monkeypatch):
    # 400 等客户端错误属永久失败（请求非法），重试无意义
    _scripted_call(monkeypatch, [_FakeHttpError("bad request", 400)])
    sleeps = _patch_sleep(monkeypatch)
    result = await call_llm_with_meta(_config(), "sys", "user")
    assert result["success"] is False
    assert result["error"]["category"] == "client_error"
    assert result["error"]["attempt"] == 1
    assert sleeps == []


async def test_run_test_probe_chat_uses_config_temperature_and_128_tokens(monkeypatch):
    calls = []

    class _FakeCompletions:
        async def create(self, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content="pong"))],
                model="probe-model",
                usage=None,
            )

    fake_client = SimpleNamespace(chat=SimpleNamespace(completions=_FakeCompletions()))
    monkeypatch.setattr(llm_client, "_build_client", lambda config: fake_client)

    result = await llm_client._run_test_probe(
        SimpleNamespace(model_name="probe-model", temperature=0.42),
        "chat_completions",
    )

    assert result["success"] is True
    assert calls[0]["temperature"] == 0.42
    assert calls[0]["max_tokens"] == 128


async def test_test_llm_connection_retries_retryable_probe_error(monkeypatch):
    attempts = []

    async def fake_probe(config, api_mode):
        attempts.append(api_mode)
        if len(attempts) == 1:
            raise Exception("upstream timed out")
        return {
            "success": True,
            "strict_success": True,
            "base_success": True,
            "stage": api_mode,
            "category": "ok",
            "message": "pong",
            "diagnosis": "ok",
            "latency_ms": 1,
            "model": config.model_name,
            "usage": None,
        }

    monkeypatch.setattr(llm_client, "_run_test_probe", fake_probe)
    sleeps = _patch_sleep(monkeypatch)

    result = await llm_client.test_llm_connection(
        SimpleNamespace(api_mode="chat_completions", model_name="probe-model")
    )

    assert result["success"] is True
    assert result["successful_mode"] == "chat_completions"
    assert [a["attempt"] for a in result["attempts"]] == [1, 2]
    assert attempts == ["chat_completions", "chat_completions"]
    assert len(sleeps) == 1


async def test_test_llm_connection_does_not_retry_auth_error(monkeypatch):
    attempts = []

    async def fake_probe(config, api_mode):
        attempts.append(api_mode)
        raise Exception("invalid api key supplied")

    monkeypatch.setattr(llm_client, "_run_test_probe", fake_probe)
    sleeps = _patch_sleep(monkeypatch)

    result = await llm_client.test_llm_connection(
        SimpleNamespace(api_mode="chat_completions", model_name="probe-model")
    )

    assert result["success"] is False
    assert [a["attempt"] for a in result["attempts"]] == [1, 1]
    assert [a["category"] for a in result["attempts"]] == ["auth", "auth"]
    assert attempts == ["chat_completions", "responses"]
    assert sleeps == []

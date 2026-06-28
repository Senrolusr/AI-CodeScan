import asyncio
import re
import time

import httpx
from openai import AsyncOpenAI

from models import LlmConfig
from services.config import (
    DEFAULT_LLM_TIMEOUT_SECONDS,
    LLM_MAX_RETRIES,
    LLM_RETRY_BASE_DELAY_SECONDS,
)
from services.secret_crypto import resolve_stored_api_key

# 可重试的瞬时错误类别（§4.8 重试策略）。永久错误（鉴权 / 模型 / 客户端 4xx）
# 立即失败，不浪费重试配额与审计时长。
RETRYABLE_ERROR_CATEGORIES = {"timeout", "rate_limit", "server_error", "network"}
# 线性退避上限，避免单次重试间隔过长拖慢审计。
LLM_RETRY_DELAY_CAP_SECONDS = 10.0


def _resolve_api_key(config: LlmConfig) -> str:
    """解析存储的 api_key：解密 enc: 密文 + 处理 ${ENV_VAR} 引用 + 兼容旧明文。"""
    return resolve_stored_api_key(config.api_key)


def _build_client(config: LlmConfig) -> AsyncOpenAI:
    return AsyncOpenAI(
        api_key=_resolve_api_key(config),
        base_url=(config.base_url or "").rstrip("/"),
        timeout=DEFAULT_LLM_TIMEOUT_SECONDS,
    )


def _get_api_mode(config: LlmConfig) -> str:
    return (config.api_mode or "chat_completions").lower()


def _resolve_completion_limit(
    config: LlmConfig,
    default_limit: int = 6144,
    hard_cap: int = 16384,
) -> int:
    configured = config.max_tokens or default_limit
    return max(16, min(configured, hard_cap))


def _format_exception_message(exc: Exception) -> str:
    text = str(exc).strip()
    lower_text = text.lower()
    if "connection error" in lower_text:
        return "连接上游模型失败。"
    if "timed out" in lower_text or "timeout" in lower_text:
        return "上游模型请求超时。"
    if (
        "unauthorized" in lower_text
        or "authentication" in lower_text
        or "invalid api key" in lower_text
    ):
        return "模型认证失败，请检查 API Key。"
    if "not found" in lower_text and "model" in lower_text:
        return "模型不存在，请检查模型名称。"
    if text:
        return text
    name = exc.__class__.__name__
    if isinstance(exc, httpx.ReadTimeout):
        return f"{name}: 上游模型请求超时"
    if isinstance(exc, httpx.ConnectTimeout):
        return f"{name}: 上游连接超时"
    if isinstance(exc, httpx.TimeoutException):
        return f"{name}: 上游请求超时"
    return name


async def _create_response_via_http(
    config: LlmConfig,
    system_prompt: str,
    user_prompt: str,
):
    base_url = (config.base_url or "").rstrip("/")
    payload = {
        "model": config.model_name,
        "input": user_prompt,
        "instructions": system_prompt,
        "temperature": config.temperature,
        "max_output_tokens": _resolve_completion_limit(config),
    }
    headers = {
        "Authorization": f"Bearer {_resolve_api_key(config)}",
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=DEFAULT_LLM_TIMEOUT_SECONDS) as client:
        response = await client.post(
            f"{base_url}/responses",
            headers=headers,
            json=payload,
        )
        response.raise_for_status()
        return response.json()


def _normalize_usage(usage) -> dict | None:
    if not usage:
        return None
    if isinstance(usage, dict):
        return {
            "prompt_tokens": usage.get("input_tokens"),
            "completion_tokens": usage.get("output_tokens"),
            "total_tokens": usage.get("total_tokens"),
        }
    return {
        "prompt_tokens": getattr(usage, "prompt_tokens", None),
        "completion_tokens": getattr(usage, "completion_tokens", None),
        "total_tokens": getattr(usage, "total_tokens", None),
    }


def _extract_response_finish_reason(response: dict) -> str | None:
    if not isinstance(response, dict):
        return None

    incomplete = response.get("incomplete_details")
    if isinstance(incomplete, dict):
        reason = incomplete.get("reason") or incomplete.get("type")
        if isinstance(reason, str) and reason.strip():
            return reason.strip()

    status = response.get("status")
    if isinstance(status, str) and status.strip():
        lower_status = status.strip().lower()
        if lower_status in {"incomplete", "failed", "cancelled"}:
            return lower_status

    for item in response.get("output", []) or []:
        if not isinstance(item, dict):
            continue
        finish_reason = item.get("finish_reason")
        if isinstance(finish_reason, str) and finish_reason.strip():
            return finish_reason.strip()
        status = item.get("status")
        if isinstance(status, str) and status.strip():
            lower_status = status.strip().lower()
            if lower_status in {"incomplete", "failed", "cancelled"}:
                return lower_status

    return None


async def _call_with_mode(
    config: LlmConfig,
    system_prompt: str,
    user_prompt: str,
    api_mode: str,
):
    from services.llm_pool import get_shared_client
    client = get_shared_client(config)
    started = time.perf_counter()
    if api_mode == "responses":
        response = await _create_response_via_http(config, system_prompt, user_prompt)
        content = response.get("output_text") or ""
        if not content:
            parts = []
            for item in response.get("output", []) or []:
                for content_item in item.get("content", []) or []:
                    text = content_item.get("text")
                    if text:
                        parts.append(text)
            content = "\n".join(parts)
        model = response.get("model") or config.model_name
        usage = response.get("usage")
        finish_reason = _extract_response_finish_reason(response)
        response_status = response.get("status")
        incomplete_details = response.get("incomplete_details")
    else:
        response = await client.chat.completions.create(
            model=config.model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=config.temperature,
            max_tokens=_resolve_completion_limit(config),
        )
        content = response.choices[0].message.content or ""
        model = response.model or config.model_name
        usage = getattr(response, "usage", None)
        finish_reason = getattr(response.choices[0], "finish_reason", None)
        response_status = None
        incomplete_details = None

    return {
        "success": True,
        "content": content,
        "meta": {
            "model": model,
            "api_mode": api_mode,
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "attempt": 1,
            "usage": _normalize_usage(usage),
            "finish_reason": finish_reason,
            "response_status": response_status,
            "incomplete_details": incomplete_details,
        },
    }


def _classify_call_error(exc: Exception) -> str:
    """把调用路径异常归类为稳定类别，供重试决策用（§4.8 上游错误分类）。

    优先看 HTTP 状态码（精确）：429→限流、5xx→上游错误均可重试；401/403→鉴权、
    404→模型、其余 4xx→客户端错误均立即失败。无状态码（连接拒绝 / DNS / 读超时等
    网络层）回退到**原始**消息匹配（``_format_exception_message`` 会本地化、抹掉
    英文关键词，故分类必须读 ``str(exc)`` 原文 + 异常类名），默认按瞬时 ``network``
    处理，宁可多一次重试也不误杀。
    """
    status_code = _extract_status_code(exc)
    if isinstance(status_code, int):
        if status_code == 429:
            return "rate_limit"
        if status_code >= 500:
            return "server_error"
        if status_code in (401, 403):
            return "auth"
        if status_code == 404:
            return "model"
        return "client_error"  # 其余 4xx：请求永久非法，重试无意义

    raw = str(exc) or ""
    combined = f"{raw} {exc.__class__.__name__}".lower()
    if "timeout" in combined or "timed out" in combined or "超时" in raw:
        return "timeout"
    if "blocked" in combined:
        return "blocked"
    if (
        "unauthorized" in combined
        or "invalid api key" in combined
        or "authentication" in combined
        or "认证失败" in raw
    ):
        return "auth"
    if "not found" in combined and "model" in combined:
        return "model"
    # 连接拒绝 / DNS / 读错误等网络层瞬时故障
    return "network"


def _retry_delay_seconds(failed_attempt: int) -> float:
    """线性退避：第 failed_attempt 次失败后等待 base*failed_attempt，封顶 LLM_RETRY_DELAY_CAP_SECONDS。"""
    return min(LLM_RETRY_BASE_DELAY_SECONDS * max(1, failed_attempt), LLM_RETRY_DELAY_CAP_SECONDS)


async def call_llm_with_meta(config: LlmConfig, system_prompt: str, user_prompt: str) -> dict:
    api_mode = _get_api_mode(config)
    last_error = None
    max_attempts = 1 + max(0, LLM_MAX_RETRIES)

    # 初始 1 次 + 至多 LLM_MAX_RETRIES 次重试。瞬时错误（timeout/限流/5xx/网络）退避后重试，
    # 永久错误（鉴权/模型/客户端 4xx）立即返回，不浪费审计时长。
    for attempt in range(max_attempts):
        try:
            result = await _call_with_mode(config, system_prompt, user_prompt, api_mode)
            result["meta"]["attempt"] = attempt + 1
            return result
        except Exception as exc:
            category = _classify_call_error(exc)
            last_error = {
                "message": _format_exception_message(exc),
                "category": category,
                "latency_ms": None,
                "attempt": attempt + 1,
            }
            if category not in RETRYABLE_ERROR_CATEGORIES:
                break  # 永久错误：重试无意义，立即失败
            if attempt + 1 < max_attempts:
                await asyncio.sleep(_retry_delay_seconds(attempt + 1))  # 最后一轮失败后不再睡

    return {
        "success": False,
        "content": "",
        "error": last_error or {
            "message": "未知模型错误",
            "category": "unknown",
            "latency_ms": None,
            "attempt": 1,
        },
    }


def _normalize_probe_text(text: str) -> str:
    cleaned = (text or "").strip().lower()
    cleaned = cleaned.replace("```", " ").replace("`", " ")
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned


def _is_pong_like(text: str) -> bool:
    cleaned = _normalize_probe_text(text)
    return bool(cleaned) and "pong" in cleaned


def _has_meaningful_content(text: str) -> bool:
    return bool((text or "").strip())


def _classify_error(error_text: str) -> str:
    error_lower = error_text.lower()
    if "blocked" in error_lower:
        return "blocked"
    if (
        "unauthorized" in error_lower
        or "invalid api key" in error_lower
        or "authentication" in error_lower
        or "认证失败" in error_text
    ):
        return "auth"
    if "not found" in error_lower and "model" in error_lower:
        return "model"
    if "timeout" in error_lower or "超时" in error_text:
        return "timeout"
    return "network"


def _extract_status_code(exc: Exception) -> int | None:
    # openai SDK 异常直接暴露 status_code；httpx/openai 的 HTTPStatusError 在 .response.status_code。
    direct = getattr(exc, "status_code", None)
    if isinstance(direct, int):
        return direct
    response = getattr(exc, "response", None)
    status_code = getattr(response, "status_code", None)
    if isinstance(status_code, int):
        return status_code
    return None


def _extract_error_body(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if response is None:
        return ""
    text = getattr(response, "text", "")
    if isinstance(text, str):
        return text[:1000]
    return ""


def _build_diagnosis(api_mode: str, error_text: str, exc: Exception | None = None) -> str:
    combined = f"{error_text}\n{_extract_error_body(exc) if exc else ''}".lower()
    status_code = _extract_status_code(exc) if exc else None

    if status_code in {401, 403}:
        return "鉴权失败，请检查 API Key、鉴权方式或账号权限。"
    if status_code == 404:
        if api_mode == "responses":
            return "当前 Base URL 很可能不支持 /responses 路径，或该服务未实现 Responses 接口。"
        return "接口路径或模型资源不存在，请检查 Base URL 是否应以 /v1 结尾，以及模型名是否正确。"
    if status_code == 405:
        return "接口路径存在但请求方法不被接受，通常是网关协议不兼容或接入方式不对。"
    if status_code == 429:
        return "请求被限流或额度不足，请检查余额、配额和并发限制。"
    if status_code and status_code >= 500:
        return "上游服务内部报错，通常不是前端配置问题，建议稍后重试并查看服务商状态。"

    if "model" in combined and ("not found" in combined or "does not exist" in combined):
        return "模型名称不可用，或当前接口模式不支持该模型。"
    if "responses" in combined and ("not found" in combined or "404" in combined):
        return "当前服务很可能不支持 Responses API。"
    if "chat" in combined and "completions" in combined and ("not found" in combined or "404" in combined):
        return "当前服务很可能不支持 Chat Completions API，或 Base URL 入口不对。"
    if "unauthorized" in combined or "authentication" in combined or "invalid api key" in combined:
        return "鉴权失败，请核对 API Key 是否正确、是否有该模型权限。"
    if "timeout" in combined or "timed out" in combined or "超时" in error_text:
        return "连接超时，请检查网络连通性、代理设置或上游服务响应时间。"
    if "connection error" in combined or "name or service not known" in combined:
        return "无法连接到上游地址，请检查 Base URL、DNS、代理和网络出口。"

    if api_mode == "responses":
        return "Responses 模式调用失败，请重点检查该服务是否兼容 /responses 接口。"
    return "Chat Completions 模式调用失败，请重点检查 Base URL、模型名和网关兼容性。"


async def _run_test_probe(config: LlmConfig, api_mode: str) -> dict:
    client = _build_client(config)
    started = time.perf_counter()
    if api_mode == "responses":
        response = await _create_response_via_http(
            config,
            "You are a connectivity test assistant. Reply with only the word pong.",
            "Reply with pong",
        )
        content = (response.get("output_text") or "").strip()
        if not content:
            parts = []
            for item in response.get("output", []) or []:
                for content_item in item.get("content", []) or []:
                    text = content_item.get("text")
                    if text:
                        parts.append(text)
            content = "\n".join(parts).strip()
        model = response.get("model") or config.model_name
        usage = response.get("usage")
    else:
        response = await client.chat.completions.create(
            model=config.model_name,
            messages=[
                {
                    "role": "system",
                    "content": "You are a connectivity test assistant. Reply with only the word pong.",
                },
                {"role": "user", "content": "Reply with pong"},
            ],
            temperature=config.temperature if config.temperature is not None else 0.1,
            max_tokens=128,
        )
        content = (response.choices[0].message.content or "").strip()
        model = response.model or config.model_name
        usage = getattr(response, "usage", None)

    base_success = _has_meaningful_content(content)
    strict_success = _is_pong_like(content)
    latency_ms = int((time.perf_counter() - started) * 1000)

    if strict_success:
        category = "ok"
        diagnosis = "接口已返回符合探测要求的内容，连通与兼容性均正常。"
    elif base_success:
        category = "probe_mismatch"
        diagnosis = "接口已成功返回内容，说明模型可用；只是未严格按探测要求仅返回 pong。"
    else:
        category = "empty_response"
        diagnosis = "接口请求成功但返回为空，建议检查模型兼容性、网关转发或响应提取逻辑。"

    return {
        "success": base_success,
        "strict_success": strict_success,
        "base_success": base_success,
        "stage": api_mode,
        "category": category,
        "message": content,
        "diagnosis": diagnosis,
        "latency_ms": latency_ms,
        "model": model,
        "usage": _normalize_usage(usage),
    }


def _build_attempt_from_exception(config: LlmConfig, api_mode: str, exc: Exception) -> dict:
    error_text = _format_exception_message(exc)
    return {
        "success": False,
        "strict_success": False,
        "base_success": False,
        "stage": api_mode,
        "category": _classify_error(error_text),
        "message": error_text,
        "diagnosis": _build_diagnosis(api_mode, error_text, exc),
        "latency_ms": None,
        "model": config.model_name,
        "usage": None,
    }


async def test_llm_connection(config: LlmConfig) -> dict:
    preferred_mode = _get_api_mode(config)
    fallback_mode = "responses" if preferred_mode == "chat_completions" else "chat_completions"
    attempts = []
    successful_mode = None
    strict_successful_mode = None

    for api_mode in [preferred_mode, fallback_mode]:
        for attempt_num in range(1, 3):
            try:
                result = await _run_test_probe(config, api_mode)
                result["attempt"] = attempt_num
                attempts.append(result)
                if result["success"] and successful_mode is None:
                    successful_mode = api_mode
                if result["strict_success"] and strict_successful_mode is None:
                    strict_successful_mode = api_mode
                if result["success"]:
                    break
            except Exception as exc:
                attempt = _build_attempt_from_exception(config, api_mode, exc)
                attempt["attempt"] = attempt_num
                attempts.append(attempt)
                if attempt["category"] not in RETRYABLE_ERROR_CATEGORIES or attempt_num >= 2:
                    break
                await asyncio.sleep(_retry_delay_seconds(attempt_num))
        if successful_mode is not None:
            break

    success = successful_mode is not None
    strict_success = strict_successful_mode is not None

    if strict_success:
        summary_message = "模型连通成功，且通过严格探测。"
    elif success:
        summary_message = "模型基础连通成功，但未通过严格 pong 探测；这通常不影响正式审计。"
    else:
        summary_message = "两种接口模式均未通过连通性测试，请根据下方明细排查。"

    return {
        "success": success,
        "strict_success": strict_success,
        "preferred_mode": preferred_mode,
        "successful_mode": successful_mode,
        "strict_successful_mode": strict_successful_mode,
        "message": summary_message,
        "attempts": attempts,
        "model": config.model_name,
    }

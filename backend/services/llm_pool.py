"""共享 LLM 客户端池，按配置复用 AsyncOpenAI 实例。"""

from openai import AsyncOpenAI

from models import LlmConfig
from services.config import DEFAULT_LLM_TIMEOUT_SECONDS

_pool: dict[int, AsyncOpenAI] = {}


def get_shared_client(config: LlmConfig) -> AsyncOpenAI:
    """按 config.id 复用 AsyncOpenAI 客户端实例，避免并发时重复建连。"""
    cached = _pool.get(config.id)
    if cached is not None:
        cached_key = getattr(cached, "_cached_api_key", "")
        cached_url = getattr(cached, "_cached_base_url", "")
        if cached_key == config.api_key and cached_url == (config.base_url or "").rstrip("/"):
            return cached

    client = AsyncOpenAI(
        api_key=config.api_key,
        base_url=(config.base_url or "").rstrip("/"),
        timeout=DEFAULT_LLM_TIMEOUT_SECONDS,
    )
    client._cached_api_key = config.api_key
    client._cached_base_url = (config.base_url or "").rstrip("/")
    _pool[config.id] = client
    return client

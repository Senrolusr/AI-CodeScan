"""Lightweight execution event logging for audit runs.

Events are stored as JSONL under the existing stage artifact directory so this
feature does not require a database migration. The records are intentionally
compact: prompts and responses are represented by lengths and short previews.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

from models import LlmConfig
from services.audit_cleanup import get_stage_artifact_dir
from services.llm_client import call_llm_with_meta

logger = logging.getLogger(__name__)

EVENT_FILE_NAME = "execution_events.jsonl"
MAX_PROMPT_PREVIEW_CHARS = 900
MAX_RESPONSE_PREVIEW_CHARS = 1600
MAX_META_STRING_CHARS = 1200
MAX_META_ITEMS = 80

_EVENT_LOCKS: dict[int, asyncio.Lock] = {}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _event_file_path(task_id: int) -> str:
    return os.path.join(get_stage_artifact_dir(int(task_id)), EVENT_FILE_NAME)


def _task_lock(task_id: int) -> asyncio.Lock:
    task_id = int(task_id)
    lock = _EVENT_LOCKS.get(task_id)
    if lock is None:
        lock = asyncio.Lock()
        _EVENT_LOCKS[task_id] = lock
    return lock


def _preview(text: Any, limit: int) -> str:
    value = str(text or "")
    if len(value) <= limit:
        return value
    return value[:limit] + "...[truncated]"


def _compact_value(value: Any, depth: int = 0) -> Any:
    if depth > 4:
        return _preview(value, MAX_META_STRING_CHARS)
    if isinstance(value, dict):
        compacted = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_META_ITEMS:
                compacted["_truncated_items"] = len(value) - MAX_META_ITEMS
                break
            compacted[str(key)] = _compact_value(item, depth + 1)
        return compacted
    if isinstance(value, (list, tuple, set)):
        items = list(value)
        compacted = [_compact_value(item, depth + 1) for item in items[:MAX_META_ITEMS]]
        if len(items) > MAX_META_ITEMS:
            compacted.append({"_truncated_items": len(items) - MAX_META_ITEMS})
        return compacted
    if isinstance(value, str):
        return _preview(value, MAX_META_STRING_CHARS)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _preview(value, MAX_META_STRING_CHARS)


def _strip_empty_fields(event: dict) -> dict:
    return {
        key: value
        for key, value in event.items()
        if value is not None and value != "" and value != {} and value != []
    }


def _append_event_sync(task_id: int, event: dict) -> dict:
    path = _event_file_path(task_id)
    os.makedirs(os.path.dirname(path), exist_ok=True)

    sequence = 1
    if os.path.isfile(path):
        with open(path, "rb") as existing:
            sequence = sum(1 for _ in existing) + 1

    event["sequence"] = sequence
    event["id"] = f"{int(task_id)}-{sequence:06d}"
    with open(path, "a", encoding="utf-8") as output:
        output.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
    return event


async def record_execution_event(
    *,
    task_id: int,
    stage_num: int | None,
    phase: str,
    event_type: str,
    title: str,
    message: str = "",
    status: str = "",
    level: str = "info",
    model: str = "",
    duration_ms: int | None = None,
    prompt_chars: int | None = None,
    response_chars: int | None = None,
    token_usage: dict | None = None,
    error: str = "",
    prompt_preview: str = "",
    response_preview: str = "",
    meta: dict | None = None,
) -> dict | None:
    """Append a compact execution event.

    Logging failures are swallowed so audit execution is never blocked by the
    diagnostics channel.
    """

    try:
        event = _strip_empty_fields(
            {
                "task_id": int(task_id),
                "stage_num": int(stage_num) if stage_num is not None else None,
                "phase": phase,
                "event_type": event_type,
                "title": title,
                "message": message,
                "status": status,
                "level": level,
                "model": model,
                "duration_ms": duration_ms,
                "prompt_chars": prompt_chars,
                "response_chars": response_chars,
                "token_usage": _compact_value(token_usage) if token_usage else None,
                "error": _preview(error, MAX_META_STRING_CHARS) if error else "",
                "prompt_preview": _preview(prompt_preview, MAX_PROMPT_PREVIEW_CHARS) if prompt_preview else "",
                "response_preview": _preview(response_preview, MAX_RESPONSE_PREVIEW_CHARS) if response_preview else "",
                "meta": _compact_value(meta or {}),
                "ts": _now_iso(),
            }
        )
        async with _task_lock(int(task_id)):
            return await asyncio.to_thread(_append_event_sync, int(task_id), event)
    except Exception:
        logger.debug("Failed to record execution event for task %s", task_id, exc_info=True)
        return None


async def call_llm_with_events(
    config: LlmConfig,
    system_prompt: str,
    user_prompt: str,
    *,
    task_id: int,
    stage_num: int | None,
    phase: str,
    title: str,
    meta: dict | None = None,
) -> dict:
    """Call the LLM and emit start/success/error events around the request."""

    prompt_chars = len(user_prompt or "")
    event_meta = {
        "provider": getattr(config, "provider", ""),
        "api_mode": getattr(config, "api_mode", ""),
        "configured_model": getattr(config, "model_name", ""),
        "temperature": getattr(config, "temperature", None),
        "max_tokens": getattr(config, "max_tokens", None),
        "system_prompt_chars": len(system_prompt or ""),
        **(meta or {}),
    }
    await record_execution_event(
        task_id=task_id,
        stage_num=stage_num,
        phase=phase,
        event_type="llm_start",
        title=title,
        status="running",
        model=getattr(config, "model_name", ""),
        prompt_chars=prompt_chars,
        prompt_preview=user_prompt,
        meta=event_meta,
    )

    started = time.perf_counter()
    try:
        result = await call_llm_with_meta(config, system_prompt, user_prompt)
    except Exception as exc:
        duration_ms = int((time.perf_counter() - started) * 1000)
        await record_execution_event(
            task_id=task_id,
            stage_num=stage_num,
            phase=phase,
            event_type="llm_error",
            title=title,
            status="failed",
            level="error",
            model=getattr(config, "model_name", ""),
            duration_ms=duration_ms,
            prompt_chars=prompt_chars,
            error=str(exc),
            meta=event_meta,
        )
        raise

    result_meta = result.get("meta") if isinstance(result.get("meta"), dict) else {}
    duration_ms = int(result_meta.get("latency_ms") or ((time.perf_counter() - started) * 1000))
    if result.get("success"):
        content = result.get("content", "")
        await record_execution_event(
            task_id=task_id,
            stage_num=stage_num,
            phase=phase,
            event_type="llm_success",
            title=title,
            status="completed",
            level="success",
            model=str(result_meta.get("model") or getattr(config, "model_name", "")),
            duration_ms=duration_ms,
            prompt_chars=prompt_chars,
            response_chars=len(content or ""),
            token_usage=result_meta.get("usage"),
            response_preview=content,
            meta={**event_meta, "llm_meta": result_meta},
        )
    else:
        error_payload = result.get("error") if isinstance(result.get("error"), dict) else {}
        await record_execution_event(
            task_id=task_id,
            stage_num=stage_num,
            phase=phase,
            event_type="llm_error",
            title=title,
            status="failed",
            level="error",
            model=str(result_meta.get("model") or getattr(config, "model_name", "")),
            duration_ms=duration_ms,
            prompt_chars=prompt_chars,
            error=str(error_payload.get("message") or "LLM call failed"),
            meta={**event_meta, "llm_meta": result_meta, "llm_error": error_payload},
        )
    return result


def _event_matches(event: dict, *, stage_num: int | None, phase: str | None, event_type: str | None) -> bool:
    if stage_num is not None and int(event.get("stage_num") or 0) != int(stage_num):
        return False
    if phase and str(event.get("phase") or "") != phase:
        return False
    if event_type and str(event.get("event_type") or "") != event_type:
        return False
    return True


async def read_execution_events(
    task_id: int,
    *,
    stage_num: int | None = None,
    phase: str | None = None,
    event_type: str | None = None,
    since_sequence: int = 0,
    limit: int = 300,
) -> dict:
    limit = max(1, min(int(limit or 300), 1000))
    since_sequence = max(0, int(since_sequence or 0))
    path = _event_file_path(task_id)
    if not os.path.isfile(path):
        return {
            "items": [],
            "total": 0,
            "limit": limit,
            "last_sequence": 0,
            "has_more": False,
            "artifact_path": os.path.relpath(path, os.path.dirname(os.path.dirname(__file__))).replace("\\", "/"),
        }

    def _read_sync() -> dict:
        items: list[dict] = []
        matched_count = 0
        last_sequence = 0
        with open(path, "r", encoding="utf-8") as source:
            for line in source:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                sequence = int(event.get("sequence") or 0)
                last_sequence = max(last_sequence, sequence)
                if sequence <= since_sequence:
                    continue
                if not _event_matches(event, stage_num=stage_num, phase=phase, event_type=event_type):
                    continue
                matched_count += 1
                items.append(event)
                if len(items) > limit:
                    items = items[-limit:]
        return {
            "items": items,
            "total": matched_count,
            "limit": limit,
            "last_sequence": last_sequence,
            "has_more": matched_count > len(items),
            "artifact_path": os.path.relpath(path, os.path.dirname(os.path.dirname(__file__))).replace("\\", "/"),
        }

    return await asyncio.to_thread(_read_sync)

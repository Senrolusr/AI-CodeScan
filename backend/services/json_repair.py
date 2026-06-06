"""Small helpers for salvaging partial JSON emitted by LLM responses."""

from __future__ import annotations

import json


def decode_json_string_fragment(value: str) -> str:
    try:
        return json.loads(f'"{value}"')
    except Exception:
        return value.replace('\\"', '"').replace("\\n", "\n").replace("\\t", "\t").replace("\\r", "\r")


def extract_balanced_json_value(
    text: str,
    start_index: int,
    open_char: str = "{",
    close_char: str = "}",
) -> tuple[str, int]:
    depth = 0
    in_string = False
    escaped = False

    for index in range(start_index, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
            continue
        if char == open_char:
            depth += 1
            continue
        if char == close_char:
            depth -= 1
            if depth == 0:
                return text[start_index : index + 1], index + 1

    return "", start_index

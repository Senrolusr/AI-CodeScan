import re
from typing import Any, Iterable


_LINE_RANGE_RE = re.compile(r"^\s*[Ll]?\s*(\d+)\s*(?:[-~\u2013\u2014]\s*[Ll]?\s*(\d+))?\s*$")


def parse_line_number(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, float):
        if value.is_integer() and value > 0:
            return int(value)
        return None

    text = str(value).strip()
    if not text:
        return None

    if text.isdigit():
        number = int(text)
        return number if number > 0 else None

    match = _LINE_RANGE_RE.fullmatch(text)
    if not match:
        return None

    number = int(match.group(1))
    return number if number > 0 else None


def parse_line_bounds(
    line_start: Any = None,
    line_end: Any = None,
    *,
    candidates: Iterable[Any] | None = None,
) -> tuple[int | None, int | None]:
    start = parse_line_number(line_start)
    end = parse_line_number(line_end)

    for value in [line_start, line_end, *(list(candidates or []))]:
        parsed_start, parsed_end = _parse_line_range(value)
        if start is None:
            start = parsed_start
        if end is None:
            end = parsed_end
        if start is not None and end is not None:
            break

    if start is None and end is not None:
        start = end
    if start is not None and end is not None and end < start:
        start, end = end, start

    return start, end


def _parse_line_range(value: Any) -> tuple[int | None, int | None]:
    if value is None or isinstance(value, bool):
        return None, None

    text = str(value).strip()
    if not text:
        return None, None

    match = _LINE_RANGE_RE.fullmatch(text)
    if not match:
        return None, None

    start = int(match.group(1))
    end = int(match.group(2)) if match.group(2) else None
    if start <= 0:
        return None, None
    if end is not None and end <= 0:
        end = None
    return start, end

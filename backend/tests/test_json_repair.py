from services.json_repair import decode_json_string_fragment, extract_balanced_json_value


def test_decode_json_string_fragment_unescapes_quotes():
    assert decode_json_string_fragment('say \\"hi\\"') == 'say "hi"'


def test_decode_json_string_fragment_unescapes_newlines():
    assert decode_json_string_fragment("line1\\nline2") == "line1\nline2"


def test_decode_json_string_fragment_passthrough_on_garbage():
    # 非 JSON 安全字符时回退到手动替换，不应抛异常
    assert decode_json_string_fragment("plain") == "plain"


def test_extract_balanced_json_value_simple_object():
    text = 'prefix {"a": 1, "b": 2} suffix'
    start = text.index("{")
    value, end = extract_balanced_json_value(text, start)
    assert value == '{"a": 1, "b": 2}'
    assert end == start + len(value)


def test_extract_balanced_json_value_nested():
    text = '{"a": {"b": {"c": 3}}}'
    value, end = extract_balanced_json_value(text, 0)
    assert value == text
    assert end == len(text)


def test_extract_balanced_json_value_ignores_braces_in_strings():
    text = '{"a": "has } and { inside"}'
    value, _ = extract_balanced_json_value(text, 0)
    assert value == text


def test_extract_balanced_json_value_unclosed_returns_empty():
    text = '{"a": 1'  # never closes
    value, end = extract_balanced_json_value(text, 0)
    assert value == ""
    assert end == 0


def test_extract_balanced_json_value_array_with_braces():
    text = '[{"x": 1}, {"y": 2}]'
    start = text.index("[")
    value, end = extract_balanced_json_value(text, start, "[", "]")
    assert value == '[{"x": 1}, {"y": 2}]'
    assert end == len(text)

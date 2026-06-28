"""Rule-hit scoring engine: keyword tiers, evidence extraction, hit acceptance."""

from __future__ import annotations

from services.code_parser_pkg._constants import *  # noqa: F401,F403
from services.code_parser_pkg._text import *  # noqa: F401,F403

import logging

logger = logging.getLogger(__name__)

def _build_rule_hits(chunks: list[dict], max_hits: int = 120) -> list[dict]:
    best_hits: dict[tuple[str, str], dict] = {}

    for chunk in chunks:
        base_file_path = str(chunk.get("base_file_path", chunk.get("file_path", "")) or "").strip()
        content = str(chunk.get("content", "") or "")
        risk_labels = [str(label).lower() for label in (chunk.get("risk_labels") or []) if str(label).strip()]
        if not base_file_path or not content or not risk_labels:
            continue
        if _is_rule_noise_path(base_file_path):
            continue

        for label in risk_labels:
            keywords = RULE_HIT_KEYWORDS.get(label, [])
            if not keywords:
                continue
            stripped_content = _strip_comments_and_strings(content)
            hit_count = _count_rule_keyword_hits(stripped_content, keywords)
            if hit_count < int(RULE_HIT_MIN_HITS.get(label, 1)):
                continue
            weighted = _weighted_keyword_score(stripped_content, label)
            min_weighted = int(RULE_HIT_MIN_WEIGHTED.get(label, 3))
            if weighted < min_weighted:
                continue
            evidence = _extract_rule_evidence(content, keywords)
            if not evidence:
                continue
            if not _accept_rule_hit(label, base_file_path, evidence, hit_count):
                continue

            hit = {
                "label": label,
                "title": _rule_hit_title(label),
                "file_path": base_file_path,
                "chunk_path": str(chunk.get("file_path", "") or base_file_path),
                "chunk_type": str(chunk.get("chunk_type", "") or "full"),
                "risk_score": _score_rule_hit(label, chunk, hit_count, evidence, weighted),
                "keyword_hit_count": hit_count,
                "weighted_score": weighted,
                "stage_nums": RULE_LABEL_STAGE_MAP.get(label, []),
                "evidence": evidence[:280],
            }
            key = (base_file_path.lower(), label)
            previous = best_hits.get(key)
            if previous is None or hit["risk_score"] > int(previous.get("risk_score", 0) or 0):
                best_hits[key] = hit

    ordered = sorted(
        best_hits.values(),
        key=lambda item: (-int(item.get("risk_score", 0) or 0), item.get("file_path", ""), item.get("label", "")),
    )
    return ordered[:max_hits]

def _is_rule_noise_path(file_path: str) -> bool:
    normalized = str(file_path or "").lower()
    noise_markers = [
        # ---- Minified / compiled ----
        ".min.js", ".min.css", ".map",
        # ---- Static assets ----
        "/assets/", "\\assets\\", "/open/assets/", "\\open\\assets\\",
        "/cache/", "\\cache\\", "/fonts/", "\\fonts\\",
        "/images/", "\\images\\", "/img/", "\\img\\",
        "/icons/", "\\icons\\", "/svg/", "\\svg\\",
        "/media/", "\\media\\", "/video/", "\\video\\",
        # ---- Vendor / third-party libraries ----
        "jquery", "sweetalert", "fontawesome", "datatables", "plupload",
        "bootstrap", "lodash", "underscore", "moment.min",
        "react-dom.production", "react.production",
        "angular.min", "vue.min", "d3.min", "chart.min",
        "tinymce", "ckeditor", "monaco", "codemirror",
        "three.min", "echarts.min", "antd.min",
        "element-ui", "iview", "ant-design",
        # ---- Test / mock / fixture directories ----
        "/__tests__/", "\\__tests__\\",
        "/__mocks__/", "\\__mocks__\\",
        "/__fixtures__/", "\\__fixtures__\\",
        "/__snapshots__/", "\\__snapshots__\\",
        "/test/", "\\test\\", "/tests/", "\\tests\\",
        "/spec/", "\\spec\\", "/testing/", "\\testing\\",
        "/mock/", "\\mock\\", "/mocks/", "\\mocks\\",
        "/stub/", "\\stub\\", "/stubs/", "\\stubs\\",
        "/fixtures/", "\\fixtures\\",
        "/cypress/", "\\cypress\\",
        ".test.js", ".test.ts", ".spec.js", ".spec.ts",
        ".test.py", "_test.py", "_test.go", "_test.rb",
        # ---- Generated / migration directories ----
        "/migrations/", "\\migrations\\",
        "/generated/", "\\generated\\",
        "/auto_generated/", "\\auto_generated\\",
        "/proto/", "\\proto\\",
        # ---- Documentation / example ----
        "/docs/", "\\docs\\", "/examples/", "\\examples\\",
        "/demo/", "\\demo\\", "/sample/", "\\sample\\",
        "/playground/", "\\playground\\",
        # ---- Build output ----
        "/dist/", "\\dist\\", "/build/", "\\build\\",
        "/out/", "\\out\\", "/target/", "\\target\\",
        "/.next/", "/.nuxt/",
        # ---- IDE / OS metadata ----
        "/.idea/", "/.vscode/", "/.vs/",
        ".ds_store", "thumbs.db",
    ]
    return any(marker in normalized for marker in noise_markers)

def _extract_rule_evidence(content: str, keywords: list[str], window_radius: int = 2) -> str:
    if not content or not keywords:
        return ""

    lines = content.splitlines()
    for index, line in enumerate(lines):
        lowered = line.lower()
        if any(keyword in lowered for keyword in keywords):
            start = max(0, index - window_radius)
            end = min(len(lines), index + window_radius + 1)
            snippet = "\n".join(lines[start:end]).strip()
            if snippet:
                return snippet
    return ""

def _count_rule_keyword_hits(content: str, keywords: list[str]) -> int:
    lowered = (content or "").lower()
    return sum(1 for keyword in keywords if keyword in lowered)

def _weighted_keyword_score(content: str, label: str) -> int:
    """Compute a weighted score using strong (×3) / medium (×1) keyword tiers."""
    lowered = (content or "").lower()
    tiers = RULE_HIT_TIERS.get(label, {})
    strong = tiers.get("strong", [])
    medium = tiers.get("medium", [])
    score = sum(3 for kw in strong if kw in lowered)
    score += sum(1 for kw in medium if kw in lowered)
    return score

def _score_rule_hit(label: str, chunk: dict, hit_count: int, evidence: str, weighted_score: int = 0) -> int:
    base_score = int(chunk.get("risk_score", 0) or 0)
    chunk_type = str(chunk.get("chunk_type", "") or "")
    file_path = str(chunk.get("base_file_path", chunk.get("file_path", "")) or "").lower()
    score = base_score + weighted_score * 3 + hit_count * 2

    if chunk_type.startswith("oversized_signal"):
        score += 4
    elif chunk_type.startswith("oversized_"):
        score += 2

    label_paths = {
        "rce": ["exec", "command", "runtime", "serialize", "deserial", "queue", "worker"],
        "injection": ["sql", "query", "model", "dao", "repository", "db"],
        "xss": ["view", "template", "render", "html", "front", "admin"],
        "auth": ["login", "auth", "session", "oauth", "user", "token"],
        "config": ["config", "settings", ".env", "secret", "credential"],
        "file": ["upload", "download", "file", "path", "backup", "archive", "import", "export"],
        "business": ["order", "payment", "wallet", "coupon", "inventory", "trade"],
    }
    if any(token in file_path for token in label_paths.get(label, [])):
        score += 4

    evidence_lower = (evidence or "").lower()
    if label == "file" and not any(
        keyword in evidence_lower
        for keyword in ["file_get_contents", "readfile(", "fopen(", "unlink(", "rename(", "copy(", "upload", "download", "realpath", "basename(", "ziparchive", "extractto"]
    ):
        score -= 8
    if label == "config" and not any(
        keyword in evidence_lower
        for keyword in ["secret", "api_key", "apikey", "private_key", "access_key", "credentials", ".env", "database_url", "db_password", "token="]
    ):
        score -= 10
    if label == "business" and hit_count < 2:
        score -= 8

    return score

def _accept_rule_hit(label: str, file_path: str, evidence: str, hit_count: int) -> bool:
    normalized_path = str(file_path or "").lower()
    evidence_lower = (evidence or "").lower()

    if label in {"file", "business"} and any(
        normalized_path.endswith(ext) for ext in [".json", ".md", ".txt", ".yml", ".yaml", ".xml"]
    ):
        return False

    if "/lang/" in normalized_path or "\\lang\\" in normalized_path:
        return label in {"config"}

    if label == "file":
        strong_file_tokens = [
            "file_get_contents", "readfile(", "fopen(", "unlink(", "mkdir(", "rmdir(",
            "copy(", "rename(", "ziparchive", "extractto", "realpath", "basename(",
            "scandir(", "opendir(", "readdir(", "glob(", "move_uploaded_file",
        ]
        file_path_tokens = ["upload", "download", "file", "path", "archive", "backup", "import", "export"]
        return (
            any(token in evidence_lower for token in strong_file_tokens)
            or (hit_count >= 2 and any(token in normalized_path for token in file_path_tokens))
        )

    if label == "business":
        business_path_tokens = ["order", "payment", "wallet", "coupon", "inventory", "trade", "cart"]
        return hit_count >= 2 and any(token in normalized_path for token in business_path_tokens)

    if label == "config":
        if normalized_path.endswith(".sql"):
            return False
        strong_config_tokens = [
            "secret", "api_key", "apikey", "private_key", "access_key", "credentials",
            ".env", "database_url", "db_password", "client_secret", "appsecret",
        ]
        config_paths = ["config", "settings", ".env", "secret", "credential", "install", "verify", "admin/index.php"]
        weak_constructor_only = [
            "__construct($private_key", "__construct ($private_key", "getrandomstring(",
        ]
        if any(token in evidence_lower for token in weak_constructor_only):
            return False
        return (
            any(token in evidence_lower for token in strong_config_tokens)
            and (
                any(token in normalized_path for token in config_paths)
                or any(token in evidence_lower for token in ["md5(", "sha1(", "token=", "http_token", "appid=", "secret="])
            )
        )

    if label == "auth":
        if normalized_path.endswith(".sql"):
            return False
        strong_auth_tokens = [
            "login", "logout", "session_start", "session_regenerate_id", "setcookie", "jwt",
            "bearer", "oauth", "password_hash", "password_verify", "captcha", "signin", "signup",
            "validate()", "authorize", "permission", "role", "scope",
        ]
        primary_auth_tokens = [
            "login", "logout", "session_regenerate_id", "setcookie", "jwt", "bearer",
            "password_hash", "password_verify", "captcha", "signin", "signup",
            "validate()", "authorize", "permission", "grant_type", "authorization_code",
        ]
        auth_paths = ["login", "auth", "session", "oauth", "user", "token", "lock", "verify", "admin"]
        weak_auth_only = [
            "require_once 'session.php'", 'require_once "session.php"', "session_start();",
        ]
        weak_auth_paths = ["/role.php", "/user.php", "/log.php", "/index.php"]
        hard_auth_tokens = [
            "login", "logout", "session_regenerate_id", "password", "captcha", "jwt", "bearer",
            "validate()", "authorization_code", "grant_type", "setcookie", "header(\"location:?p=login",
        ]
        if hit_count < 2 and not any(token in normalized_path for token in auth_paths):
            return False
        if any(token in normalized_path for token in weak_auth_paths) and not any(
            token in evidence_lower for token in ["login", "logout", "validate()", "authorize", "permission", "grant_type", "authorization_code", "session_regenerate_id", "setcookie"]
        ):
            return False
        if any(token in normalized_path for token in ["/log.php", "/index.php"]) and not any(
            token in evidence_lower for token in ["header(\"location:?p=login", "header('location:?p=login", "validate()", "authorization_code", "grant_type", "session_regenerate_id", "setcookie", "password", "captcha"]
        ):
            return False
        if any(token in evidence_lower for token in weak_auth_only) and not any(
            token in evidence_lower for token in ["password", "jwt", "oauth", "setcookie", "session_regenerate_id", "validate()", "scope", "authorize", "permission"]
        ):
            return False
        return (
            any(token in evidence_lower for token in strong_auth_tokens)
            and any(token in evidence_lower for token in hard_auth_tokens)
            and any(token in evidence_lower for token in primary_auth_tokens)
            and any(token in normalized_path for token in auth_paths)
        )

    if label == "xss":
        xss_sink_tokens = [
            "innerhtml", "outerhtml", "document.write", "dangerouslysetinnerhtml", "v-html",
            "<script", "onerror=", "onclick=", "echo\"<script", "echo '<script",
        ]
        xss_source_tokens = [
            "$_get", "$_post", "$_request", "$_server", "$_cookie",
            "request.", "params", "query", "input", "form", "body", "json",
            "$_get[", "$_post[", "$request[", "$text", "$msg", "$message",
        ]
        soft_xss_flow_tokens = ["$url", "$redirect", "$return", "location.href", "window.location"]
        xss_paths = ["view", "template", "render", "html", "front", "admin", "session", "login"]
        if any(token in normalized_path for token in [".css", ".sql", ".json"]):
            return False
        return (
            any(token in evidence_lower for token in xss_sink_tokens)
            and (
                any(token in evidence_lower for token in xss_source_tokens)
                or (
                    any(token in evidence_lower for token in soft_xss_flow_tokens)
                    and any(token in evidence_lower for token in ["$_get", "$_post", "query", "input", "redirect="])
                )
            )
            and any(token in normalized_path for token in xss_paths)
        )

    return True

def _rule_hit_title(label: str) -> str:
    return {
        "rce": "危险执行/反序列化信号",
        "injection": "注入风险信号",
        "xss": "输出编码/XSS 信号",
        "auth": "认证鉴权信号",
        "config": "配置/敏感信息信号",
        "file": "文件操作信号",
        "business": "业务逻辑信号",
    }.get(label, f"{label} 信号")

__all__ = [
    '_build_rule_hits',
    '_is_rule_noise_path',
    '_extract_rule_evidence',
    '_count_rule_keyword_hits',
    '_weighted_keyword_score',
    '_score_rule_hit',
    '_accept_rule_hit',
    '_rule_hit_title',
]

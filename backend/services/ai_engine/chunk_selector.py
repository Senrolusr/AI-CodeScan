"""Per-stage chunk scoring, selection, and Stage-1 batching."""

from __future__ import annotations

import json
import math
import re

from services.ai_engine._utils import _truncate_text
from services.ai_engine._constants import STAGE1_BATCH_TARGET_LEN, STAGE1_MAX_PASSES, STAGE1_SOFT_MAX_BATCHES

import logging

logger = logging.getLogger(__name__)

def _is_static_asset_chunk(file_path: str) -> bool:
    path = str(file_path or "").lower()
    if not path:
        return False
    static_suffixes = (
        ".min.js",
        ".min.css",
        ".map",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".mp3",
        ".mp4",
        ".avi",
        ".pdf",
    )
    if path.endswith(static_suffixes):
        return True
    static_markers = [
        "/assets/",
        "\\assets\\",
        "/static/",
        "\\static\\",
        "/fonts/",
        "\\fonts\\",
        "/images/",
        "\\images\\",
        "/cache/index.html",
        "\\cache\\index.html",
    ]
    return any(marker in path for marker in static_markers)

def _score_stage8_chunk(chunk: dict) -> int:
    file_path = str(chunk.get("file_path", "") or "").lower()
    content_head = str(chunk.get("content", "") or "")[:6000].lower()
    haystack = f"{file_path}\n{content_head}"
    score = 0

    strong_keywords = [
        "move_uploaded_file",
        "readfile(",
        "file_get_contents",
        "file_put_contents",
        "fopen(",
        "fwrite(",
        "fread(",
        "unlink(",
        "mkdir(",
        "rmdir(",
        "copy(",
        "rename(",
        "ziparchive",
        "extractto",
        "realpath",
        "pathinfo(",
        "basename(",
        "scandir(",
        "opendir(",
        "readdir(",
        "glob(",
        "download",
        "upload",
        "attachment",
        "archive",
        "backup",
        "import",
        "export",
        "tempfile",
        "mktemp",
        "symlink",
        "readlink",
        "move_uploaded_file",
        "is_uploaded_file",
        "parse_ini_file",
        "chdir(",
        "chroot(",
        "multipartfile",
        "files.delete",
        "files.copy",
        "files.move",
        "fs.unlink",
        "fs.readfile",
        "fs.writefile",
        "filepath.join",
        "filepath.clean",
        "shutil.rmtree",
        "shutil.copy",
        "shutil.move",
        "shutil.unpack_archive",
        "sendfile",
        "send_file",
        "content-disposition",
        "phar(",
    ]
    medium_keywords = [
        "file",
        "path",
        "open(",
        "os.path",
        "filesystem",
        "storage",
        "saveas",
        "zip",
        "tar",
        "../",
        "..\\",
        "directory",
        "folder",
        "read(",
        "write(",
        "stream",
        "blob",
        "chunk",
        "buffer",
        "tmp",
        "temp",
        "filename",
        "extension",
        "mime_type",
        "content_type",
    ]
    weak_noise = [
        "index.html",
        "<html",
        "jquery",
        "sweetalert",
        "datatables",
        "fontawesome",
        "plupload.min",
        ".min.js", ".min.css",
        "bootstrap", "lodash.min", "underscore.min",
        "react-dom.production", "react.production",
        "angular.min", "vue.min", "d3.min", "chart.min",
        "tinymce", "ckeditor", "monaco", "codemirror",
        "three.min", "echarts.min", "antd.min",
        "element-ui", "ant-design",
        "/vendor/", "\\vendor\\",
        "/__tests__/", "\\__tests__\\",
        "/__mocks__/", "\\__mocks__\\",
        "/node_modules/", "\\node_modules\\",
        ".test.js", ".spec.js", ".test.ts", ".spec.ts",
        "_test.py", "_test.go",
        "/migrations/", "\\migrations\\",
        "/generated/", "\\generated\\",
        "/docs/", "\\docs\\",
        "/demo/", "\\demo\\",
    ]

    score += sum(4 for keyword in strong_keywords if keyword in haystack)
    score += sum(1 for keyword in medium_keywords if keyword in haystack)
    score -= sum(2 for keyword in weak_noise if keyword in haystack)

    if any(token in file_path for token in ["upload", "download", "file", "path", "backup", "archive", "import", "export"]):
        score += 4
    if any(token in file_path for token in ["/admin/", "\\admin\\", "/front/", "\\front\\"]):
        score += 1
    if any(file_path.endswith(ext) for ext in [".php", ".py", ".java", ".go", ".rb", ".cs", ".js", ".ts"]):
        score += 2
    if any(token in file_path for token in [".min.", "/cache/", "\\cache\\", "/open/assets/", "\\open\\assets\\"]):
        score -= 5

    return score

def _select_stage8_chunks(
    chunks: list[dict],
    route_files: set[str] | None = None,
    evidence_files: set[str] | None = None,
) -> list[dict]:
    scored = []
    fallback = []
    for chunk in chunks:
        file_path = str(chunk.get("file_path", "") or "")
        if _is_static_asset_chunk(file_path):
            continue
        score = _score_stage8_chunk(chunk) + _shared_chunk_priority_boost(
            chunk,
            stage_num=8,
            route_files=route_files,
            evidence_files=evidence_files,
        )
        if score > 0:
            scored.append((score, chunk))
        elif len(fallback) < 80:
            fallback.append(chunk)

    scored.sort(
        key=lambda item: (
            -item[0],
            str(item[1].get("file_path", "") or ""),
        )
    )
    selected = [chunk for _, chunk in scored[:24]]
    if len(selected) < 12:
        selected.extend(fallback[: 12 - len(selected)])
    return selected or chunks[:12]

def _score_stage4_chunk(chunk: dict) -> int:
    file_path = str(chunk.get("file_path", "") or "").lower()
    content_head = str(chunk.get("content", "") or "")[:7000].lower()
    haystack = f"{file_path}\n{content_head}"
    score = 0

    strong_keywords = [
        "innerhtml",
        "outerhtml",
        "document.write",
        "dangerouslysetinnerhtml",
        "v-html",
        "render(",
        "template",
        "echo $_get",
        "echo $_post",
        "htmlspecialchars",
        "strip_tags",
        "sanitize",
        "escape",
        "xss",
        "insertadjacenthtml",
        "domparser",
        "parsefromstring",
        "srcdoc",
        "javascript:",
        "bypasssecuritytrusthtml",
        "bypasssecuritytrusturl",
        "domsanitizer",
        "[innerhtml]",
        "v-bind:html",
        "contenteditable",
        "document.writeln",
        "writeln",
        "createtextnode",
        "object.data",
        "embed.src",
        "iframe.src",
        "location.href",
        "postmessage(",
    ]
    medium_keywords = [
        ".vue",
        ".jsx",
        ".tsx",
        ".html",
        "render",
        "html",
        "iframe",
        "script",
        "onclick",
        "onerror",
        "contenteditable",
        "onload=",
        "onfocus=",
        "onmouseover=",
        "data:",
        "encodeuricomponent",
        "decodeuricomponent",
        "textcontent",
        "innertext",
        "createelement",
    ]
    weak_noise = [
        ".min.js",
        ".min.css",
        "jquery.min",
        "fontawesome",
        "sweetalert",
        "datatables",
        "bootstrap", "lodash.min", "underscore.min",
        "react-dom.production", "react.production",
        "angular.min", "vue.min", "d3.min", "chart.min",
        "tinymce", "ckeditor", "monaco", "codemirror",
        "three.min", "echarts.min", "antd.min",
        "element-ui", "ant-design",
        "/vendor/", "\\vendor\\",
        "/__tests__/", "\\__tests__\\",
        "/__mocks__/", "\\__mocks__\\",
        "/node_modules/", "\\node_modules\\",
        ".test.js", ".spec.js", ".test.ts", ".spec.ts",
        "/docs/", "\\docs\\",
        "/demo/", "\\demo\\",
    ]

    score += sum(4 for keyword in strong_keywords if keyword in haystack)
    score += sum(1 for keyword in medium_keywords if keyword in haystack)
    score -= sum(2 for keyword in weak_noise if keyword in haystack)

    if any(token in file_path for token in ["template", "view", "render", "admin", "front"]):
        score += 2
    if any(file_path.endswith(ext) for ext in [".php", ".vue", ".jsx", ".tsx", ".js", ".ts", ".html"]):
        score += 2
    if any(token in file_path for token in ["/cache/", "\\cache\\", "/open/assets/", "\\open\\assets\\"]):
        score -= 5

    return score

def _select_stage4_chunks(
    chunks: list[dict],
    route_files: set[str] | None = None,
    evidence_files: set[str] | None = None,
) -> list[dict]:
    scored = []
    fallback = []
    for chunk in chunks:
        file_path = str(chunk.get("file_path", "") or "")
        if _is_static_asset_chunk(file_path):
            continue
        score = _score_stage4_chunk(chunk) + _shared_chunk_priority_boost(
            chunk,
            stage_num=4,
            route_files=route_files,
            evidence_files=evidence_files,
        )
        if score > 0:
            scored.append((score, chunk))
        elif len(fallback) < 80:
            fallback.append(chunk)

    scored.sort(key=lambda item: (-item[0], str(item[1].get("file_path", "") or "")))
    selected = [chunk for _, chunk in scored[:24]]
    if len(selected) < 12:
        selected.extend(fallback[: 12 - len(selected)])
    return selected or chunks[:12]

def _score_stage5_chunk(chunk: dict) -> int:
    file_path = str(chunk.get("file_path", "") or "").lower()
    content_head = str(chunk.get("content", "") or "")[:7000].lower()
    haystack = f"{file_path}\n{content_head}"
    score = 0

    strong_keywords = [
        "login",
        "logout",
        "session_start",
        "session_regenerate_id",
        "setcookie",
        "cookie(",
        "jwt",
        "bearer",
        "oauth",
        "password_hash",
        "password_verify",
        "md5(",
        "sha1(",
        "captcha",
        "token",
        "signin",
        "signup",
        "remember",
        "authenticate",
        "verify_token",
        "validate_token",
        "refresh_token",
        "access_token",
        "saml",
        "samlresponse",
        "kerberos",
        "ntlm",
        "recaptcha",
        "hcaptcha",
        "totp",
        "mfa",
        "2fa",
        "bcrypt",
        "argon2",
        "pbkdf2",
        "antiforgerytoken",
        "xsrf",
        "_csrf",
        "password_reset",
        "forgot_password",
        "session_destroy",
        "session_id(",
    ]
    medium_keywords = [
        "auth",
        "session",
        "cookie",
        "user",
        "role",
        "permission",
        "verify",
        "csrf",
        "credential",
        "secret",
        "authorization",
        "identity",
        "principal",
        "claim",
        "privilege",
        "oauth2",
        "openid",
        "sso",
        "logout",
        "register",
        "rate_limit",
        "throttle",
        "lockout",
        "login_attempts",
        "failed_attempts",
        "account_lock",
        "password_change",
        "changepassword",
    ]
    weak_noise = [
        ".min.js",
        ".min.css",
        "index.html",
        "jquery.min",
        "fontawesome",
        "datatables",
        "bootstrap", "lodash.min",
        "react-dom.production", "react.production",
        "angular.min", "vue.min",
        "tinymce", "ckeditor",
        "/vendor/", "\\vendor\\",
        "/__tests__/", "\\__tests__\\",
        "/__mocks__/", "\\__mocks__\\",
        "/node_modules/", "\\node_modules\\",
        ".test.js", ".spec.js", ".test.ts", ".spec.ts",
        "/docs/", "\\docs\\",
        "/demo/", "\\demo\\",
    ]

    score += sum(4 for keyword in strong_keywords if keyword in haystack)
    score += sum(1 for keyword in medium_keywords if keyword in haystack)
    score -= sum(2 for keyword in weak_noise if keyword in haystack)

    if any(token in file_path for token in ["login", "session", "oauth", "auth", "user", "role", "captcha", "token"]):
        score += 4
    if any(token in file_path for token in ["/admin/", "\\admin\\", "/front/", "\\front\\", "/api/", "\\api\\"]):
        score += 1
    if any(file_path.endswith(ext) for ext in [".php", ".py", ".java", ".go", ".rb", ".cs", ".js", ".ts"]):
        score += 2
    if any(token in file_path for token in ["/cache/", "\\cache\\", "/open/assets/", "\\open\\assets\\"]):
        score -= 5

    return score

def _select_stage5_chunks(
    chunks: list[dict],
    route_files: set[str] | None = None,
    evidence_files: set[str] | None = None,
) -> list[dict]:
    scored = []
    fallback = []
    for chunk in chunks:
        file_path = str(chunk.get("file_path", "") or "")
        if _is_static_asset_chunk(file_path):
            continue
        score = _score_stage5_chunk(chunk) + _shared_chunk_priority_boost(
            chunk,
            stage_num=5,
            route_files=route_files,
            evidence_files=evidence_files,
        )
        if score > 0:
            scored.append((score, chunk))
        elif len(fallback) < 80:
            fallback.append(chunk)

    scored.sort(key=lambda item: (-item[0], str(item[1].get("file_path", "") or "")))
    selected = [chunk for _, chunk in scored[:24]]
    if len(selected) < 12:
        selected.extend(fallback[: 12 - len(selected)])
    return selected or chunks[:12]

def _score_stage6_chunk(chunk: dict) -> int:
    file_path = str(chunk.get("file_path", "") or "").lower()
    content = str(chunk.get("content", "") or "")[:5000].lower()
    haystack = f"{file_path}\n{content}"
    score = 0

    strong_signals = [
        "permission", "permissions", "authorize", "authorization", "acl", "role", "roles",
        "tenant", "tenant_id", "owner", "ownership", "resource_id", "user_id", "account_id",
        "idor", "scope", "guard", "policy", "preauthorize", "haspermission", "isadmin",
        "hasrole", "hasauthority", "secured", "roles_allowed",
        "accesscontrol", "access_control", "rbac", "abac",
        "isauthenticated", "isfullyauthenticated", "isrememberme",
        "hasanyrole", "hasanyauthority", "withpermission",
        "checkpermission", "checkauthorization",
        "tenant隔离", "multi_tenant",
        "belongsto", "ownedby", "createdby",
        "resource_type", "target_id", "target_user",
        "impersonate", "sudo", "escalate", "privilege_escalation",
    ]
    medium_signals = [
        "admin", "member", "staff", "org_id", "project_id", "team_id", "customer_id",
        "current_user", "currentuser", "subject", "principal", "can_access", "allowed",
        "isowner", "ismember", "isadmin", "isstaff", "issuperuser",
        "department_id", "branch_id", "division_id",
        "belongs_to", "belongs_to_current_user",
        "filter_by_user", "filter_by_tenant", "scope_by",
        "visible_to", "accessible_by", "shared_with",
        "ownership_check", "access_check", "permission_check",
        "viewer", "editor", "contributor", "manager",
        "superadmin", "sysadmin", "root",
        "group_id", "organization_id", "company_id",
        "row_level", "field_level", "column_level",
    ]
    weak_noise = [
        "captcha", "logout", "forgot password", "reset password", "register", "signup",
        "/open/assets/", "\\open\\assets\\", "/cache/", "\\cache\\",
        ".min.js", ".min.css",
        "jquery", "sweetalert", "fontawesome", "datatables",
        "bootstrap", "lodash.min",
        "/vendor/", "\\vendor\\",
        "/__tests__/", "\\__tests__\\",
        "/__mocks__/", "\\__mocks__\\",
        "/node_modules/", "\\node_modules\\",
        ".test.js", ".spec.js", ".test.ts", ".spec.ts",
        "/docs/", "\\docs\\",
        "/demo/", "\\demo\\",
    ]

    score += sum(5 for keyword in strong_signals if keyword in haystack)
    score += sum(2 for keyword in medium_signals if keyword in haystack)
    score -= sum(2 for keyword in weak_noise if keyword in haystack)

    if any(token in file_path for token in ["permission", "authorize", "policy", "guard", "role", "tenant", "acl"]):
        score += 5
    if any(token in file_path for token in ["/controller", "/controllers/", "/service", "/services/", "/api/", "/routes/", "/routers/"]):
        score += 2
    if any(file_path.endswith(ext) for ext in [".php", ".py", ".java", ".go", ".rb", ".cs", ".js", ".ts"]):
        score += 1
    if _is_static_asset_chunk(file_path):
        score -= 8

    return score

def _select_stage6_chunks(
    chunks: list[dict],
    route_files: set[str] | None = None,
    evidence_files: set[str] | None = None,
) -> list[dict]:
    scored = []
    fallback = []
    for chunk in chunks:
        file_path = str(chunk.get("file_path", "") or "")
        if _is_static_asset_chunk(file_path):
            continue
        score = _score_stage6_chunk(chunk) + _shared_chunk_priority_boost(
            chunk,
            stage_num=6,
            route_files=route_files,
            evidence_files=evidence_files,
        )
        if score > 0:
            scored.append((score, chunk))
        elif len(fallback) < 60:
            fallback.append(chunk)

    scored.sort(key=lambda item: (-item[0], str(item[1].get("file_path", "") or "")))
    selected = [chunk for _, chunk in scored[:24]]
    if len(selected) < 12:
        selected.extend(fallback[: 12 - len(selected)])
    return selected or chunks[:12]

def _shared_chunk_priority_boost(
    chunk: dict,
    stage_num: int,
    route_files: set[str] | None = None,
    evidence_files: set[str] | None = None,
) -> int:
    route_files = route_files or set()
    evidence_files = evidence_files or set()
    file_path = str(chunk.get("file_path", "") or "")
    base_file_path = str(chunk.get("base_file_path", file_path) or file_path)
    normalized_path = base_file_path.lower()
    chunk_type = str(chunk.get("chunk_type", "") or "")
    risk_score = int(chunk.get("risk_score", 0) or 0)
    risk_labels = [str(label).lower() for label in (chunk.get("risk_labels") or []) if str(label).strip()]

    score = risk_score
    if normalized_path in route_files:
        score += 8
    if normalized_path in evidence_files:
        score += 6
    if chunk_type.startswith("oversized_signal"):
        score += 5
    elif chunk_type.startswith("oversized_"):
        score += 2

    stage_label_map = {
        2: {"rce"},
        3: {"injection"},
        4: {"xss"},
        5: {"auth"},
        6: {"auth"},
        7: {"config"},
        8: {"file"},
        9: {"business"},
    }
    if any(label in stage_label_map.get(stage_num, set()) for label in risk_labels):
        score += 8

    if any(token in normalized_path for token in ["/routes/", "/routers/", "/api/", "/controller", "/controllers/", "urls.py", "views.py"]):
        score += 3
    if any(token in normalized_path for token in ["/auth", "/security", "/middleware", "config", "settings", ".env"]):
        score += 2
    return score

def _select_stage_chunks(
    stage_num: int,
    chunks: list[dict],
    static_routes: list[dict] | None = None,
    audit_memory: dict | None = None,
    source_sink_hints: list[dict] | None = None,
    focus_files: list[str] | None = None,
    focus_functions: list[str] | None = None,
    pre_discovery: dict | None = None,
) -> list[dict]:
    route_files = {
        str(route.get("file_path", "")).strip().lower()
        for route in (static_routes or [])
        if isinstance(route, dict) and str(route.get("file_path", "")).strip()
    }
    evidence_files = {
        str(path).strip().lower()
        for path in (audit_memory or {}).get("evidence_files", [])
        if str(path).strip()
    }
    source_sink_files = {
        str(item.get("file_path", "")).strip().lower()
        for item in (source_sink_hints or [])
        if isinstance(item, dict)
        and stage_num in (item.get("stage_nums", []) if isinstance(item.get("stage_nums"), list) else [])
        and str(item.get("file_path", "")).strip()
    }
    evidence_files = evidence_files | source_sink_files
    focus_file_set = {
        str(f).strip().lower()
        for f in (focus_files or [])
        if str(f).strip()
    }
    focus_func_list = [str(f).strip().lower() for f in (focus_functions or []) if str(f).strip()]

    if stage_num == 1:
        return _select_stage1_skeleton_chunks(chunks, pre_discovery=pre_discovery)
    if stage_num == 4:
        return _select_stage4_chunks(chunks, route_files=route_files, evidence_files=evidence_files)
    if stage_num == 5:
        return _select_stage5_chunks(chunks, route_files=route_files, evidence_files=evidence_files)
    if stage_num == 6:
        return _select_stage6_chunks(chunks, route_files=route_files, evidence_files=evidence_files)
    if stage_num == 8:
        return _select_stage8_chunks(chunks, route_files=route_files, evidence_files=evidence_files)

    rules = {
        2: [
            "exec", "subprocess", "system", "shell", "eval", "popen", "runtime.exec", "processbuilder",
            "child_process", "pickle", "unserialize", "yaml.load", "marshal", "deserialize",
            "proc_open", "pcntl_exec", "assert", "vm.run", "class.forname", "scriptengine",
            "objectinputstream", "os/exec", "exec.command", "spawn", "compile",
            "jinja2", "freemarker", "velocity", "ognl", "spel", "mvel",
        ],
        3: [
            "sql", "query", "cursor", "mongodb", "redis", "orm", "database",
            "select ", "insert ", "update ", "delete ",
            "execute(", "raw(", "executescript(", "rawsql", "raw_query",
            "preparedstatement", "jdbctemplate", "hibernate", "mybatis",
            "sequelize", "knex", "typeorm", "prisma", "mongoose",
            "db.query", "db.exec", "gorm", "sqlx",
            "$where", "ldap_search", "graphql",
        ],
        4: [
            "xss", "csrf", ".vue", ".jsx", ".tsx", ".html", "template", "render",
            "innerhtml", "v-html", "document.write",
            "outerhtml", "dangerouslysetinnerhtml", "domparser",
            "insertadjacenthtml", "contenteditable",
            "srcdoc", "javascript:", "postmessage",
            "bypasssecuritytrust", "domsanitizer",
            "htmlspecialchars", "strip_tags", "escape", "sanitize",
        ],
        5: [
            "auth", "login", "jwt", "token", "session", "cookie", "oauth",
            "signin", "signup", "password", "captcha",
            "bearer", "authenticate", "verify_token",
            "saml", "kerberos", "ntlm",
            "recaptcha", "hcaptcha", "totp", "mfa", "2fa",
            "bcrypt", "argon2", "pbkdf2",
            "refresh_token", "access_token", "csrf",
        ],
        6: [
            "permission", "role", "acl", "authorize", "preauthorize",
            "idor", "tenant", "owner", "resource_id", "user_id",
            "authorization", "policy", "scope", "guard",
            "tenant_id", "account_id", "isadmin", "hasrole",
            "org_id", "project_id", "team_id",
            "current_user", "principal", "can_access",
            "ownership", "access_control",
        ],
        7: [
            ".env", "config", "settings", "docker", "compose",
            "yaml", "yml", "toml", "ini", "requirements", "package.json",
            "secret", "api_key", "private_key", "access_key", "credentials",
            "db_password", "database_url", "debug=true",
            "cors_origin", "allowed_hosts", "ssl", "tls",
            "aws_secret", "azure_key", "gcp_key",
            "kubernetes", "nginx", "apache",
            "github_token", "slack_token", "stripe_key",
            "0.0.0.0", "verify=false",
        ],
        8: [
            "file", "upload", "download", "path", "open(", "os.", "shutil", "zip", "tar",
            "fopen", "readfile", "file_get_contents", "unlink",
            "mkdir", "rmdir", "copy(", "rename(", "scandir",
            "realpath", "basename", "dirname", "glob(",
            "tempfile", "symlink", "move_uploaded_file",
            "fs.readfile", "fs.writefile", "multipartfile",
            "filepath.join", "os.path", "extractto",
            "../", "..\\",
        ],
        9: [
            "order", "payment", "amount", "price", "inventory", "coupon",
            "workflow", "status", "balance", "logic", "business",
            "refund", "withdraw", "deposit", "transfer",
            "invoice", "billing", "receipt", "tax",
            "discount", "promo", "voucher", "reward",
            "stock", "quantity", "merchant", "customer",
            "settlement", "commission", "profit",
            "approve", "reject", "cancel", "confirm",
            "points", "level", "vip", "membership",
            "quota", "threshold",
        ],
    }
    keywords = rules.get(stage_num, [])
    if not keywords:
        return chunks[:30]

    scored = []
    fallback = []
    for chunk in chunks:
        file_path = str(chunk.get("file_path", "") or "").lower()
        content_head = str(chunk.get("content", "") or "")[:4000].lower()
        haystack = f"{file_path}\n{content_head}"
        priority = _shared_chunk_priority_boost(
            chunk,
            stage_num=stage_num,
            route_files=route_files,
            evidence_files=evidence_files,
        )
        if file_path in source_sink_files:
            priority += 10
        if focus_file_set and file_path in focus_file_set:
            priority += 30
        if focus_func_list and any(fn in content_head for fn in focus_func_list):
            priority += 8
        if any(keyword in haystack for keyword in keywords):
            scored.append((priority + 12, chunk))
        elif priority > 0:
            scored.append((priority, chunk))
        elif len(fallback) < 120:
            fallback.append(chunk)

    target = 40 if stage_num == 1 else 32
    minimum = 20 if stage_num == 1 else 16
    scored.sort(key=lambda item: (-item[0], str(item[1].get("file_path", "") or "")))
    selected = [chunk for _, chunk in scored[:target]]
    if len(selected) < minimum:
        selected.extend(fallback[: minimum - len(selected)])
    return selected or chunks[:minimum]

def _is_high_signal_stage1_chunk(chunk: dict) -> bool:
    file_path = str(chunk.get("file_path", "")).lower()
    content = str(chunk.get("content", "")[:4000]).lower()
    high_signal_paths = [
        "main.py", "app.py", "server.js", "index.js", "manage.py",
        "/router", "/routers/", "/routes/", "/api/", "/controller", "/controllers/",
        "/middleware", "/auth", "/security", "urls.py", ".module.ts", "package.json",
        "requirements.txt", "pyproject.toml", ".env", "config",
    ]
    high_signal_content = [
        "include_router", "apirouter", "@router.", "@app.", "fastapi(",
        "jwt", "oauth", "session", "middleware", "auth", "login",
        "router.get(", "router.post(", "app.get(", "app.post(",
        "urlpatterns", "include(", "@controller(", "@module(",
        "permission", "authorize", "cookie", "csrf",
    ]
    return any(keyword in file_path for keyword in high_signal_paths) or any(
        keyword in content for keyword in high_signal_content
    )

def _prioritize_stage1_chunks(chunks: list[dict]) -> list[dict]:
    def score(chunk: dict) -> tuple[int, str]:
        file_path = str(chunk.get("file_path", "")).lower()
        content = str(chunk.get("content", "")[:4000]).lower()
        path_boost = 0
        content_boost = 0

        high_signal_paths = [
            "main.py", "app.py", "server.js", "index.js", "manage.py",
            "/router", "/routers/", "/routes/", "/api/", "/controller", "/controllers/",
            "/middleware", "/auth", "/security", "urls.py",
            "package.json", "requirements.txt", "pyproject.toml", ".env",
        ]
        high_signal_content = [
            "include_router", "apirouter", "@router.", "@app.", "fastapi(",
            "jwt", "oauth", "session", "middleware", "auth", "login",
            "router.get(", "router.post(", "app.get(", "app.post(",
        ]

        for keyword in high_signal_paths:
            if keyword in file_path:
                path_boost += 3
        for keyword in high_signal_content:
            if keyword in content:
                content_boost += 2

        # Smaller files often contain entry wiring and config that are cheap but high value.
        size_penalty = min(len(str(chunk.get("content", ""))) // 4000, 9)
        return (path_boost + content_boost - size_penalty, file_path)

    return sorted(chunks, key=score, reverse=True)

def _is_stage1_low_value_chunk(chunk: dict, must_keep_paths: set[str] | None = None) -> bool:
    file_path = str(chunk.get("file_path", "") or "").strip().lower()
    if not file_path:
        return True

    normalized_file_path = re.sub(r"#l\d+(?:-\d+)?$", "", file_path)
    must_keep_paths = must_keep_paths or set()
    if normalized_file_path in must_keep_paths:
        return False

    basename = normalized_file_path.replace("\\", "/").rsplit("/", 1)[-1]
    content = str(chunk.get("content", "")[:2000] or "").lower()

    low_value_exts = (
        ".md", ".txt", ".css", ".scss", ".sass", ".less", ".map",
        ".svg", ".png", ".jpg", ".jpeg", ".gif", ".woff", ".woff2", ".ttf",
    )
    if basename.endswith(low_value_exts):
        return True

    low_value_names = {"readme.md", "license", "license.md", "changelog", "changelog.md", "changes.md"}
    if basename in low_value_names:
        return True

    low_value_path_markers = [
        "/ckeditor/", "/codemirror/", "/tinymce/", "/ueditor/",
        "/styles/", "/style/", "/css/", "/fonts/", "/images/", "/img/",
        "/static/", "/assets/", "/public/", "/docs/", "/doc/", "/manual/",
        "/vendor/", "/dist/", "/build/",
    ]
    if any(marker in normalized_file_path for marker in low_value_path_markers):
        return True

    if basename.endswith(".min.js") or basename.endswith(".bundle.js"):
        return True

    # 阶段一只做入口与架构扫描，纯静态资源或第三方说明文档会稀释扫描预算。
    if "copyright" in content and "license" in content and len(content) < 1200:
        return True

    return False

def _is_stage1_entry_file(chunk: dict) -> bool:
    file_path = str(chunk.get("file_path", "")).lower()
    content = str(chunk.get("content", "")[:5000]).lower()
    strong_paths = [
        "/router", "/routers/", "/routes/", "/api/", "/controller", "/controllers/",
        "/middleware", "/auth", "/security", "/guard", "/permission", "/policy",
        "urls.py", "views.py", "handlers/", "endpoints/", "gateway", "proxy",
        "webhook", "callback", "dto", "schema", "serializer", "validator",
        "request", "response", "route.ts", "route.js", ".module.ts", "main.py", "app.py",
        "server.js", "index.js", "manage.py",
    ]
    strong_content = [
        "include_router", "apirouter", "@router.", "@app.", "fastapi(",
        "router.get(", "router.post(", "router.put(", "router.delete(",
        "app.get(", "app.post(", "app.put(", "app.delete(", "router.use(", "app.use(",
        "urlpatterns", "re_path(", "path(", "blueprint.route(", "route::",
        "include(", "@controller(", "@module(", "@requestmapping(", "@getmapping(", "@postmapping(",
        "gin.", ".group(", "middleware", "jwt", "oauth", "session", "permission",
        "authorize", "shouldbind", "bindjson", "validator", "schema", "dto",
    ]
    return any(keyword in file_path for keyword in strong_paths) or any(keyword in content for keyword in strong_content)

def _select_stage1_entry_chunks(chunks: list[dict]) -> list[dict]:
    selected = []
    seen_paths = set()

    for chunk in _prioritize_stage1_chunks(chunks):
        file_path = str(chunk.get("file_path", ""))
        normalized_path = file_path.lower()
        if not _is_stage1_entry_file(chunk):
            continue
        if normalized_path in seen_paths:
            continue
        seen_paths.add(normalized_path)
        selected.append(chunk)
        if len(selected) >= 120:
            break

    return selected

def _estimate_chunk_prompt_len(chunk: dict) -> int:
    return len(str(chunk.get("content", "") or "")) + len(str(chunk.get("file_path", "") or "")) + 32

def _estimate_chunks_prompt_len(chunks: list[dict]) -> int:
    return sum(_estimate_chunk_prompt_len(chunk) for chunk in chunks)

def _select_stage1_skeleton_chunks(chunks: list[dict], pre_discovery: dict | None = None) -> list[dict]:
    """Select Stage 1 skeleton chunks, enriched with pre-discovery signals."""
    rule_hit_scores: dict[str, int] = {}
    source_sink_scores: dict[str, int] = {}
    hub_boost: dict[str, int] = {}
    must_cover_set: set[str] = set()
    file_roles: dict[str, str] = {}

    if pre_discovery:
        for hit in (pre_discovery.get("rule_hits") or []):
            if isinstance(hit, dict):
                fp = str(hit.get("file_path", "")).strip().lower()
                if fp:
                    rule_hit_scores[fp] = rule_hit_scores.get(fp, 0) + int(hit.get("risk_score", 0) or 0)
        for hint in (pre_discovery.get("source_sink_hints") or []):
            if isinstance(hint, dict):
                fp = str(hint.get("file_path", "")).strip().lower()
                if fp:
                    source_sink_scores[fp] = source_sink_scores.get(fp, 0) + int(hint.get("risk_score", 0) or 0)
        ig = pre_discovery.get("import_graph") or {}
        for fp, score in (ig.get("hub_scores") or {}).items():
            hub_boost[str(fp).strip().lower()] = min(int(score), 10) * 2
        sf = pre_discovery.get("security_files") or {}
        must_cover_set = {fp.lower() for fp in (sf.get("must_cover_files") or [])}
        file_roles = {fp.lower(): role for fp, role in (ig.get("file_roles") or {}).items()}

    filtered_chunks = [chunk for chunk in chunks if not _is_stage1_low_value_chunk(chunk, must_keep_paths=must_cover_set)]
    candidate_chunks = filtered_chunks or chunks
    prioritized = _prioritize_stage1_chunks(candidate_chunks)
    entry_first = _select_stage1_entry_chunks(prioritized)

    def _pre_discovery_boost(chunk: dict) -> int:
        fp = str(chunk.get("file_path", "")).strip().lower()
        s = rule_hit_scores.get(fp, 0) // 10 + source_sink_scores.get(fp, 0) // 10 + hub_boost.get(fp, 0)
        if fp in must_cover_set:
            s += 50
        role = file_roles.get(fp, "")
        if role in {"auth", "middleware", "config", "route"}:
            s += 15
        elif role in {"controller", "service"}:
            s += 8
        return s

    scored = sorted(prioritized, key=lambda c: (-_pre_discovery_boost(c), str(c.get("file_path", ""))))
    entry_paths = {str(c.get("file_path", "")).lower() for c in entry_first}
    non_entry = [c for c in scored if str(c.get("file_path", "")).lower() not in entry_paths]
    merged = entry_first + non_entry

    selected: list[dict] = []
    seen_paths = set()
    # 阶段一要尽量覆盖完整审计集，不能再被固定文件数或固定总字符数硬截断。
    for chunk in merged:
        normalized_path = str(chunk.get("file_path", "")).lower()
        if normalized_path in seen_paths:
            continue
        selected.append(chunk)
        seen_paths.add(normalized_path)
    return selected or prioritized

def _split_chunks_for_stage1(
    chunks: list[dict],
    max_len: int = STAGE1_BATCH_TARGET_LEN,
    max_batches: int | None = None,
    pre_discovery: dict | None = None,
) -> list[list[dict]]:
    if not chunks:
        return [[]]

    if max_batches is None or max_batches <= 0:
        # 阶段一批次数按审计集体量动态扩展，避免大项目被固定 5 轮截断。
        estimated_total_len = _estimate_chunks_prompt_len(chunks)
        max_batches = max(STAGE1_MAX_PASSES, math.ceil(estimated_total_len / max(max_len, 1)))
    max_batches = max(1, max_batches)

    # Build import relationships for grouping related files together
    imports = {}
    if pre_discovery:
        imports = (pre_discovery.get("import_graph") or {}).get("imports") or {}

    # Build a file -> group_id mapping based on import relationships
    fp_to_idx = {str(c.get("file_path", "")).lower(): i for i, c in enumerate(chunks)}
    parent = list(range(len(chunks)))

    def _find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def _union(a: int, b: int):
        ra, rb = _find(a), _find(b)
        if ra != rb:
            parent[ra] = rb

    for i, chunk in enumerate(chunks):
        fp = str(chunk.get("file_path", "")).lower()
        for dep_fp in imports.get(fp, []):
            j = fp_to_idx.get(dep_fp.lower())
            if j is not None:
                _union(i, j)

    # Group chunks by their connected component, then assign groups to batches
    groups: dict[int, list[int]] = {}
    for i in range(len(chunks)):
        root = _find(i)
        groups.setdefault(root, []).append(i)

    # Sort groups: largest first to spread evenly
    sorted_groups = sorted(groups.values(), key=lambda g: (-len(g), g[0]))

    batches: list[list[dict]] = [[] for _ in range(max_batches)]
    batch_lens = [0 for _ in range(max_batches)]

    for group_indices in sorted_groups:
        # 保持导入关系相近的代码尽量落在同一轮，同时优先填充最轻的批次。
        best_idx = min(range(max_batches), key=lambda bi: batch_lens[bi])
        for idx in group_indices:
            chunk = chunks[idx]
            estimated_len = _estimate_chunk_prompt_len(chunk)
            batches[best_idx].append(chunk)
            batch_lens[best_idx] += estimated_len

    batches = [batch for batch in batches if batch]
    batches = _merge_stage1_batches_for_soft_cap(batches, soft_cap=STAGE1_SOFT_MAX_BATCHES)
    return batches or [chunks[:1]]

def _merge_stage1_batches_for_soft_cap(batches: list[list[dict]], soft_cap: int) -> list[list[dict]]:
    if not isinstance(batches, list):
        return batches

    soft_cap = max(1, int(soft_cap or 1))
    merged_batches = [list(batch) for batch in batches if batch]
    if len(merged_batches) <= soft_cap:
        return merged_batches

    batch_lens = [
        sum(_estimate_chunk_prompt_len(chunk) for chunk in batch)
        for batch in merged_batches
    ]

    while len(merged_batches) > soft_cap:
        smallest_idx = min(range(len(merged_batches)), key=lambda idx: (batch_lens[idx], len(merged_batches[idx])))
        target_candidates = [idx for idx in range(len(merged_batches)) if idx != smallest_idx]
        if not target_candidates:
            break
        target_idx = min(target_candidates, key=lambda idx: (batch_lens[idx], len(merged_batches[idx])))
        merged_batches[target_idx].extend(merged_batches[smallest_idx])
        batch_lens[target_idx] += batch_lens[smallest_idx]
        del merged_batches[smallest_idx]
        del batch_lens[smallest_idx]

    return merged_batches

def _frontload_route_related_stage1_chunks(chunks: list[dict], static_routes: list[dict]) -> list[dict]:
    route_files = set()
    for route in static_routes:
        if not isinstance(route, dict):
            continue
        file_path = str(route.get("file_path", "")).strip()
        if file_path:
            route_files.add(file_path.lower())

    def score(chunk: dict) -> tuple[int, int, str]:
        file_path = str(chunk.get("file_path", "")).lower()
        content = str(chunk.get("content", "")[:4000]).lower()
        route_file_boost = 0
        path_boost = 0
        content_boost = 0

        if file_path in route_files:
            route_file_boost += 10

        route_paths = [
            "/router", "/routers/", "/routes/", "/api/", "/controller", "/controllers/",
            "urls.py", "views.py", "handlers/", "endpoints/", "gateway", "proxy",
            "webhook", "callback", "resolver", "resource", "route.ts", "route.js", ".module.ts",
        ]
        support_paths = [
            "/middleware", "/auth", "/security", "permission", "acl", "guard", "interceptor",
            "dto", "schema", "serializer", "validator", "request", "response", "policy",
        ]
        route_content = [
            "include_router", "apirouter", "@router.", "@app.", "fastapi(",
            "router.get(", "router.post(", "router.put(", "router.delete(",
            "app.get(", "app.post(", "app.put(", "app.delete(",
            "blueprint.route(", "route::", "urlpatterns", "re_path(", "path(",
            "include(", "router.use(", "app.use(", "@controller(", "@module(", "@get(", "@post(", "@requestmapping(",
            "@getmapping(", "@postmapping(", ".group(", "gin.",
        ]
        support_content = [
            "jwt", "oauth", "session", "middleware", "auth", "login",
            "permission", "authorize", "cookie", "csrf", "bindjson", "shouldbind",
            "validator", "schema", "dto", "serialize", "deserialize",
        ]

        for keyword in route_paths:
            if keyword in file_path:
                path_boost += 4
        for keyword in support_paths:
            if keyword in file_path:
                path_boost += 2
        for keyword in route_content:
            if keyword in content:
                content_boost += 3
        for keyword in support_content:
            if keyword in content:
                content_boost += 1

        size_penalty = min(len(str(chunk.get("content", ""))) // 6000, 6)
        return (route_file_boost + path_boost + content_boost - size_penalty, -len(file_path), file_path)

    return sorted(chunks, key=score, reverse=True)

def _build_stage1_pass_context(prev_context: str, compressed_summary: dict, pass_index: int, total_passes: int) -> str:
    sections = []
    if prev_context:
        sections.append(_truncate_text(prev_context, 5000 if pass_index > 1 else 8000))

    sections.append(f"[Stage 1 Multi-pass Progress] Current pass {pass_index}/{total_passes}.")
    sections.append("[Current Compressed Summary]")
    sections.append(_truncate_text(json.dumps(compressed_summary, ensure_ascii=False), 5000 if pass_index > 1 else 8000))
    sections.append("Requirement: continue filling new architecture, route, and data-flow findings based on the compressed summary above. Do not repeat large amounts of already confirmed information.")
    return "\n".join(sections)

__all__ = [
    '_is_static_asset_chunk',
    '_score_stage8_chunk',
    '_select_stage8_chunks',
    '_score_stage4_chunk',
    '_select_stage4_chunks',
    '_score_stage5_chunk',
    '_select_stage5_chunks',
    '_score_stage6_chunk',
    '_select_stage6_chunks',
    '_shared_chunk_priority_boost',
    '_select_stage_chunks',
    '_is_high_signal_stage1_chunk',
    '_prioritize_stage1_chunks',
    '_is_stage1_low_value_chunk',
    '_is_stage1_entry_file',
    '_select_stage1_entry_chunks',
    '_estimate_chunk_prompt_len',
    '_estimate_chunks_prompt_len',
    '_select_stage1_skeleton_chunks',
    '_split_chunks_for_stage1',
    '_merge_stage1_batches_for_soft_cap',
    '_frontload_route_related_stage1_chunks',
    '_build_stage1_pass_context',
]

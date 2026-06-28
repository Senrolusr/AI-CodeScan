"""Source-sink hint generation for downstream audit staging."""

from __future__ import annotations

from services.code_parser_pkg._utils import *  # noqa: F401,F403
from services.code_parser_pkg._text import *  # noqa: F401,F403
from services.code_parser_pkg.rules import *  # noqa: F401,F403

import logging

logger = logging.getLogger(__name__)

def _build_source_sink_hints(chunks: list[dict], static_routes: list[dict], max_hints: int = 120) -> list[dict]:
    route_map: dict[str, list[dict]] = {}
    for route in static_routes:
        if not isinstance(route, dict):
            continue
        file_path = str(route.get("file_path", "") or "").strip()
        if not file_path:
            continue
        route_map.setdefault(file_path, []).append(route)

    sources = [
        ("query", ["request.args", "request.get(", "request.getlist(", "request.query_params", "request.query", "request.get_json", "request.form", "request.files", "request.body", "request.post", "request.data", "request.json", "ctx.query", "ctx.params", "querystring", "$_get", "$_post", "$_request", "input(", "formdata", "req.query", "req.params", "req.body", "c.queryparam", "c.formvalue", "c.param", "ctx.request.body", "params[", "request.parameter", "request.getparameter", "httpservletrequest", "req.param(", "c.request(", "request.input", "inputstream", "request.input", "httpcontext"]),
        ("db_input", ["username", "password", "token", "role", "user_id", "order", "price", "amount", "path", "file", "code", "captcha", "account_id", "tenant_id", "resource_id", "org_id", "customer_id", "balance", "coupon", "discount", "status", "url", "redirect", "email", "phone"]),
    ]
    sink_specs = {
        "rce": {
            "stage_nums": [2],
            "sinks": [
                "exec(", "eval(", "system(", "popen(", "subprocess",
                "runtime.exec", "processbuilder", "pickle.loads", "yaml.load(",
                "unserialize(", "deserialize(",
                "shell_exec", "passthru(", "proc_open", "pcntl_exec",
                "os.system", "os.popen", "child_process",
                "assert(", "compile(", "vm.runincontext",
                "class.forname", "scriptengine", "objectinputstream",
                "os/exec", "exec.command", "spawn(",
                "marshal.loads", "cPickle.loads",
                "jinja2", "freemarker", "velocity", "ognl", "spel",
            ],
            "title": "外部输入到危险执行链",
        },
        "injection": {
            "stage_nums": [3],
            "sinks": [
                "select ", "insert ", "update ", "delete ", "execute(", "executemany(",
                "query(", "raw(", "$where", "cursor",
                "executescript(", "rawsql", "raw_query", "text(",
                "preparedstatement", "jdbctemplate", "hibernate",
                "sequelize", "knex.raw", "typeorm", "prisma",
                "db.query", "db.exec", "gorm", "sqlx",
                ".extra(", ".rawquery", "createorreplace",
                "cursor.execute", "mysqli_query", "pg_query",
                "ldap_search", "graphql",
            ],
            "title": "外部输入到注入类 sink",
        },
        "xss": {
            "stage_nums": [4],
            "sinks": [
                "innerhtml", "outerhtml", "document.write", "dangerouslysetinnerhtml",
                "v-html", "render(", "template", "html",
                "insertadjacenthtml", "domparser", "srcdoc",
                "javascript:", "bypasssecuritytrusthtml",
                "contenteditable", "postmessage(",
                "[innerhtml]", "v-bind:html",
            ],
            "title": "外部输入到输出渲染点",
        },
        "auth": {
            "stage_nums": [5, 6],
            "sinks": [
                "login", "session", "jwt", "token", "captcha",
                "permission", "authorize", "role", "owner", "tenant", "user_id",
                "authenticate", "verify_token", "password_verify",
                "session_regenerate_id", "setcookie",
                "csrf", "bearer", "oauth",
                "saml", "kerberos", "totp", "mfa",
                "account_id", "resource_id",
            ],
            "title": "外部输入到认证授权判断点",
        },
        "file": {
            "stage_nums": [8],
            "sinks": [
                "open(", "fopen(", "readfile(", "file_get_contents",
                "unlink(", "rename(", "copy(", "move_uploaded_file",
                "extractto", "realpath", "basename(", "scandir(", "glob(",
                "file_put_contents", "mkdir(", "rmdir(",
                "multipartfile", "files.delete", "files.copy",
                "fs.readfile", "fs.writefile", "fs.unlink",
                "filepath.join", "shutil.rmtree", "shutil.copy",
                "tempfile", "symlink",
            ],
            "title": "外部输入到文件操作点",
        },
        "business": {
            "stage_nums": [9],
            "sinks": [
                "order", "payment", "price", "amount", "inventory",
                "coupon", "balance", "status", "money",
                "refund", "withdraw", "deposit", "transfer",
                "invoice", "billing", "receipt", "tax",
                "discount", "promo", "voucher", "reward",
                "settlement", "commission", "profit",
            ],
            "title": "外部输入到业务关键字段",
        },
    }

    hints: list[dict] = []
    seen = set()
    for chunk in chunks:
        if not isinstance(chunk, dict):
            continue
        base_file_path = str(chunk.get("base_file_path", chunk.get("file_path", "")) or "").strip()
        chunk_path = str(chunk.get("file_path", "") or base_file_path).strip()
        content = str(chunk.get("content", "") or "")
        lowered = _strip_comments_and_strings(content[:16000]).lower()
        if not base_file_path or not lowered:
            continue

        matched_sources = []
        for source_name, keywords in sources:
            if any(keyword in lowered for keyword in keywords):
                matched_sources.append(source_name)
        if not matched_sources:
            continue

        related_routes = route_map.get(base_file_path, [])
        route_paths = _dedupe_preserve_order([str(route.get("path", "") or "").strip() for route in related_routes if str(route.get("path", "") or "").strip()])

        for label, spec in sink_specs.items():
            matched_sink_keywords = [keyword for keyword in spec["sinks"] if keyword in lowered]
            if not matched_sink_keywords:
                continue
            evidence = _extract_rule_evidence(content, matched_sink_keywords, window_radius=3)
            route_bonus = 4 if route_paths else 0
            risk_labels = [str(item).lower() for item in (chunk.get("risk_labels") or []) if str(item).strip()]
            label_bonus = 5 if label in risk_labels or (label == "auth" and any(item in risk_labels for item in ["auth", "business"])) else 0
            risk_score = int(chunk.get("risk_score", 0) or 0) + len(matched_sources) * 4 + len(matched_sink_keywords) * 5 + route_bonus + label_bonus
            key = (base_file_path.lower(), label, ",".join(route_paths[:3]), ",".join(sorted(matched_sink_keywords[:3])))
            if key in seen:
                continue
            seen.add(key)
            hints.append(
                {
                    "title": spec["title"],
                    "label": label,
                    "stage_nums": spec["stage_nums"],
                    "file_path": base_file_path,
                    "chunk_path": chunk_path,
                    "source_types": matched_sources,
                    "sink_keywords": matched_sink_keywords[:8],
                    "route_paths": route_paths[:8],
                    "risk_score": risk_score,
                    "evidence": evidence[:360] if evidence else "",
                }
            )

    hints.sort(key=lambda item: (-int(item.get("risk_score", 0) or 0), item.get("file_path", ""), item.get("label", "")))
    return hints[:max_hints]

__all__ = [
    '_build_source_sink_hints',
]

import os
import json
import re
import hashlib

from services.config import (
    MAX_FILE_SIZE, MAX_FILES, TOTAL_CHARS_LIMIT,
    CACHE_SCHEMA_VERSION, OVERSIZED_HEAD_CHARS, OVERSIZED_TAIL_CHARS,
    OVERSIZED_MAX_WINDOWS, OVERSIZED_WINDOW_RADIUS,
)

# Extensions that are typically source code
CODE_EXTENSIONS = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".py", ".pyw",
    ".java", ".kt", ".scala",
    ".go", ".rs", ".c", ".cpp", ".h", ".hpp",
    ".rb", ".php", ".cs", ".swift",
    ".vue", ".svelte",
    ".sh", ".bash", ".zsh",
    ".sql", ".graphql",
    ".html", ".htm", ".css", ".scss", ".less", ".sass",
    ".json", ".yaml", ".yml", ".toml", ".xml", ".ini", ".cfg",
    ".md", ".txt", ".env",
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".svn", ".hg",
    "dist", "build", "out", "target", ".next", ".nuxt",
    "vendor", ".venv", "venv", "env", ".tox",
    ".idea", ".vscode", ".vs",
}

CACHE_ROOT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "project_cache")

RISK_KEYWORDS = {
    "rce": [
        "exec(", "eval(", "system(", "shell_exec", "passthru(", "popen(", "subprocess",
        "runtime.exec", "processbuilder", "child_process", "os.system", "pickle.loads",
        "yaml.load(", "marshal.loads", "deserialize", "unserialize",
        "assert(", "compile(", "proc_open", "pcntl_exec", "vm.run",
        "class.forname", "scriptengine", "objectinputstream", "readobject(",
        "os/exec", "exec.command", "spawn(", "ioctl(", "syscall(",
        "codebase", "jinja2", "freemarker", "velocity", "ognl", "spel",
    ],
    "injection": [
        "select ", "insert ", "update ", "delete ", "execute(", "executemany(", "raw(",
        "cursor", "query(", "$where", "mongodb", "redis", "sql", "orm", "statement",
        "preparedstatement", "jdbctemplate", "hibernate", "mybatis",
        "sequelize", "knex", "typeorm", "prisma", "mongoose",
        "db.query", "db.exec", "gorm", "sqlx",
        "ldap_search", "ldap_bind", "graphql", "mutation {",
        "executescript(", "rawsql", "raw_query", "text(",
    ],
    "xss": [
        "innerhtml", "outerhtml", "document.write", "dangerouslysetinnerhtml", "v-html",
        "render(", "template", "onclick", "onerror", "<script", "htmlspecialchars",
        "v-text", "insertadjacenthtml", "domparser", "contenteditable",
        "srcdoc", "javascript:", "data:", "postmessage(",
        "bypasssecuritytrust", "domsanitizer", "[innerhtml]",
        "strip_tags", "sanitize", "escape", "encodeuri",
    ],
    "auth": [
        "auth", "login", "logout", "session", "cookie", "jwt", "token", "oauth",
        "password", "captcha", "permission", "authorize", "role", "csrf",
        "signin", "signup", "authenticate", "bearer", "verify_token",
        "saml", "samlresponse", "kerberos", "ntlm",
        "recaptcha", "hcaptcha", "totp", "mfa", "2fa",
        "bcrypt", "argon2", "pbkdf2", "scrypt",
        "rate_limit", "throttle", "lockout", "login_attempts",
        "refresh_token", "access_token", "antiforgerytoken",
    ],
    "file": [
        "upload", "download", "file_get_contents", "fopen(", "readfile(", "open(",
        "realpath", "path", "os.path", "shutil", "zip", "tar", "../", "..\\",
        "move_uploaded_file", "attachment",
        "file_put_contents", "unlink(", "mkdir(", "rmdir(", "copy(", "rename(",
        "scandir(", "opendir(", "readdir(", "glob(", "basename(", "dirname(",
        "tempfile", "tmpfile", "symlink", "readlink",
        "fs.readfile", "fs.writefile", "fs.unlink",
        "files.delete", "files.copy", "multipartfile",
        "os.open", "os.create", "filepath.join",
        "extractto", "ziparchive", "phar(",
        "..%2f", "..%5c", "%2e%2e",
    ],
    "config": [
        ".env", "secret", "apikey", "api_key", "password", "token", "private_key",
        "access_key", "credentials", "config", "settings", "docker", "compose",
        "secret_key", "app_secret", "api_secret",
        "db_password", "database_url", "debug=true", "debug=1",
        "cors_origin", "allowed_hosts", "allowed_origins",
        "aws_secret", "azure_key", "gcp_key",
        "ssl", "tls", "certificate", "0.0.0.0",
        "nginx", "apache", "kubernetes", "k8s",
        "github_token", "slack_token", "stripe_key",
        "package.json", "requirements.txt", "pom.xml", "go.mod",
        ".git", ".svn", "backup.sql", "dump.sql",
    ],
    "business": [
        "order", "payment", "amount", "price", "inventory", "coupon", "balance",
        "workflow", "status", "business", "tenant", "owner",
        "refund", "withdraw", "deposit", "transfer", "recharge",
        "invoice", "billing", "receipt", "tax",
        "discount", "promo", "voucher", "reward",
        "stock", "quantity", "sku",
        "approve", "reject", "cancel", "confirm",
        "merchant", "seller", "buyer", "customer",
        "settlement", "commission", "profit", "margin",
        "points", "level", "vip", "membership",
        "quota", "limit", "threshold", "cap",
    ],
}

RULE_LABEL_STAGE_MAP = {
    "rce": [2],
    "injection": [3],
    "xss": [4],
    "auth": [5, 6],
    "config": [7],
    "file": [8],
    "business": [9],
    "ssrf": [2, 3],
    "xxe": [2, 3],
    "crypto": [5, 7],
}

RULE_HIT_KEYWORDS = {
    "rce": [
        # ---- Python ----
        "exec(", "eval(", "system(", "os.system", "os.popen", "popen(", "subprocess",
        "subprocess.call", "subprocess.run", "subprocess.Popen", "subprocess.check_output",
        "subprocess.check_call", "os.exec", "os.spawn", "commands.getoutput",
        "pickle.loads", "pickle.load(", "cPickle.loads", "shelve.open",
        "yaml.load(", "yaml.unsafe_load(", "yaml.full_load(", "ruamel.yaml",
        "marshal.loads", "marshal.load(", "shutil.unpack_archive",
        "codebase.exec", "codebase.eval", "compile(",
        # ---- PHP ----
        "shell_exec", "passthru(", "system(", "exec(", "popen(",
        "proc_open", "pcntl_exec", "pcntl_fork",
        "unserialize(", "assert(", "preg_replace(", "create_function(",
        "call_user_func(", "call_user_func_array(",
        # ---- Java ----
        "runtime.exec", "runtime.getruntime", "processbuilder", "processbuilder(",
        "class.forname", "getruntime().exec", "scriptengine", "nashorn",
        "objectinputstream", "readobject(", "xmldecoder", "xstream",
        "ysoserial", "invocationhandler", "rmi://",
        # ---- Node.js / JavaScript ----
        "child_process", "child_process.exec", "child_process.spawn",
        "child_process.fork", "require('child_process')",
        "vm.runincontext", "vm.runinnewcontext", "vm.runinthiscontext",
        "new function(", "settimeout(", "setinterval(",
        "function(", "eval(",
        # ---- Go ----
        "os/exec", "exec.command", "exec.commandcontext", "cmd.run",
        "cmd.start", "cmd.output", "cmd.combinedoutput",
        # ---- Ruby ----
        "system(", "exec(", "ioctl(", "syscall(", "spawn(",
        "open(", "open3.", "io.popen", "kernel.system",
        "eval(", "binding.eval", "instance_eval", "class_eval",
        # ---- .NET / C# ----
        "process.start", "processstartinfo", "diagnostics.process",
        # ---- Deserialization / General ----
        "deserialize(", "from_json", "object_from", "json_serializable",
        "jsonpickle", "jsonpickle.decode", "jsonpickle.encode",
        "objectmapper.readvalue", "jackson.readvalue",
        "fastjson", "fastjson.parse", "gson.fromjson",
        "kotlinx.serialization", "swift.jsondecoder",
        # ---- Template injection ----
        "jinja2", "jinja2.template", "render_template_string",
        "mako.template", "tornado.template", "freemarker",
        "velocity", "thymeleaf", "twig", "smarty", "erb(",
        "stringtemplate", "handlebars.compile", "mustache.render",
        "nunjucks", "ejs.render", "pug.render",
        # ---- Expression Language ----
        "el(", "${", "#{", "ognl", "spel", "mvel",
    ],
    "injection": [
        # ---- SQL - General ----
        "select ", "select*", "insert into", "insert ", "update ", "update ",
        "delete from", "delete ", "drop table", "drop database", "truncate ",
        "alter table", "create table", "union select", "union all",
        # ---- Python DB ----
        "execute(", "executemany(", "executescript(", "query(", "prepare(",
        "raw(", "cursor.execute", "cursor.executemany",
        "rawsql", "raw_query", "execute_sql", "text(",
        "sqlalchemy", ".execute(", ".from_sql",
        ".extra(", ".rawquery", ".raw(", ".createorreplace",
        "sqlite3.execute", "sqlite3.connect",
        # ---- PHP DB ----
        "mysqli_query", "mysqli_fetch", "mysqli_prepare", "mysqli_real_query",
        "mysql_query", "mysql_fetch", "mysql_db_query",
        "pg_query", "pg_send_query", "pg_prepare", "pg_execute",
        "sqlsrv_query", "oci_execute", "oci_parse",
        "pdo->query", "pdo->exec", "pdo->prepare",
        "sqlite_query", "sqlite_single_query", "sqlite_exec",
        "oci_parse", "ora_exec", "ingres_query",
        # ---- Java DB ----
        "preparedstatement", "statement.execute", "statement.executequery",
        "statement.executeupdate", "jdbctemplate.query", "jdbctemplate.update",
        "jdbctemplate.execute", "namedparameterjdbctemplate",
        "hibernate.createquery", "hibernate.createsqlquery",
        "entitymanager.createnativequery", "session.createsqlquery",
        "mybatis select", "mybatis insert", "mybatis update",
        # ---- Node.js / JS DB ----
        "sequelize.query", "sequelize.raw", "knex.raw", "knex.whereRaw",
        "typeorm.query", "typeorm.querybuilder", "prisma.$queryraw",
        "mongoose.where", "mongodb.find", "mongodb.aggregate",
        # ---- Go DB ----
        "db.query", "db.exec", "db.queryrow", "db.queryrowcontext",
        "gorm.raw", "gorm.exec", "xorm.exec", "sqlx.query",
        # ---- NoSQL ----
        "$where", "$gt", "$lt", "$ne", "$or", "$and", "$regex", "$expr",
        "mongodb", "mongo.find", "mongo.aggregate", "mongo.where",
        "redis", "redis.get", "redis.set", "redis.eval",
        # ---- ORM / Query Builder ----
        "orm", "statement", "createorreplace", "buildquery",
        ".filter(", ".annotate(", ".aggregate(", ".extra(",
        # ---- GraphQL / LDAP ----
        "graphql", "mutation {", "query {", "fragment",
        "ldap_search", "ldap_bind", "ldap_add",
    ],
    "xss": [
        # ---- DOM Manipulation ----
        "innerhtml", "outerhtml", "document.write", "document.writeln",
        "writeln", "insertadjacenthtml", "insertadjacenttext",
        "domparser", "parsefromstring", "createtextnode",
        "createelement", "createelementns", "appendchild",
        "replacechild", "insertbefore", "setattribute",
        "innerhtml =", "outerhtml =",
        # ---- React / Vue / Angular ----
        "dangerouslysetinnerhtml", "dangerouslysetinnerhtml:",
        "v-html", "v-text", "v-bind:html",
        "{{{", "::", "[innerhtml]",
        "bypasssecuritytrusthtml", "bypasssecuritytrustresourceurl",
        "bypasssecuritytrustscript", "bypasssecuritytrusturl",
        "sanitizer.bypasssecuritytrust", "domsanitizer",
        # ---- Event Handlers ----
        "<script", "onerror=", "onclick=", "onload=", "onmouseover=",
        "onfocus=", "onblur=", "onsubmit=", "onchange=",
        "oninput=", "onkeydown=", "onkeyup=", "onkeypress=",
        "onmousedown=", "onmouseup=", "ondblclick=",
        "ondrag=", "ondragstart=", "ondragend=",
        "oncontextmenu=", "onanimationend=",
        # ---- PHP Output ----
        "echo\"", "echo '", "echo $_get", "echo $_post", "echo $_request",
        "echo $_server", "echo htmlspecialchars", "echo htmlentities",
        "print(", "printf(", "sprintf(", "vprintf(",
        # ---- Encoding / Sanitization (signals mitigation or need for it) ----
        "htmlspecialchars", "htmlentities", "strip_tags",
        "ent_quotes", "ent_html5",
        "sanitize", "escape", "encodeuri", "encodeuricomponent",
        "xss", "contenteditable", "contenteditable=",
        # ---- Misc ----
        "srcdoc", "srcdoc=", "data:", "javascript:",
        "object.data", "embed.src", "iframe.src",
        "location.href", "location.replace", "location.assign",
        "document.referrer", "window.name",
        "postmessage(", "receivemessage",
        "eval(", "settimeout(", "setinterval(",
        "new function(",
    ],
    "auth": [
        # ---- Authentication ----
        "login", "logout", "signin", "signup", "sign_in", "sign_up",
        "signout", "sign_out", "register", "authenticate",
        "password", "passwd", "pwd", "pass_hash",
        "password_hash", "password_verify", "password_check",
        "password_reset", "forgot_password", "change_password",
        "changepassword", "updatepassword",
        # ---- Session Management ----
        "session_start", "session_regenerate_id", "session_destroy",
        "session_id", "session_id(", "session.cookie",
        "setcookie", "setcookie(", "setrawcookie(",
        "session", "cookie(", "cookie", "cookies",
        "remember", "remember_me", "persistent",
        "session fixation", "session hijacking",
        # ---- JWT / Token ----
        "jwt", "jsonwebtoken", "jwt.encode", "jwt.decode",
        "jwt.verify", "jwttoken", "jwt_token",
        "bearer", "bearer ", "authorization:", "authorization: bearer",
        "token", "verify_token", "validate_token", "refresh_token",
        "access_token", "id_token", "auth_token",
        "tokeninvalid", "tokenexpired", "tokenverify",
        "jwks", "jwks_uri", "openid-configuration",
        # ---- OAuth / SSO ----
        "oauth", "oauth2", "oauth_callback", "oauth_token",
        "client_id", "client_secret", "redirect_uri",
        "authorization_code", "grant_type",
        "saml", "samlresponse", "saml_assertion",
        "cas(", "kerberos", "ntlm",
        # ---- CSRF ----
        "csrf", "_csrf", "xsrf", "csrftoken", "csrf_token",
        "antiforgerytoken", "antiforgery", "validatantiforgerytoken",
        "x-csrf-token", "x-xsrf-token",
        # ---- Multi-Factor ----
        "captcha", "recaptcha", "hcaptcha", "turnstile",
        "totp", "hotp", "mfa", "2fa", "otp",
        "sms_code", "verification_code", "authenticator",
        # ---- Brute Force Protection ----
        "rate_limit", "rate_limiter", "throttle",
        "lockout", "login_attempts", "failed_attempts",
        "account_lock", "max_attempts",
        # ---- Password Storage ----
        "md5(", "sha1(", "sha256", "bcrypt", "scrypt", "argon2",
        "pbkdf2", "crypt(",
        "password_hash", "password_needs_rehash",
    ],
    "config": [
        # ---- Environment / Secrets ----
        ".env", ".env.local", ".env.production", ".env.development",
        "secret", "secret_key", "secret_key_base", "app_secret",
        "api_key", "apikey", "api_secret",
        "private_key", "privatekey", "private_key_path",
        "access_key", "accesskey", "access_secret",
        "credentials", "credential", "aws_credential",
        "db_password", "database_url", "database_host",
        "db_host", "db_user", "db_name", "db_pass",
        "token=", "token =", "bearer ",
        # ---- Hardcoded Values ----
        "password=", "password =", "passwd=",
        "hardcoded", "hardcode", "plaintext",
        "debug=true", "debug = true", "debug=1", "debug=true",
        "debug_mode", "debug = 1", "app_debug",
        "trace=true", "trace_enabled",
        "verbose=true", "logging=debug",
        # ---- CORS / Network ----
        "allowed_hosts", "allowed_origins", "cors_origin",
        "cors_allow", "cors_enabled", "access-control-allow",
        "access-control-allow-origin", "access-control-allow-credentials",
        "access-control-allow-methods", "access-control-allow-headers",
        # ---- Server Config ----
        "config", "settings", "configuration",
        "docker", "compose", "docker-compose", "dockerfile",
        "kubernetes", "k8s", "helm", "chart.yaml",
        "nginx", "apache", "httpd.conf", ".htaccess",
        "ssl", "tls", "https", "certificate", "cert_file",
        "server_name", "server_port", "bind_address",
        "0.0.0.0", "listen 80", "listen 443",
        # ---- Cloud / SaaS Keys ----
        "aws_secret", "aws_access_key", "s3_secret",
        "azure_key", "azure_connection_string",
        "gcp_key", "gcp_service_account", "google_api_key",
        "sendgrid_key", "stripe_key", "mailgun_key",
        "twilio_sid", "twilio_token",
        "github_token", "gitlab_token", "slack_token", "slack_webhook",
        # ---- Dependency / Supply Chain ----
        "requirements.txt", "package.json", "package-lock.json",
        "yarn.lock", "gemfile", "gemfile.lock",
        "pom.xml", "build.gradle", "go.sum", "go.mod",
        "cargo.lock", "composer.json", "composer.lock",
        "pip.conf", "npmrc", ".npmrc", "pypirc",
        # ---- Backup / Exposed Files ----
        ".git", ".svn", ".hg", "backup.sql", "dump.sql",
        ".ds_store", "thumbs.db", "web.config", "app.config",
    ],
    "file": [
        # ---- PHP File Operations ----
        "move_uploaded_file", "readfile(", "file_get_contents", "file_put_contents",
        "fopen(", "fread(", "fwrite(", "fclose(",
        "unlink(", "mkdir(", "rmdir(", "copy(", "rename(",
        "file(", "file_exists(", "is_file(", "is_dir(",
        "parse_ini_file(", "parse_url(", "pathinfo(",
        # ---- PHP Upload ----
        "move_uploaded_file", "is_uploaded_file",
        "$_files", "upload_max_filesize", "tmp_name",
        # ---- PHP Directory ----
        "basename(", "dirname(", "scandir(", "opendir(", "readdir(",
        "glob(", "chdir(", "chroot(", "realpath(",
        "ziparchive", "extractto", "zip->open", "zip->extractto",
        "phar(", "phar://",
        # ---- Python File Operations ----
        "open(", "os.path", "os.path.join", "os.path.abspath",
        "os.path.realpath", "os.path.basename", "os.path.dirname",
        "os.listdir", "os.walk", "os.remove", "os.rmdir", "os.mkdir",
        "os.makedirs", "os.rename", "os.chmod", "os.chown",
        "shutil.copy", "shutil.move", "shutil.rmtree",
        "shutil.unpack_archive", "shutil.make_archive",
        "pathlib", "pathlib.path",
        "tempfile", "tempfile.mktemp", "tempfile.namedtemporaryfile",
        # ---- Java File Operations ----
        "new file(", "fileinputstream", "fileoutputstream",
        "filereader", "filewriter", "randomaccessfile",
        "files.delete", "files.copy", "files.move",
        "files.walk", "files.list", "files.readallbytes",
        "files.write", "files.newbufferedreader",
        "multipartfile", "part.write", "part.getinputstream",
        "transfersto", "inputstream",
        # ---- Node.js File Operations ----
        "fs.readfile", "fs.writefile", "fs.unlink",
        "fs.mkdir", "fs.rmdir", "fs.rename", "fs.copyfile",
        "fs.createreadstream", "fs.createwritestream",
        "fs.readdir", "fs.stat", "fs.exists",
        "require('fs')", "import fs from",
        "busboy", "multer", "formidable", "multiparty",
        # ---- Go File Operations ----
        "os.open", "os.create", "os.readfile", "os.writefile",
        "os.remove", "os.rename", "os.mkdirall",
        "filepath.join", "filepath.clean", "filepath.walk",
        "io.copy", "io.readall", "io.util.readall",
        "archive/zip", "archive/tar", "compress/gzip",
        # ---- General ----
        "download", "upload", "attachment", "export", "import",
        "archive", "backup", "restore",
        "sendfile", "send_file", "download(",
        "content-disposition", "content-type",
        "../", "..\\", "..%2f", "..%5c", "%2e%2e",
        "path_traversal", "directory traversal",
        "symlink", "readlink", "lstat",
        "tmp", "temp", "tmp_name", "tmpfile",
    ],
    "business": [
        # ---- E-Commerce / Trading ----
        "order", "orders", "order_id", "order_status",
        "payment", "pay", "checkout", "purchase", "transaction",
        "amount", "price", "total", "subtotal", "fee",
        "currency", "exchange_rate", "rate",
        "discount", "coupon", "promo", "promotion", "voucher",
        "balance", "account_balance", "credit", "debit",
        "refund", "refund_amount", "chargeback", "return",
        "withdraw", "withdrawal", "deposit", "transfer",
        "recharge", "topup", "cash",
        # ---- Inventory ----
        "inventory", "stock", "stock_quantity", "quantity",
        "sku", "product_id", "item_id",
        "restock", "replenish", "out_of_stock",
        # ---- Workflow / State ----
        "workflow", "status", "state_machine",
        "approve", "reject", "cancel", "confirm",
        "pending", "completed", "failed",
        "review", "audit", "verify", "validate",
        # ---- Multi-Tenant / Ownership ----
        "business", "tenant", "tenant_id", "owner", "owner_id",
        "merchant", "seller", "buyer", "customer",
        "org", "organization_id", "company_id",
        # ---- Financial ----
        "invoice", "billing", "receipt", "tax",
        "profit", "margin", "commission",
        "settlement", "clearing", "ledger",
        "bank_account", "card_number", "cvv",
        "secrets", "dividend", "bonus",
        # ---- User Assets ----
        "points", "reward", "gift", "prize",
        "level", "rank", "vip", "membership",
        "privilege", "entitlement",
        # ---- Rate / Quota ----
        "quota", "limit", "cap", "threshold",
        "daily_limit", "max_amount", "min_amount",
        "rate_limit", "frequency",
    ],
    "ssrf": [
        # ---- Python HTTP Clients ----
        "requests.get(", "requests.post(", "requests.put(", "requests.delete(",
        "requests.patch(", "requests.head(", "requests.options(",
        "requests.request(", "requests.session",
        "urllib.request", "urlopen(", "urlretrieve(",
        "urllib2.urlopen", "urllib.request.urlopen",
        "http.client", "http.client.httpconnection", "http.client.httpsconnection",
        "httplib2", "httpx.get", "httpx.post",
        "aiohttp", "aiohttp.session", "asyncio",
        # ---- PHP HTTP Clients ----
        "curl_exec", "curl_init", "curl_setopt",
        "file_get_contents(", "stream_context_create",
        "fsockopen(", "pfsockopen(",
        "guzzle", "guzzlehttp", "guzzle->get", "guzzle->post",
        # ---- Java HTTP Clients ----
        "httpurlconnection", "url.openconnection",
        "httpclient", "okhttp", "okhttpcall",
        "resttemplate", "webclient", "feign.client",
        "url(", "new url(", "url.openstream",
        "httpget", "httppost",
        # ---- Node.js HTTP Clients ----
        "http.get", "http.request", "https.get", "https.request",
        "fetch(", "axios", "axios.get", "axios.post",
        "got(", "node-fetch", "superagent", "needle",
        "request(", "unirest",
        # ---- Go HTTP Clients ----
        "http.get(", "http.post(", "http.newrequest",
        "http.client", "http.defaultclient",
        "resty", "req", "go-resty",
        # ---- Ruby HTTP Clients ----
        "net/http", "open-uri", "httparty",
        "httparty.get", "httparty.post",
        "curb", "typhoeus",
        # ---- .NET HTTP Clients ----
        "webclient", "webrequest", "httpwebrequest",
        "httpclient", "restsharp",
        # ---- Cloud / Internal ----
        "metadata", "metadata.google.internal",
        "169.254.169.254", "instance-metadata",
        "ec2_metadata", "imds",
        "localhost", "127.0.0.1", "0.0.0.0",
        "internal", "private", "intranet",
        # ---- URL Parsing ----
        "redirect", "url_redirect", "location:",
        "header('location", "response.redirect",
        "redirect_url", "return_url", "next=",
        "url=", "uri=", "dest=", "target=",
    ],
    "xxe": [
        # ---- Java XML Parsers ----
        "xmlinputfactory", "saxparser", "saxparserfactory",
        "documentbuilder", "documentbuilderfactory",
        "xmlreader", "xmlreaderfactory", "saxbuilder",
        "saxreader", "domparser", "xmlreader",
        "transformerfactory", "saxtransformerfactory",
        "schemafactory", "validator",
        "xmlconfiguration", "blobserializer",
        # ---- Python XML Parsers ----
        "xml.etree", "xml.etree.elementtree", "elementtree",
        "xml.dom", "xml.dom.minidom", "xml.sax",
        "lxml.etree", "lxml.objectify", "defusedxml",
        "fromstring(", "parse(", "xml.parse(",
        "expat", "pyexpat", "xml.parsers.expat",
        # ---- PHP XML Parsers ----
        "simplexml_load_string", "simplexml_load_file",
        "domdocument", "domxpath", "xml_parse",
        "xml_parser_create", "xml_set_element_handler",
        "xmldocument", "simplexmlelement",
        # ---- .NET XML Parsers ----
        "xmlreader", "xmlreader.create", "xmldocument",
        "xmltextreader", "xmlvalidatingreader",
        "xpathdocument", "xpathnavigator",
        "xmlserializer", "datacontractserializer",
        # ---- Go XML Parsers ----
        "encoding/xml", "xml.unmarshal", "xml.decoder",
        "xml.newdecoder",
        # ---- Node.js XML Parsers ----
        "libxmljs", "xml2js", "fast-xml-parser",
        "sax", "xml-stream",
        # ---- General XXE Patterns ----
        "entity", "<!entity", "<!doctype",
        "system ", "public ", "external",
        "parameter entity", "general entity",
        "dtd", "external dtd", "external entity",
        "xxe", "xinclude",
        "soap", "wsdl", "svg", "xlsx", "docx",
    ],
    "crypto": [
        # ---- Weak Hash Algorithms ----
        "md5(", "md5.new", "md5.hexdigest", "hashlib.md5",
        "sha1(", "sha1.new", "sha1.hexdigest", "hashlib.sha1",
        # ---- Weak Ciphers ----
        "des", "3des", "tripledes", "des-ede3",
        "rc4", "rc2", "blowfish",
        "ecb", "aes_ecb", "aes-128-ecb", "ecb_mode",
        "cipher(", "cipheriv", "createcipher",
        "aes_ecb", "des_ecb", "des_cbc",
        # ---- Weak Key Sizes ----
        "aes-128", "rsa-1024", "rsa-2048",
        "key_size=128", "key_length=128",
        # ---- Insecure Random ----
        "random.random(", "random.randint(", "random.randrange(",
        "math.random(", "math.random",
        "java.util.random", "system.random",
        "np.random", "numpy.random",
        "secrets", "secrets.token", "uuid.uuid",
        # ---- Hardcoded Keys ----
        "aes_key", "encryption_key", "secret_key",
        "signing_key", "hmac_key", "salt",
        "iv=", "initialization_vector", "nonce=",
        "padding", "pkcs5", "pkcs7", "oaep",
        # ---- Certificate / TLS Issues ----
        "verify=false", "ssl_verify=false", "insecure",
        "tls_skip_verify", "ssl._create_unverified_context",
        "check_hostname=false", "cert_reqs=cert_none",
        "rejectunauthorized=false", "strictssl=false",
        # ---- Password Hashing ----
        "base64(", "b64encode", "b64decode",
        "encode(", "decode(",
        "rot13", "caesar", "atob(", "btoa(",
    ],
}

RULE_HIT_MIN_HITS = {
    "rce": 1,
    "injection": 1,
    "xss": 1,
    "auth": 1,
    "config": 1,
    "file": 1,
    "business": 2,
    "ssrf": 1,
    "xxe": 1,
    "crypto": 1,
}

# Keyword tiering: strong keywords carry weight 3, medium carry weight 1.
# A rule hit requires a minimum weighted score (RULE_HIT_MIN_WEIGHTED).
RULE_HIT_TIERS = {
    "rce": {
        "strong": [
            "exec(", "eval(", "system(", "os.system", "os.popen", "popen(",
            "subprocess.Popen", "subprocess.call", "subprocess.run",
            "subprocess.check_output", "subprocess.check_call",
            "runtime.exec", "runtime.getruntime", "processbuilder",
            "child_process.exec", "child_process.spawn", "child_process.fork",
            "pickle.loads", "pickle.load(", "cPickle.loads",
            "yaml.load(", "yaml.unsafe_load(", "marshal.loads",
            "shell_exec", "passthru(", "proc_open", "pcntl_exec",
            "unserialize(", "deserialize(", "objectinputstream", "readobject(",
            "vm.runincontext", "vm.runinnewcontext", "class.forname",
            "objectmapper.readvalue", "xstream",
        ],
        "medium": [
            "subprocess", "os.exec", "os.spawn", "commands.getoutput",
            "shelve.open", "yaml.full_load(", "ruamel.yaml",
            "marshal.load(", "shutil.unpack_archive",
            "codebase.exec", "codebase.eval", "compile(",
            "pcntl_fork", "process.start", "processstartinfo",
            "jsonpickle", "jsonpickle.decode", "fastjson",
            "gson.fromjson", "jackson.readvalue",
            "new function(", "require('child_process')",
            "os/exec", "exec.command", "exec.commandcontext",
            "assert(", "ioctl(", "syscall(",
            "jinja2", "freemarker", "velocity", "thymeleaf",
            "render_template_string", "mako.template",
            "twig", "smarty", "erb(", "ejs.render",
            "ognl", "spel", "mvel",
            "invocationhandler", "scriptengine", "nashorn",
            "stringtemplate", "handlebars.compile",
            "binding.eval", "instance_eval", "class_eval",
            "kernel.system", "open3.", "io.popen",
        ],
    },
    "injection": {
        "strong": [
            "select ", "insert into", "update ", "delete from",
            "execute(", "executemany(", "executescript(",
            "cursor.execute", "cursor.executemany",
            "query(", "raw(", "rawsql", "raw_query",
            ".extra(", ".rawquery",
            "mysqli_query", "mysql_query", "pg_query", "sqlsrv_query", "oci_execute",
            "pdo->query", "pdo->exec", "pdo->prepare",
            "preparedstatement", "statement.execute", "statement.executequery",
            "jdbctemplate.query", "jdbctemplate.update", "jdbctemplate.execute",
            "hibernate.createquery", "hibernate.createsqlquery",
            "entitymanager.createnativequery",
            "$where", "$gt", "$lt", "$ne", "$regex", "$expr",
            "sequelize.query", "sequelize.raw", "knex.raw", "knex.whereRaw",
            "typeorm.query", "prisma.$queryraw",
            "db.query", "db.exec", "gorm.raw", "sqlx.query",
        ],
        "medium": [
            "prepare(", "createorreplace",
            "insert ", "delete ", "drop table", "truncate ",
            "union select", "union all",
            "cursor", "text(", "orm", "statement",
            "sqlite_query", "sqlite3.execute",
            "mybatis select", "mybatis insert", "mybatis update",
            "mongo.find", "mongo.aggregate", "mongoose.where",
            "redis.eval", "redis.get",
            "graphql", "mutation {", "query {",
            "ldap_search", "ldap_bind",
            "sqlalchemy", ".execute(", ".from_sql",
        ],
    },
    "xss": {
        "strong": [
            "innerhtml", "outerhtml", "document.write", "document.writeln",
            "dangerouslysetinnerhtml", "v-html",
            "insertadjacenthtml", "domparser",
            "srcdoc", "javascript:", "data:",
            "bypasssecuritytrusthtml", "bypasssecuritytrusturl",
            "bypasssecuritytrustscript", "bypasssecuritytrustresourceurl",
            "onerror=", "onclick=", "onload=",
            "<script", "echo\"<script", "echo '<script",
        ],
        "medium": [
            "v-text", "v-bind:html", "[innerhtml]", "{{{",
            "writeln", "insertadjacenttext",
            "parsefromstring", "createtextnode",
            "object.data", "embed.src", "iframe.src",
            "location.href", "location.replace", "location.assign",
            "postmessage(", "receivemessage",
            "contenteditable", "contenteditable=",
            "domsanitizer", "sanitizer.bypasssecuritytrust",
            "onmouseover=", "onfocus=", "onsubmit=",
            "echo $_get", "echo $_post", "echo $_request",
            "htmlspecialchars", "strip_tags", "sanitize", "escape",
            "encodeuri", "encodeuricomponent",
            "new function(", "settimeout(", "setinterval(",
        ],
    },
    "auth": {
        "strong": [
            "login", "logout", "session_start", "session_regenerate_id",
            "session_destroy", "setcookie", "setrawcookie(",
            "jwt", "jsonwebtoken", "jwt.encode", "jwt.decode", "jwt.verify",
            "bearer", "authorization: bearer",
            "oauth", "oauth2", "saml", "samlresponse",
            "password_hash", "password_verify", "password_check",
            "verify_token", "validate_token", "authenticate",
            "csrf", "_csrf", "xsrf", "antiforgerytoken", "csrftoken",
            "captcha", "recaptcha", "hcaptcha", "totp", "mfa", "2fa",
            "bcrypt", "argon2", "pbkdf2", "scrypt",
        ],
        "medium": [
            "signin", "signup", "sign_in", "sign_up",
            "signout", "sign_out", "register",
            "password", "passwd", "pwd",
            "password_reset", "forgot_password", "change_password",
            "session", "cookie(", "cookie", "cookies",
            "token", "refresh_token", "access_token", "auth_token",
            "jwks", "openid-configuration",
            "client_id", "client_secret", "redirect_uri",
            "authorization_code", "grant_type",
            "kerberos", "ntlm", "cas(",
            "remember", "remember_me",
            "rate_limit", "rate_limiter", "throttle", "lockout",
            "login_attempts", "failed_attempts",
            "otp", "sms_code", "verification_code",
            "md5(", "sha1(", "sha256", "crypt(",
            "x-csrf-token", "x-xsrf-token",
        ],
    },
    "config": {
        "strong": [
            ".env", ".env.local", ".env.production",
            "secret_key", "app_secret", "api_secret",
            "api_key", "apikey", "private_key", "privatekey",
            "access_key", "accesskey", "access_secret",
            "credentials", "credential", "aws_credential",
            "db_password", "database_url",
            "aws_secret", "aws_access_key",
            "azure_key", "azure_connection_string",
            "gcp_key", "gcp_service_account",
            "sendgrid_key", "stripe_key", "mailgun_key",
            "github_token", "gitlab_token", "slack_token", "slack_webhook",
            "twilio_sid", "twilio_token",
            "debug=true", "debug = true", "debug=1",
            "password=", "password =", "passwd=",
        ],
        "medium": [
            "secret", "token=", "token =", "bearer ",
            "allowed_hosts", "allowed_origins", "cors_origin",
            "cors_allow", "access-control-allow-origin",
            "ssl", "tls", "certificate", "cert_file",
            "config", "settings", "configuration",
            "docker", "compose", "docker-compose", "dockerfile",
            "kubernetes", "k8s", "helm",
            "nginx", "apache", "httpd.conf", ".htaccess",
            "server_name", "0.0.0.0",
            "database_host", "db_host", "db_user", "db_name", "db_pass",
            "google_api_key",
            "requirements.txt", "package.json", "pom.xml", "go.mod",
            "pip.conf", ".npmrc", "pypirc",
            ".git", ".svn", "backup.sql", "dump.sql",
            "verify=false", "ssl_verify=false", "insecure",
        ],
    },
    "file": {
        "strong": [
            "move_uploaded_file", "is_uploaded_file",
            "file_get_contents", "file_put_contents",
            "fopen(", "fread(", "fwrite(",
            "readfile(", "unlink(", "mkdir(", "rmdir(",
            "copy(", "rename(",
            "ziparchive", "extractto", "phar(",
            "realpath", "basename(", "scandir(",
            "opendir(", "readdir(", "glob(",
            "shutil.rmtree", "shutil.copy", "shutil.move",
            "shutil.unpack_archive",
            "fs.unlink", "fs.readfile", "fs.writefile",
            "multipartfile",
            "move_uploaded_file", "sendfile", "send_file",
            "filepath.clean",
        ],
        "medium": [
            "upload", "download", "attachment",
            "archive", "backup", "import", "export",
            "pathinfo(", "dirname(",
            "open(", "os.path.join", "os.path.abspath",
            "os.listdir", "os.walk", "os.remove",
            "tempfile", "mktemp", "symlink", "readlink",
            "files.delete", "files.copy", "files.move",
            "filepath.join", "os.path",
            "../", "..\\", "..%2f", "..%5c",
            "content-disposition", "content-type",
            "tmp", "temp", "tmp_name",
            "fs.createwritestream", "fs.createreadstream",
            "busboy", "multer", "formidable",
            "new file(", "fileinputstream", "fileoutputstream",
        ],
    },
    "business": {
        "strong": [
            "order", "orders", "order_id", "order_status",
            "payment", "checkout", "purchase", "transaction",
            "amount", "price", "total", "subtotal",
            "coupon", "discount", "promo", "promotion", "voucher",
            "balance", "account_balance",
            "refund", "refund_amount", "chargeback",
            "withdraw", "withdrawal", "deposit", "transfer",
            "inventory", "stock", "stock_quantity",
        ],
        "medium": [
            "currency", "exchange_rate", "fee", "rate",
            "credit", "debit", "recharge", "topup",
            "quantity", "sku", "product_id",
            "restock", "out_of_stock",
            "workflow", "status", "state_machine",
            "approve", "reject", "cancel", "confirm",
            "invoice", "billing", "receipt", "tax",
            "settlement", "commission", "profit", "margin",
            "merchant", "seller", "buyer", "customer",
            "points", "reward", "level", "vip", "membership",
            "quota", "threshold", "limit", "cap",
            "daily_limit", "max_amount", "min_amount",
        ],
    },
    "ssrf": {
        "strong": [
            "requests.get(", "requests.post(", "requests.put(", "requests.delete(",
            "requests.request(", "requests.session",
            "urllib.request", "urlopen(", "urlretrieve(",
            "curl_exec", "curl_init", "curl_setopt",
            "http.get(", "http.post(", "http.newrequest",
            "httpurlconnection", "url.openconnection",
            "guzzlehttp", "guzzle->get", "guzzle->post",
            "fetch(", "axios", "axios.get", "axios.post",
            "okhttp", "resttemplate", "webclient",
            "new url(", "url.openstream",
            "169.254.169.254", "metadata.google.internal",
        ],
        "medium": [
            "urllib2.urlopen", "http.client", "httpx.get", "httpx.post",
            "aiohttp", "asyncio",
            "file_get_contents(", "fsockopen(", "pfsockopen(",
            "http.get", "http.request", "https.get", "https.request",
            "got(", "node-fetch", "superagent", "needle",
            "net/http", "open-uri", "httparty",
            "webclient", "webrequest", "httpwebrequest", "restsharp",
            "redirect", "url_redirect", "location:",
            "return_url", "next=", "url=", "dest=",
            "localhost", "127.0.0.1", "0.0.0.0",
            "internal", "private", "intranet",
        ],
    },
    "xxe": {
        "strong": [
            "xmlinputfactory", "saxparser", "saxparserfactory",
            "documentbuilder", "documentbuilderfactory",
            "xmlreader", "xmlreaderfactory",
            "transformerfactory", "saxtransformerfactory",
            "xml.etree", "xml.etree.elementtree",
            "lxml.etree", "lxml.objectify",
            "simplexml_load_string", "simplexml_load_file",
            "domdocument", "domxpath",
            "xmlreader.create", "xmldocument", "xmltextreader",
            "encoding/xml", "xml.unmarshal", "xml.newdecoder",
            "<!entity", "<!doctype",
        ],
        "medium": [
            "saxbuilder", "saxreader", "domparser",
            "xml.dom", "xml.dom.minidom", "xml.sax",
            "defusedxml", "expat", "pyexpat",
            "xml_parse", "xml_parser_create",
            "xmlserializer", "datacontractserializer",
            "libxmljs", "xml2js", "fast-xml-parser",
            "entity", "dtd", "external entity",
            "xxe", "xinclude",
            "soap", "wsdl", "svg",
        ],
    },
    "crypto": {
        "strong": [
            "md5(", "md5.new", "hashlib.md5",
            "sha1(", "sha1.new", "hashlib.sha1",
            "des", "rc4", "ecb", "aes_ecb",
            "verify=false", "ssl_verify=false",
            "ssl._create_unverified_context",
            "check_hostname=false", "cert_reqs=cert_none",
            "rejectunauthorized=false", "strictssl=false",
            "tls_skip_verify",
        ],
        "medium": [
            "3des", "tripledes", "blowfish", "rc2",
            "aes-128", "rsa-1024",
            "cipher(", "cipheriv", "createcipher",
            "random.random(", "randint(", "math.random(",
            "java.util.random",
            "aes_key", "encryption_key", "hmac_key",
            "base64(", "b64encode", "b64decode",
            "iv=", "nonce=", "padding",
            "rot13", "atob(", "btoa(",
        ],
    },
}

RULE_HIT_MIN_WEIGHTED = {
    "rce": 3,
    "injection": 3,
    "xss": 3,
    "auth": 4,
    "config": 3,
    "file": 3,
    "business": 4,
    "ssrf": 3,
    "xxe": 3,
    "crypto": 3,
}

ROUTE_EXPORT_NAMES = {
    "router", "api_router", "bp", "blueprint", "urlpatterns", "urls", "routes", "route",
}


def _build_analysis_strategy_fingerprint() -> str:
    payload = {
        "cache_schema_version": CACHE_SCHEMA_VERSION,
        "max_file_size": MAX_FILE_SIZE,
        "max_files": MAX_FILES,
        "total_chars_limit": TOTAL_CHARS_LIMIT,
        "oversized_head_chars": OVERSIZED_HEAD_CHARS,
        "oversized_tail_chars": OVERSIZED_TAIL_CHARS,
        "oversized_max_windows": OVERSIZED_MAX_WINDOWS,
        "oversized_window_radius": OVERSIZED_WINDOW_RADIUS,
        "skip_dirs": sorted(SKIP_DIRS),
        "code_extensions": sorted(CODE_EXTENSIONS),
        "risk_keywords": {key: list(value) for key, value in sorted(RISK_KEYWORDS.items())},
        "rule_label_stage_map": {key: list(value) for key, value in sorted(RULE_LABEL_STAGE_MAP.items())},
        "rule_hit_keywords": {key: list(value) for key, value in sorted(RULE_HIT_KEYWORDS.items())},
        "rule_hit_min_hits": dict(sorted(RULE_HIT_MIN_HITS.items())),
        "rule_hit_tiers": {k: {"strong": sorted(v.get("strong", [])), "medium": sorted(v.get("medium", []))} for k, v in sorted(RULE_HIT_TIERS.items())},
        "rule_hit_min_weighted": dict(sorted(RULE_HIT_MIN_WEIGHTED.items())),
    }
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(serialized.encode("utf-8", errors="ignore")).hexdigest()


def parse_project(project_dir: str) -> tuple[list, str]:
    """Scan project directory and return (file_tree, tech_stack)."""
    state = {"file_count": 0}
    file_tree = _build_tree(project_dir, project_dir, state=state)
    tech_stack = _detect_tech_stack(project_dir, file_tree)
    return file_tree, tech_stack


# ============================================================
# Phase 0: Static Pre-Discovery
# ============================================================

# ── Tech Stack Profile ────────────────────────────────────────

def _build_tech_stack_profile(project_dir: str, file_tree: list) -> dict:
    """Structured tech stack detection from dependency/config files."""
    profile = {"language": [], "framework": [], "database": [], "orm": [], "auth_library": [], "template_engine": [], "message_queue": [], "build_tool": []}
    flat_files = _flatten_files(file_tree)
    filenames = {f["name"] for f in flat_files}

    pkg = _read_project_file(project_dir, "package.json")
    req = _read_project_file(project_dir, "requirements.txt")
    pyproj = _read_project_file(project_dir, "pyproject.toml")
    pom = _read_project_file(project_dir, "pom.xml")
    gomod = _read_project_file(project_dir, "go.mod")
    cargotoml = _read_project_file(project_dir, "Cargo.toml")
    gemfile = _read_project_file(project_dir, "Gemfile")
    composer = _read_project_file(project_dir, "composer.json")

    # Python
    py_content = "\n".join(filter(None, [req, pyproj])).lower()
    if py_content or any(f["path"].endswith(".py") for f in flat_files[:50]):
        profile["language"].append("Python")
        if "django" in py_content:
            profile["framework"].append("Django")
        if "flask" in py_content:
            profile["framework"].append("Flask")
        if "fastapi" in py_content:
            profile["framework"].append("FastAPI")
        if "tornado" in py_content:
            profile["framework"].append("Tornado")
        if "sqlalchemy" in py_content:
            profile["orm"].append("SQLAlchemy")
        if "django" in py_content and "orm" not in profile["orm"]:
            profile["orm"].append("Django ORM")
        if "mongoengine" in py_content:
            profile["orm"].append("MongoEngine")
        if "peewee" in py_content:
            profile["orm"].append("Peewee")
        if "psycopg" in py_content or "psycopg2" in py_content:
            profile["database"].append("PostgreSQL")
        if "pymysql" in py_content or "mysqlclient" in py_content:
            profile["database"].append("MySQL")
        if "sqlite" in py_content:
            profile["database"].append("SQLite")
        if "pymongo" in py_content:
            profile["database"].append("MongoDB")
        if "redis" in py_content:
            profile["database"].append("Redis")
        if "celery" in py_content:
            profile["message_queue"].append("Celery")
        if "rq" in py_content:
            profile["message_queue"].append("Redis Queue")
        if "jinja" in py_content:
            profile["template_engine"].append("Jinja2")
        if "pyjwt" in py_content or "python-jose" in py_content or "jose" in py_content:
            profile["auth_library"].append("JWT")
        if "flask-login" in py_content:
            profile["auth_library"].append("Flask-Login")
        if "passlib" in py_content or "bcrypt" in py_content:
            profile["auth_library"].append("Passlib")
        if "poetry" in (pyproj or "").lower():
            profile["build_tool"].append("Poetry")
        if "setuptools" in py_content:
            profile["build_tool"].append("Setuptools")

    # Node.js
    if pkg:
        pkg_lower = pkg.lower()
        profile["language"].append("JavaScript/TypeScript")
        if '"express"' in pkg_lower:
            profile["framework"].append("Express")
        if '"koa"' in pkg_lower:
            profile["framework"].append("Koa")
        if '"@nestjs/core"' in pkg_lower:
            profile["framework"].append("NestJS")
        if '"fastify"' in pkg_lower:
            profile["framework"].append("Fastify")
        if '"next"' in pkg_lower:
            profile["framework"].append("Next.js")
        if '"react"' in pkg_lower:
            profile["framework"].append("React")
        if '"vue"' in pkg_lower:
            profile["framework"].append("Vue")
        if '"mongoose"' in pkg_lower:
            profile["orm"].append("Mongoose")
        if '"prisma"' in pkg_lower or '"@prisma/client"' in pkg_lower:
            profile["orm"].append("Prisma")
        if '"sequelize"' in pkg_lower:
            profile["orm"].append("Sequelize")
        if '"typeorm"' in pkg_lower:
            profile["orm"].append("TypeORM")
        if '"pg"' in pkg_lower or '"postgresql"' in pkg_lower:
            profile["database"].append("PostgreSQL")
        if '"mysql"' in pkg_lower or '"mysql2"' in pkg_lower:
            profile["database"].append("MySQL")
        if '"mongodb"' in pkg_lower:
            profile["database"].append("MongoDB")
        if '"ioredis"' in pkg_lower or '"redis"' in pkg_lower:
            profile["database"].append("Redis")
        if '"jsonwebtoken"' in pkg_lower or '"jose"' in pkg_lower:
            profile["auth_library"].append("JWT")
        if '"passport"' in pkg_lower:
            profile["auth_library"].append("Passport")
        if '"bull"' in pkg_lower:
            profile["message_queue"].append("Bull")
        if '"amqplib"' in pkg_lower or '"rabbitmq"' in pkg_lower:
            profile["message_queue"].append("RabbitMQ")
        if '"ejs"' in pkg_lower:
            profile["template_engine"].append("EJS")
        if '"pug"' in pkg_lower:
            profile["template_engine"].append("Pug")
        if '"handlebars"' in pkg_lower:
            profile["template_engine"].append("Handlebars")
        if '"webpack"' in pkg_lower:
            profile["build_tool"].append("Webpack")
        if '"vite"' in pkg_lower:
            profile["build_tool"].append("Vite")

    # Go
    if gomod:
        profile["language"].append("Go")
        gomod_lower = gomod.lower()
        if "gin-gonic" in gomod_lower:
            profile["framework"].append("Gin")
        if "echo" in gomod_lower:
            profile["framework"].append("Echo")
        if "fiber" in gomod_lower:
            profile["framework"].append("Fiber")
        if "gorm" in gomod_lower:
            profile["orm"].append("GORM")
        if "postgres" in gomod_lower:
            profile["database"].append("PostgreSQL")
        if "mysql" in gomod_lower:
            profile["database"].append("MySQL")
        if "mongo" in gomod_lower:
            profile["database"].append("MongoDB")
        if "redis" in gomod_lower:
            profile["database"].append("Redis")

    # Java
    if pom:
        profile["language"].append("Java")
        pom_lower = pom.lower()
        if "spring-boot" in pom_lower:
            profile["framework"].append("Spring Boot")
        if "hibernate" in pom_lower:
            profile["orm"].append("Hibernate")
        if "mybatis" in pom_lower:
            profile["orm"].append("MyBatis")
        if "spring-security" in pom_lower:
            profile["auth_library"].append("Spring Security")
        if "shiro" in pom_lower:
            profile["auth_library"].append("Apache Shiro")
        if "thymeleaf" in pom_lower:
            profile["template_engine"].append("Thymeleaf")
        if "kafka" in pom_lower:
            profile["message_queue"].append("Kafka")
        if "rabbitmq" in pom_lower:
            profile["message_queue"].append("RabbitMQ")
        profile["build_tool"].append("Maven")

    # Ruby
    if gemfile:
        profile["language"].append("Ruby")
        gem_lower = gemfile.lower()
        if "rails" in gem_lower:
            profile["framework"].append("Rails")
        if "activerecord" in gem_lower:
            profile["orm"].append("ActiveRecord")
        if "devise" in gem_lower:
            profile["auth_library"].append("Devise")

    # PHP
    if composer:
        profile["language"].append("PHP")
        comp_lower = composer.lower()
        if "laravel" in comp_lower:
            profile["framework"].append("Laravel")
        if "symfony" in comp_lower:
            profile["framework"].append("Symfony")
        if "doctrine" in comp_lower:
            profile["orm"].append("Doctrine")

    # Rust
    if cargotoml:
        profile["language"].append("Rust")
        cargo_lower = cargotoml.lower()
        if "actix" in cargo_lower:
            profile["framework"].append("Actix")
        if "axum" in cargo_lower:
            profile["framework"].append("Axum")
        if "rocket" in cargo_lower:
            profile["framework"].append("Rocket")
        if "diesel" in cargo_lower:
            profile["orm"].append("Diesel")
        if "sqlx" in cargo_lower:
            profile["orm"].append("SQLx")

    # Deduplicate
    for key in profile:
        profile[key] = list(dict.fromkeys(profile[key]))

    return profile


# ── Directory Structure Classification ─────────────────────────

_DIR_ROLE_PATTERNS = {
    "controller": ["controller", "controllers", "handler", "handlers", "endpoint", "endpoints", "api", "apis"],
    "service": ["service", "services", "logic", "business", "usecase", "usecases", "interactor", "interactors"],
    "model": ["model", "models", "entity", "entities", "domain"],
    "middleware": ["middleware", "middlewares", "interceptor", "interceptors", "guard", "guards", "filter", "filters"],
    "config": ["config", "configuration", "settings", "conf"],
    "route": ["route", "routes", "router", "routers", "urls"],
    "auth": ["auth", "authentication", "security", "permission", "permissions"],
    "dao": ["dao", "repository", "repositories", "mapper", "mappers", "dal", "persistence"],
    "view": ["view", "views", "template", "templates", "page", "pages", "component", "components"],
    "util": ["util", "utils", "helper", "helpers", "common", "shared", "lib", "libs"],
    "test": ["test", "tests", "spec", "specs", "__tests__", "testing"],
    "migrate": ["migration", "migrations", "migrate", "db"],
}

_PROJECT_PATTERNS = {
    "mvc": {"controller", "model", "view"},
    "layered": {"controller", "service", "dao"},
    "clean": {"entity", "usecase", "interactor"},
    "django_mvt": {"view", "model", "template"},
}


def _classify_directory_structure(file_tree: list) -> dict:
    """Classify directory roles and detect project pattern."""
    dir_roles = {}
    all_dir_names = set()

    def _walk_tree(nodes, parent_path=""):
        for node in nodes:
            if node.get("type") != "directory":
                continue
            name_lower = node["name"].lower()
            rel_path = f"{parent_path}/{node['name']}" if parent_path else node["name"]
            all_dir_names.add(name_lower)
            role = _match_dir_role(name_lower)
            if role:
                dir_roles[rel_path] = {"role": role, "name": node["name"]}
            if "children" in node:
                _walk_tree(node["children"], rel_path)

    _walk_tree(file_tree)

    detected_roles = {info["role"] for info in dir_roles.values()}
    pattern = "unknown"
    best_overlap = 0
    for pname, required in _PROJECT_PATTERNS.items():
        overlap = len(detected_roles & required)
        if overlap >= len(required) * 0.5 and overlap > best_overlap:
            best_overlap = overlap
            pattern = pname

    return {"pattern": pattern, "directory_roles": dir_roles, "detected_roles": sorted(detected_roles)}


def _match_dir_role(name_lower: str) -> str | None:
    for role, patterns in _DIR_ROLE_PATTERNS.items():
        if name_lower in patterns:
            return role
    return None


# ── Import Graph Construction ──────────────────────────────────

_PY_IMPORT_RE = re.compile(r'^(?:from\s+(\S+)\s+)?import\s+([^\n#]+)', re.MULTILINE)
_JS_IMPORT_RE = re.compile(r'(?:import\s+.*?from\s+["\'](\.[^"\']+)["\']|require\s*\(\s*["\'](\.[^"\']+)["\']\))', re.MULTILINE)
_GO_IMPORT_RE = re.compile(r'import\s*\(([\s\S]*?)\)', re.MULTILINE)
_GO_SINGLE_IMPORT_RE = re.compile(r'import\s+"([^"]+)"', re.MULTILINE)
_JAVA_IMPORT_RE = re.compile(r'import\s+([\w.]+)\s*;', re.MULTILINE)


def _build_import_graph(project_dir: str, file_tree: list) -> dict:
    """Build file-level import/dependency graph."""
    files = _flatten_files(file_tree)
    imports = {}   # file_path -> [imported_file_paths]
    file_hub_scores = {}  # file_path -> hub score (how many files import it)
    file_roles = {}  # file_path -> inferred role

    ext_map = {}
    for f in files:
        ext_map.setdefault(f.get("extension", ""), []).append(f)

    py_files = {f["path"].replace("\\", "/") for f in ext_map.get(".py", [])}
    py_modules = {}
    for fp in py_files:
        parts = fp.replace("/", ".").rsplit(".", 1)[0]
        py_modules[parts] = fp
        py_modules[parts.rsplit(".", 1)[-1]] = fp

    js_files = {f["path"].replace("\\", "/") for f in ext_map.get(".js", []) + ext_map.get(".ts", []) + ext_map.get(".jsx", []) + ext_map.get(".tsx", []) + ext_map.get(".mjs", [])}

    for f in files:
        fp = f["path"].replace("\\", "/")
        full_path = os.path.join(project_dir, fp)
        if f.get("size", 0) > MAX_FILE_SIZE:
            continue
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception:
            continue

        resolved = set()
        ext = f.get("extension", "").lower()

        if ext == ".py":
            for match in _PY_IMPORT_RE.finditer(content):
                mod = match.group(1) or match.group(2)
                if not mod:
                    continue
                mod = mod.split(",")[0].strip().split(" as ")[0].strip()
                if mod.startswith("."):
                    mod = mod.lstrip(".")
                    parent = "/".join(fp.split("/")[:-1])
                    candidate = f"{parent}/{mod}".replace("//", "/")
                    for candidate_fp in [f"{candidate}.py", f"{candidate}/__init__.py"]:
                        if candidate_fp in py_files:
                            resolved.add(candidate_fp)
                elif mod in py_modules:
                    resolved.add(py_modules[mod])
        elif ext in {".js", ".jsx", ".ts", ".tsx", ".mjs"}:
            for match in _JS_IMPORT_RE.finditer(content):
                rel = match.group(1) or match.group(2)
                if not rel:
                    continue
                parent = "/".join(fp.split("/")[:-1])
                candidate = _resolve_js_import(parent, rel, js_files)
                if candidate:
                    resolved.add(candidate)
        elif ext == ".go":
            # Go: resolve internal imports via directory matching
            all_go_dirs = set()
            for gf in files:
                gfp = gf.get("path", "").replace("\\", "/")
                if gfp.lower().endswith(".go"):
                    all_go_dirs.add("/".join(gfp.split("/")[:-1]))

            # Detect Go module name from go.mod
            go_module = ""
            gm_content = _read_project_file(project_dir, "go.mod")
            if gm_content:
                for gml in gm_content.split("\n"):
                    gml = gml.strip()
                    if gml.startswith("module "):
                        go_module = gml.split(None, 1)[-1].strip()
                        break

            for match in _GO_IMPORT_RE.finditer(content):
                block = match.group(1) or ""
                pkg_lines = [l.strip().strip('"').strip() for l in block.split("\n")]
                for match2 in _GO_SINGLE_IMPORT_RE.finditer(content):
                    pkg_lines.append(match2.group(1))
                for pkg_line in pkg_lines:
                    if not pkg_line or pkg_line.startswith("//") or pkg_line.startswith("_"):
                        continue
                    # Strip alias: "alias "path"" -> "path"
                    if '"' in pkg_line:
                        pkg_line = pkg_line[pkg_line.index('"') + 1:].rstrip('"').strip()
                    # Strip module prefix for internal packages
                    if go_module and pkg_line.startswith(go_module + "/"):
                        pkg_line = pkg_line[len(go_module) + 1:]
                    elif go_module and pkg_line == go_module:
                        pkg_line = ""
                    if not pkg_line:
                        continue
                    # Match to directory
                    pkg_lower = pkg_line.lower()
                    for go_dir in all_go_dirs:
                        if go_dir.lower() == pkg_lower or go_dir.lower().endswith("/" + pkg_lower):
                            for gf in files:
                                gfp = gf.get("path", "").replace("\\", "/")
                                if gfp.lower().startswith(go_dir.lower() + "/") and gfp.lower().endswith(".go") and gfp != fp:
                                    resolved.add(gfp)
                            break
        elif ext == ".java":
            for match in _JAVA_IMPORT_RE.finditer(content):
                pkg_class = match.group(1)
                if pkg_class:
                    candidate = "/".join(pkg_class.split(".")) + ".java"
                    if candidate in py_files or any(f.endswith(candidate) for f in py_files):
                        resolved.add(candidate)

        if resolved:
            imports[fp] = sorted(resolved)
            for target in resolved:
                file_hub_scores[target] = file_hub_scores.get(target, 0) + 1

    # Infer file roles from content keywords
    for f in files:
        fp = f["path"].replace("\\", "/")
        full_path = os.path.join(project_dir, fp)
        if f.get("size", 0) > MAX_FILE_SIZE:
            continue
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                head = fh.read(4000).lower()
        except Exception:
            continue

        role = _infer_file_role(fp, head)
        if role:
            file_roles[fp] = role

    top_hubs = sorted(file_hub_scores.items(), key=lambda x: -x[1])[:40]

    return {
        "imports": imports,
        "hub_scores": {fp: score for fp, score in top_hubs},
        "file_roles": file_roles,
    }


def _resolve_js_import(parent: str, rel_path: str, js_files: set) -> str | None:
    """Resolve a JS relative import to a file path."""
    base = f"{parent}/{rel_path}".replace("//", "/")
    for suffix in ["", ".js", ".jsx", ".ts", ".tsx", ".mjs", "/index.js", "/index.ts"]:
        candidate = base + suffix
        if candidate in js_files:
            return candidate
    return None


def _infer_file_role(file_path: str, content_head: str) -> str | None:
    """Infer a file's architectural role from path and content."""
    fp_lower = file_path.lower()
    dir_parts = fp_lower.replace("\\", "/").split("/")

    if any(p in dir_parts for p in ["middleware", "middlewares", "interceptor", "guard", "guards"]):
        return "middleware"
    if any(p in dir_parts for p in ["controller", "controllers", "handler", "handlers", "endpoints"]):
        return "controller"
    if any(p in dir_parts for p in ["service", "services", "usecase"]):
        return "service"
    if any(p in dir_parts for p in ["model", "models", "entity", "entities", "domain"]):
        return "model"
    if any(p in dir_parts for p in ["route", "routes", "router", "routers", "urls"]):
        return "route"
    if any(p in dir_parts for p in ["config", "configuration", "settings", "conf"]):
        return "config"
    if any(p in dir_parts for p in ["auth", "security", "permission"]):
        return "auth"
    if any(p in dir_parts for p in ["dao", "repository", "mapper", "persistence"]):
        return "dao"

    if "class.*middleware" in content_head or "def middleware" in content_head:
        return "middleware"
    if "@controller" in content_head or "@restcontroller" in content_head:
        return "controller"
    if "@service" in content_head:
        return "service"
    if "router.get(" in content_head or "router.post(" in content_head or "include_router" in content_head:
        return "route"
    if "jwt" in content_head and ("sign" in content_head or "verify" in content_head):
        return "auth"

    return None


# ── Middleware/Decorator Mapping ────────────────────────────────

_AUTH_DECORATOR_PATTERNS = [
    re.compile(r'@(\w*(?:auth|login|token|jwt|bearer)\w*)\b', re.I),
    re.compile(r'@(?:pre_?authorize|secured|roles_allowed|has_role|has_authority|permit_all|deny_all)\b', re.I),
    re.compile(r'@require_(?:auth|login|permission|role|scopes)', re.I),
    re.compile(r'decorator\s*\(\s*["\']?(\w*(?:auth|login|jwt|token)\w*)', re.I),
    re.compile(r'@UseGuards\((\w+)\)', re.I),
]

_MIDDLEWARE_PATTERNS = [
    re.compile(r'app\.use\(\s*([/\w]*)\s*,?\s*(?:\w+)?\s*\)', re.I),
    re.compile(r'app\.add_middleware\(\s*(\w+)', re.I),
    re.compile(r'MIDDLEWARE\s*=\s*\[([^\]]+)\]', re.I),
    re.compile(r'(?:const|let|var)\s+\w+\s*=\s*require\(["\']([/\w]*(?:middleware|auth|session|cors|csrf|helmet)[/\w]*)["\']\)', re.I),
    re.compile(r'\.use\(\s*/[^,]+,\s*(\w+Middleware)', re.I),
    re.compile(r'func\s+(\w+Middleware)\s*\(', re.I),
]


def _build_middleware_map(project_dir: str, file_tree: list, code_chunks: list[dict]) -> dict:
    """Extract middleware registrations and auth decorator mappings."""
    files = _flatten_files(file_tree)
    middleware_chain = []
    auth_decorators = {}
    route_auth_map = {}

    for f in files:
        fp = f["path"].replace("\\", "/")
        full_path = os.path.join(project_dir, fp)
        if f.get("size", 0) > MAX_FILE_SIZE:
            continue
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception:
            continue

        # Detect middleware registrations
        for pattern in _MIDDLEWARE_PATTERNS:
            for match in pattern.finditer(content):
                name = match.group(1) or "anonymous"
                middleware_chain.append({"name": name, "file_path": fp})

        # Detect auth decorators
        for pattern in _AUTH_DECORATOR_PATTERNS:
            for match in pattern.finditer(content):
                deco_name = match.group(1) or match.group(0).lstrip("@")
                if deco_name not in auth_decorators:
                    auth_decorators[deco_name] = {"file_path": fp, "count": 0}
                auth_decorators[deco_name]["count"] += 1

    # Map auth decorators to routes via route file analysis
    for chunk in code_chunks:
        fp = str(chunk.get("file_path", "")).replace("\\", "/")
        content = str(chunk.get("content", "")[:8000])
        for pattern in _AUTH_DECORATOR_PATTERNS:
            for match in pattern.finditer(content):
                deco_name = match.group(1) or match.group(0).lstrip("@")
                # Find nearby route definitions
                route_match = re.search(r'(?:app|router|bp|blueprint|api)\.(get|post|put|delete|patch)\(\s*["\']([^"\']*)["\']', content[match.end():match.end() + 200])
                if not route_match:
                    route_match = re.search(r'@(get|post|put|delete|patch)\(\s*["\']([^"\']*)["\']', content[match.end():match.end() + 200])
                if route_match:
                    method = route_match.group(1).upper()
                    path = route_match.group(2)
                    route_auth_map[f"{method} {path}"] = deco_name

    return {
        "middleware_chain": middleware_chain[:30],
        "auth_decorators": {k: v for k, v in sorted(auth_decorators.items(), key=lambda x: -x[1]["count"])[:20]},
        "route_auth_map": route_auth_map,
    }


# ── Security-Critical File Identification ──────────────────────

_SECURITY_FILE_PATTERNS = {
    "auth_handler": [
        re.compile(r'(?:login|authenticate|signin|sign_in|do_login|handle_login|verify_token|check_auth|auth_check)', re.I),
    ],
    "auth_middleware": [
        re.compile(r'class\s+\w*(?:Auth|Jwt|Token|Session|Login)Middleware', re.I),
        re.compile(r'func\s+\w*(?:Auth|Jwt|Token|Session)Middleware', re.I),
        re.compile(r'(?:def|function)\s+\w*(?:auth|jwt|token|session)_(?:middleware|guard|check|verify)', re.I),
    ],
    "permission": [
        re.compile(r'(?:permission|authorize|can_access|check_permission|has_role|is_admin|require_role|rbac|acl)', re.I),
    ],
    "crypto": [
        re.compile(r'(?:encrypt|decrypt|hash|bcrypt|scrypt|argon|pbkdf|hmac|aes|rsa|private_key|public_key|certificate|ssl|tls)', re.I),
    ],
    "file_operation": [
        re.compile(r'(?:upload|download|readfile|writefile|file_get_contents|fopen|move_uploaded|send_file|serve_file|attachment)', re.I),
    ],
    "db_query": [
        re.compile(r'(?:raw_query|execute_query|cursor\.execute|\.raw\(|\.query\(|\.find\(|\.aggregate\()', re.I),
    ],
    "config_secret": [
        re.compile(r'(?:secret_key|private_key|api_key|password|token|credential|database_url|connection_string)', re.I),
    ],
}

_MUST_COVER_ROLES = {"auth", "middleware", "config", "route"}


def _identify_security_critical_files(
    project_dir: str, file_tree: list, import_graph: dict, tech_profile: dict
) -> dict:
    """Identify files that must be covered for security audit completeness."""
    files = _flatten_files(file_tree)
    critical_files = {}  # file_path -> {"reasons": [...], "priority": int}
    file_roles = import_graph.get("file_roles", {})
    hub_scores = import_graph.get("hub_scores", {})

    for f in files:
        fp = f["path"].replace("\\", "/")
        full_path = os.path.join(project_dir, fp)
        if f.get("size", 0) > MAX_FILE_SIZE:
            continue
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception:
            continue

        reasons = []

        # Check by file role
        role = file_roles.get(fp, "")
        if role in _MUST_COVER_ROLES:
            reasons.append(f"role:{role}")

        # Check by security patterns
        content_lower = content[:16000].lower()
        for category, patterns in _SECURITY_FILE_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(content_lower):
                    reasons.append(f"security:{category}")
                    break

        # Check by hub score (highly imported files)
        hub_score = hub_scores.get(fp, 0)
        if hub_score >= 3:
            reasons.append(f"hub:imported_by_{hub_score}")

        # Check for config files
        basename = os.path.basename(fp).lower()
        if basename in {
            "main.py", "app.py", "server.js", "index.js", "manage.py",
            "settings.py", "config.py", "config.yaml", "config.json",
            "application.yml", "application.properties", ".env",
            "package.json", "requirements.txt", "go.mod", "pom.xml",
        }:
            reasons.append("entry:config_or_entry")

        if reasons:
            priority = len(reasons) + (5 if any("auth" in r for r in reasons) else 0)
            critical_files[fp] = {"reasons": reasons, "priority": priority}

    # Sort by priority descending
    sorted_files = sorted(critical_files.items(), key=lambda x: (-x[1]["priority"], x[0]))
    return {
        "must_cover_files": [fp for fp, _ in sorted_files],
        "file_details": {fp: info for fp, info in sorted_files},
        "total_critical_count": len(sorted_files),
    }


# ── Pre-Discovery Orchestration ────────────────────────────────

def run_pre_discovery(project_dir: str, file_tree: list, code_chunks: list[dict], static_routes: list[dict]) -> dict:
    """Run all static pre-discovery analyses and return combined result."""
    tech_profile = _build_tech_stack_profile(project_dir, file_tree)
    dir_structure = _classify_directory_structure(file_tree)
    import_graph = _build_import_graph(project_dir, file_tree)
    middleware_map = _build_middleware_map(project_dir, file_tree, code_chunks)
    security_files = _identify_security_critical_files(project_dir, file_tree, import_graph, tech_profile)

    return {
        "tech_profile": tech_profile,
        "dir_structure": dir_structure,
        "import_graph": import_graph,
        "middleware_map": middleware_map,
        "security_files": security_files,
    }


def warm_project_cache(project_id: int, project_dir: str, file_tree: list) -> dict:
    code_chunks, chunk_stats = get_code_chunks(project_dir, file_tree, include_stats=True)
    static_routes, route_stats = extract_project_routes(project_dir, file_tree, include_stats=True)
    rule_hits = _build_rule_hits(code_chunks)
    source_sink_hints = _build_source_sink_hints(code_chunks, static_routes)
    pre_discovery = run_pre_discovery(project_dir, file_tree, code_chunks, static_routes)
    source_files = _flatten_files(file_tree)
    project_fingerprint = _build_project_fingerprint(file_tree)
    analysis_strategy_fingerprint = _build_analysis_strategy_fingerprint()
    oversized_files = sum(1 for file_node in source_files if file_node.get("size", 0) > MAX_FILE_SIZE)
    scan_stats = {
        "source_files_detected": len(source_files),
        "oversized_files_skipped": oversized_files,
        "files_considered_for_chunks": chunk_stats.get("files_considered", 0),
        "files_with_content": chunk_stats.get("files_with_content", 0),
        "chunk_count": chunk_stats.get("chunk_count", len(code_chunks)),
        "total_chars_loaded": chunk_stats.get("total_chars_loaded", 0),
        "truncated_by_total_chars": bool(chunk_stats.get("truncated_by_total_chars")),
        "oversized_files_compacted": chunk_stats.get("oversized_files_compacted", 0),
        "rule_hit_count": len(rule_hits),
        "source_sink_hint_count": len(source_sink_hints),
        "route_count": len(static_routes),
        "route_source_files": route_stats.get("files_scanned", 0),
        "partial_audit": bool(
            chunk_stats.get("truncated_by_total_chars") or chunk_stats.get("oversized_files_compacted")
        ),
    }
    cache_payload = {
        "cache_schema_version": CACHE_SCHEMA_VERSION,
        "project_id": project_id,
        "project_fingerprint": project_fingerprint,
        "analysis_strategy_fingerprint": analysis_strategy_fingerprint,
        "code_chunks": code_chunks,
        "static_routes": static_routes,
        "rule_hits": rule_hits,
        "source_sink_hints": source_sink_hints,
        "pre_discovery": pre_discovery,
        "scan_stats": scan_stats,
    }
    _write_project_cache(project_id, cache_payload)
    return cache_payload


def load_project_cache(project_id: int, file_tree: list | None = None) -> dict | None:
    cache_path = _project_cache_path(project_id)
    if not os.path.isfile(cache_path):
        return None
    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    if int(payload.get("cache_schema_version", 0) or 0) != CACHE_SCHEMA_VERSION:
        return None
    cached_strategy_fingerprint = str(payload.get("analysis_strategy_fingerprint", "") or "")
    current_strategy_fingerprint = _build_analysis_strategy_fingerprint()
    if not cached_strategy_fingerprint or cached_strategy_fingerprint != current_strategy_fingerprint:
        return None
    if file_tree is not None:
        cached_fingerprint = str(payload.get("project_fingerprint", "") or "")
        current_fingerprint = _build_project_fingerprint(file_tree)
        if not cached_fingerprint or cached_fingerprint != current_fingerprint:
            return None
    return payload


def get_or_build_project_cache(project_id: int, project_dir: str, file_tree: list) -> dict:
    cached = load_project_cache(project_id, file_tree=file_tree)
    if cached:
        code_chunks = cached.get("code_chunks")
        static_routes = cached.get("static_routes")
        rule_hits = cached.get("rule_hits")
        source_sink_hints = cached.get("source_sink_hints")
        scan_stats = cached.get("scan_stats")
        if (
            isinstance(code_chunks, list)
            and isinstance(static_routes, list)
            and isinstance(rule_hits, list)
            and isinstance(source_sink_hints, list)
            and isinstance(scan_stats, dict)
        ):
            return cached
    return warm_project_cache(project_id, project_dir, file_tree)


def clear_project_cache(project_id: int) -> None:
    cache_path = _project_cache_path(project_id)
    if os.path.isfile(cache_path):
        try:
            os.remove(cache_path)
        except OSError:
            pass


def _project_cache_dir(project_id: int) -> str:
    return os.path.join(CACHE_ROOT, str(project_id))


def _project_cache_path(project_id: int) -> str:
    return os.path.join(_project_cache_dir(project_id), "analysis.json")


def _write_project_cache(project_id: int, payload: dict) -> None:
    cache_dir = _project_cache_dir(project_id)
    os.makedirs(cache_dir, exist_ok=True)
    with open(_project_cache_path(project_id), "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False)


def _build_project_fingerprint(file_tree: list) -> str:
    normalized_entries: list[str] = []
    for file_node in _flatten_files(file_tree or []):
        normalized_entries.append(
            "|".join(
                [
                    str(file_node.get("path", "") or ""),
                    str(file_node.get("extension", "") or ""),
                    str(file_node.get("size", 0) or 0),
                ]
            )
        )
    normalized_entries.sort()
    joined = "\n".join(normalized_entries)
    return hashlib.sha256(joined.encode("utf-8", errors="ignore")).hexdigest()


def _build_tree(base_path: str, current_path: str, depth: int = 0, state: dict | None = None) -> list:
    """Build a nested file tree structure."""
    state = state or {"file_count": 0}
    if depth > 10:
        return []

    items = []
    try:
        entries = sorted(os.listdir(current_path))
    except PermissionError:
        return []

    for entry in entries:
        full_path = os.path.join(current_path, entry)
        rel_path = os.path.relpath(full_path, base_path).replace("\\", "/")

        if os.path.isdir(full_path):
            if entry in SKIP_DIRS or entry.startswith("."):
                continue
            children = _build_tree(base_path, full_path, depth + 1, state=state)
            if children:
                items.append({
                    "name": entry,
                    "type": "directory",
                    "path": rel_path,
                    "children": children,
                })
        else:
            if state["file_count"] >= MAX_FILES:
                break
            ext = os.path.splitext(entry)[1].lower()
            if ext not in CODE_EXTENSIONS:
                continue
            try:
                size = os.path.getsize(full_path)
            except OSError:
                size = 0
            state["file_count"] += 1
            items.append({
                "name": entry,
                "type": "file",
                "path": rel_path,
                "extension": ext,
                "size": size,
            })

    return items


def _detect_tech_stack(project_dir: str, file_tree: list) -> str:
    """Detect tech stack from project files."""
    detected = []
    flat_files = _flatten_files(file_tree)
    filenames = {f["name"] for f in flat_files}

    package_json = _read_project_file(project_dir, "package.json")
    requirements_txt = _read_project_file(project_dir, "requirements.txt")
    pyproject_toml = _read_project_file(project_dir, "pyproject.toml")
    pom_xml = _read_project_file(project_dir, "pom.xml")
    go_mod = _read_project_file(project_dir, "go.mod")

    if package_json:
        package_lower = package_json.lower()
        if "koa" in package_lower:
            detected.append("Node.js/Koa")
        if "express" in package_lower:
            detected.append("Node.js/Express")
        if "\"react\"" in package_lower:
            detected.append("React")
        if "\"vue\"" in package_lower:
            detected.append("Vue")

    python_manifest = "\n".join([requirements_txt, pyproject_toml]).lower()
    if "manage.py" in filenames or "django" in python_manifest:
        detected.append("Python/Django")
    if "flask" in python_manifest:
        detected.append("Python/Flask")
    if "fastapi" in python_manifest:
        detected.append("Python/FastAPI")
    if pom_xml:
        detected.append("Java/Spring")
    if go_mod:
        detected.append("Go")

    detected = list(dict.fromkeys(detected))

    if not detected:
        # Fallback: check by extension distribution
        ext_counts = {}
        for f in flat_files:
            ext = f.get("extension", "")
            ext_counts[ext] = ext_counts.get(ext, 0) + 1

        if ext_counts.get(".py", 0) > 3:
            detected.append("Python")
        elif ext_counts.get(".js", 0) > 3 or ext_counts.get(".ts", 0) > 3:
            detected.append("Node.js")
        elif ext_counts.get(".java", 0) > 3:
            detected.append("Java")
        elif ext_counts.get(".go", 0) > 3:
            detected.append("Go")

    return ", ".join(detected) if detected else "Unknown"


def _read_project_file(project_dir: str, filename: str) -> str:
    for root, dirs, files in os.walk(project_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        if filename in files:
            file_path = os.path.join(root, filename)
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    return f.read(200_000)
            except OSError:
                return ""
    return ""


def _flatten_files(tree: list) -> list:
    """Flatten the tree into a list of file nodes."""
    files = []
    for node in tree:
        if node["type"] == "file":
            files.append(node)
        elif node["type"] == "directory" and "children" in node:
            files.extend(_flatten_files(node["children"]))
    return files


def get_code_chunks(project_dir: str, file_tree: list, max_chunk_size: int = 3000, include_stats: bool = False) -> list[dict] | tuple[list[dict], dict]:
    """Read code files and split into chunks for LLM processing."""
    files = _flatten_files(file_tree)
    chunks = []
    total_chars = 0
    stats = {
        "files_considered": 0,
        "files_with_content": 0,
        "chunk_count": 0,
        "total_chars_loaded": 0,
        "truncated_by_total_chars": False,
        "oversized_files_compacted": 0,
    }

    for f in files:
        full_path = os.path.join(project_dir, f["path"])
        stats["files_considered"] += 1

        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception:
            continue

        if not content.strip():
            continue
        stats["files_with_content"] += 1

        if f.get("size", 0) > MAX_FILE_SIZE:
            sub_chunks = _build_oversized_file_chunks(f["path"], content)
            if sub_chunks:
                chunks.extend(sub_chunks)
                stats["oversized_files_compacted"] += 1
            total_chars += sum(len(chunk.get("content", "")) for chunk in sub_chunks)
        elif len(content) > max_chunk_size:
            sub_chunks = _split_file(f["path"], content, max_chunk_size)
            chunks.extend(sub_chunks)
            total_chars += len(content)
        else:
            chunks.append(_build_chunk(f["path"], content))
            total_chars += len(content)

        stats["total_chars_loaded"] = total_chars
        if total_chars > TOTAL_CHARS_LIMIT:
            stats["truncated_by_total_chars"] = True
            break

    stats["chunk_count"] = len(chunks)
    if include_stats:
        return chunks, stats
    return chunks


def extract_project_routes(project_dir: str, file_tree: list, include_stats: bool = False) -> list[dict] | tuple[list[dict], dict]:
    """Best-effort static route extraction for common web frameworks."""
    files = _flatten_files(file_tree)
    routes = []
    seen = set()
    stats = {"files_scanned": 0}
    file_contents: dict[str, str] = {}
    existing_py_paths = {
        file_node["path"].replace("\\", "/")
        for file_node in files
        if file_node["path"].lower().endswith(".py")
    }
    gin_prefixes = _build_gin_api_prefixes(project_dir, files)
    fastapi_prefixes = _build_fastapi_router_prefixes(project_dir, files)
    django_prefixes = _build_django_include_prefixes(project_dir, files)
    flask_prefixes = _build_flask_blueprint_prefixes(project_dir, files)
    js_router_prefixes = _build_js_router_prefixes(project_dir, files)
    nestjs_prefixes = _build_nestjs_module_prefixes(project_dir, files)

    for file_node in files:
        rel_path = file_node["path"]
        full_path = os.path.join(project_dir, rel_path)
        if file_node.get("size", 0) > MAX_FILE_SIZE:
            continue
        stats["files_scanned"] += 1

        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception:
            continue
        file_contents[rel_path] = content

        file_routes = _extract_routes_from_content(
            rel_path,
            content,
            prefix_override=(
                _resolve_prefix_for_path(rel_path, fastapi_prefixes)
                or _resolve_prefix_for_path(rel_path, django_prefixes)
                or _resolve_prefix_for_path(rel_path, flask_prefixes)
                or _resolve_prefix_for_path(rel_path, nestjs_prefixes)
                or js_router_prefixes.get(rel_path, "")
                or gin_prefixes.get(rel_path, "")
            ),
        )
        for route in file_routes:
            if rel_path.lower().endswith(".py"):
                route = _enrich_python_route_metadata(
                    route,
                    current_path=rel_path,
                    current_content=content,
                    file_contents=file_contents,
                    existing_paths=existing_py_paths,
                )
            key = (
                route.get("method", "UNKNOWN"),
                route.get("path", ""),
                route.get("handler", ""),
                route.get("file_path", rel_path),
            )
            if key in seen:
                continue
            seen.add(key)
            routes.append(route)

    if include_stats:
        return routes, stats
    return routes


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


def _extract_routes_from_content(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    routes = []
    effective_prefix = prefix_override
    fastapi_local_prefix = _extract_fastapi_local_prefix(content)
    flask_local_prefix = _extract_flask_local_prefix(content)
    if fastapi_local_prefix:
        effective_prefix = _join_route_paths(effective_prefix, fastapi_local_prefix)
    elif flask_local_prefix:
        effective_prefix = _join_route_paths(effective_prefix, flask_local_prefix)

    if file_path.lower().endswith(".go") or "gin." in content:
        routes.extend(_extract_gin_routes(file_path, content, prefix_override=prefix_override))
    if _looks_like_js_router_file(file_path, content):
        routes.extend(_extract_js_router_routes(file_path, content, prefix_override=prefix_override))
    if file_path.lower().endswith(".py") and ("Blueprint(" in content or ".route(" in content or "add_url_rule(" in content):
        routes.extend(_extract_flask_routes(file_path, content, prefix_override=effective_prefix))
    if file_path.lower().endswith((".ts", ".tsx", ".js")) and "@Controller" in content:
        routes.extend(_extract_nestjs_routes(file_path, content, prefix_override=prefix_override))
    if file_path.lower().endswith((".ts", ".tsx", ".js")) and "forRoutes(" in content:
        routes.extend(_extract_nestjs_forroutes_bindings(file_path, content, prefix_override=prefix_override))
    if file_path.lower().endswith(".java") or "@RequestMapping" in content or "@GetMapping" in content:
        routes.extend(_extract_spring_routes(file_path, content, prefix_override=prefix_override))

    # --- Additional framework patterns ---

    # JAX-RS (Java): @Path, @GET, @POST etc. on methods
    if file_path.lower().endswith(".java"):
        routes.extend(_extract_jaxrs_routes(file_path, content, prefix_override=prefix_override))

    # .NET/C#: [HttpGet], [Route], [ApiController] patterns
    if file_path.lower().endswith(".cs"):
        routes.extend(_extract_dotnet_routes(file_path, content, prefix_override=prefix_override))

    # Go: net/http, chi, echo, fiber, mux patterns
    if file_path.lower().endswith(".go"):
        routes.extend(_extract_go_stdlib_routes(file_path, content, prefix_override=prefix_override))

    # Ruby on Rails: routes.rb get/post/resources
    if file_path.lower().endswith(".rb") and "route" in content.lower():
        routes.extend(_extract_rails_routes(file_path, content, prefix_override=prefix_override))

    # Rust: actix_web #[route], rocket #[get], axum .route()
    if file_path.lower().endswith(".rs"):
        routes.extend(_extract_rust_routes(file_path, content, prefix_override=prefix_override))

    # PHP: Laravel Route::*, Symfony @Route annotation
    if file_path.lower().endswith(".php"):
        routes.extend(_extract_php_routes(file_path, content, prefix_override=prefix_override))

    # Python: FastAPI WebSocket, Tornado, aiohttp
    if file_path.lower().endswith(".py"):
        routes.extend(_extract_python_async_routes(file_path, content, prefix_override=effective_prefix))

    # DRF @action decorator on ViewSets
    if file_path.lower().endswith(".py") and "@action(" in content:
        routes.extend(_extract_drf_action_routes(file_path, content, prefix_override=effective_prefix))

    patterns = [
        (
            re.compile(
                r'@(?:\w+\.)?(get|post|put|delete|patch|options|head|route|websocket|ws)\(\s*["\']([^"\']*)["\']',
                re.I,
            ),
            "python_decorator",
        ),
        (
            re.compile(
                r'\b(?:app|router|bp|blueprint|api|server|service|app\.\w+)\.(get|post|put|delete|patch|options|head|all|use)\(\s*["\']([^"\']*)["\']',
                re.I,
            ),
            "js_style",
        ),
        (
            re.compile(
                r'path\(\s*["\']([^"\']*)["\']\s*,\s*([A-Za-z_][\w\.]*)',
                re.I,
            ),
            "django_path",
        ),
        (
            re.compile(
                r're_path\(\s*r?["\']([^"\']*)["\']\s*,\s*([A-Za-z_][\w\.]*)',
                re.I,
            ),
            "django_re_path",
        ),
        (
            re.compile(
                r'url\(\s*r?["\']([^"\']*)["\']\s*,\s*([A-Za-z_][\w\.]*)',
                re.I,
            ),
            "django_url",
        ),
        (
            re.compile(
                r'Route::(get|post|put|delete|patch|options|any)\(\s*["\']([^"\']+)["\']',
                re.I,
            ),
            "laravel",
        ),
    ]

    for pattern, kind in patterns:
        for match in pattern.finditer(content):
            if _is_comment_or_docstring_match(content, match.start()):
                continue
            if kind in {"python_decorator", "js_style", "laravel"}:
                method = match.group(1).upper()
                path = match.group(2)
                handler = _guess_handler_nearby(content, match.start())
            else:
                method = "ANY"
                path = match.group(1)
                handler = match.group(2)

            routes.append(
                {
                    "method": "ANY" if method == "ROUTE" else method,
                    "path": _join_route_paths(effective_prefix, path),
                    "handler": _normalize_handler_name(handler or "Unknown"),
                    "file_path": file_path,
                    "auth": _guess_auth_type(content),
                    "params": _merge_params(
                        _extract_route_params(path),
                        _extract_python_handler_params(content, _normalize_handler_name(handler or "Unknown")),
                    ),
                    "line_start": _line_number_from_offset(content, match.start()),
                    "source_kind": kind,
                    "notes": "Static route extraction",
                }
            )

    return routes


# ---------------------------------------------------------------------------
# Additional framework route extractors
# ---------------------------------------------------------------------------

def _extract_jaxrs_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    """Extract JAX-RS routes: class-level @Path + method-level @GET/@POST etc."""
    routes = []
    class_path = ""
    class_path_match = re.search(r'@Path\(\s*["\']([^"\']*)["\']', content)
    if class_path_match:
        class_path = class_path_match.group(1)

    method_map = {
        "@GET": "GET", "@POST": "POST", "@PUT": "PUT", "@DELETE": "DELETE",
        "@PATCH": "PATCH", "@HEAD": "HEAD", "@OPTIONS": "OPTIONS",
    }
    method_path_pattern = re.compile(
        r'@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\n\s*(?:@Path\(\s*["\']([^"\']*)["\']\s*\)\s*\n\s*)?(?:public|private|protected)\s+\S+\s+(\w+)\s*\(',
        re.I,
    )
    for match in method_path_pattern.finditer(content):
        annotation, sub_path, handler = match.group(1).upper(), match.group(2) or "", match.group(3)
        method = method_map.get(f"@{annotation}", "ANY")
        full_path = _join_route_paths(prefix_override, _join_route_paths(class_path, sub_path))
        routes.append({
            "method": method, "path": full_path, "handler": handler,
            "file_path": file_path, "auth": _guess_auth_type(content),
            "params": _extract_route_params(full_path), "notes": "Static route extraction (JAX-RS)",
        })
    return routes


def _extract_dotnet_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    """Extract ASP.NET Core routes: [Route], [HttpGet], [HttpPost] etc."""
    routes = []
    class_route = ""
    class_route_match = re.search(r'\[Route\(\s*@"?([^"\]\s]+)"?\s*\)\]', content)
    if not class_route_match:
        class_route_match = re.search(r'\[Route\(\s*["\']([^"\']+)["\']\s*\)\]', content)
    if class_route_match:
        class_route = class_route_match.group(1).replace("[controller]", "").replace("[action]", "")

    http_methods = ["HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch"]
    for method_attr in http_methods:
        pattern = re.compile(
            rf'\[{method_attr}(?:\(\s*(?:@"?([^"\]\s]+)"?|["\']([^"\']+)["\'])\s*\))?\]\s*(?:\[.*?\]\s*)*(?:public|private|protected)\s+\S+\s+(\w+)\s*\(',
            re.I,
        )
        for match in pattern.finditer(content):
            path = match.group(1) or match.group(2) or ""
            handler = match.group(3)
            method = method_attr.replace("Http", "").upper()
            full_path = _join_route_paths(prefix_override, _join_route_paths(class_route, path))
            routes.append({
                "method": method, "path": full_path, "handler": handler,
                "file_path": file_path, "auth": _guess_auth_type(content),
                "params": _extract_route_params(full_path), "notes": "Static route extraction (.NET)",
            })

    # [ApiController] + [Route("api/[controller]")] without method-level paths
    if "[ApiController]" in content and routes:
        pass  # already covered above
    return routes


def _extract_go_stdlib_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    """Extract Go stdlib net/http, chi, echo, fiber, gorilla/mux routes."""
    routes = []

    # chi r.Get / r.Post etc.
    chi_pattern = re.compile(r'(\w+)\.(Get|Post|Put|Delete|Patch|Head|Options|Connect|Trace|Handle|HandleFunc)\(\s*"([^"]+)"\s*,\s*(\w+(?:\.\w+)?)', re.I)
    chi_vars = set()
    for match in chi_pattern.finditer(content):
        var_name, method, path, handler = match.groups()
        chi_vars.add(var_name)
        http_method = method.upper() if method.lower() not in ("handle", "handlefunc") else "ANY"
        full_path = _join_route_paths(prefix_override, path)
        routes.append({
            "method": http_method, "path": full_path, "handler": _normalize_handler_name(handler),
            "file_path": file_path, "auth": _guess_auth_type(content),
            "params": _extract_route_params(full_path), "notes": "Static route extraction (Go chi)",
        })

    # echo e.GET / e.POST etc.
    echo_pattern = re.compile(r'(\w+)\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\(\s*"([^"]+)"\s*,\s*(\w+(?:\.\w+)?)', re.I)
    for match in echo_pattern.finditer(content):
        _, method, path, handler = match.groups()
        full_path = _join_route_paths(prefix_override, path)
        routes.append({
            "method": method.upper(), "path": full_path, "handler": _normalize_handler_name(handler),
            "file_path": file_path, "auth": _guess_auth_type(content),
            "params": _extract_route_params(full_path), "notes": "Static route extraction (Go echo)",
        })

    # fiber app.Get / app.Post etc.
    fiber_pattern = re.compile(r'(\w+)\.(Get|Post|Put|Delete|Patch|Head|Options|All|Use)\(\s*"([^"]+)"\s*,\s*(\w+(?:\.\w+)?)', re.I)
    for match in fiber_pattern.finditer(content):
        _, method, path, handler = match.groups()
        if "Use" in method:
            continue
        http_method = "ANY" if method.lower() == "all" else method.upper()
        full_path = _join_route_paths(prefix_override, path)
        routes.append({
            "method": http_method, "path": full_path, "handler": _normalize_handler_name(handler),
            "file_path": file_path, "auth": _guess_auth_type(content),
            "params": _extract_route_params(full_path), "notes": "Static route extraction (Go fiber)",
        })

    # stdlib http.HandleFunc / http.Handle
    stdlib_pattern = re.compile(r'http\.HandleFunc\(\s*"([^"]+)"\s*,\s*(\w+(?:\.\w+)?)', re.I)
    for match in stdlib_pattern.finditer(content):
        path, handler = match.groups()
        full_path = _join_route_paths(prefix_override, path)
        routes.append({
            "method": "ANY", "path": full_path, "handler": _normalize_handler_name(handler),
            "file_path": file_path, "auth": _guess_auth_type(content),
            "params": _extract_route_params(full_path), "notes": "Static route extraction (Go net/http)",
        })

    return routes


def _extract_rails_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    """Extract Ruby on Rails routes from routes.rb."""
    routes = []
    # Rails: get '/path', to: 'controller#action'
    rails_pattern = re.compile(
        r"(?:get|post|put|delete|patch)\s+['\"]([^'\"]+)['\"]",
        re.I,
    )
    for match in rails_pattern.finditer(content):
        path = match.group(1)
        method = content[match.start():match.start() + content[match.start():].find("'")].strip().split()[0].upper() if match.start() < len(content) else "ANY"
        method = content[match.start():].split("'")[0].split()[-1].upper() if content[match.start():].split("'") else "GET"
        # Simpler: just extract method from the match
        raw = content[match.start():match.start() + 10].lower()
        if raw.startswith("post"):
            method = "POST"
        elif raw.startswith("put"):
            method = "PUT"
        elif raw.startswith("delete"):
            method = "DELETE"
        elif raw.startswith("patch"):
            method = "PATCH"
        else:
            method = "GET"
        full_path = _join_route_paths(prefix_override, path)
        routes.append({
            "method": method, "path": full_path, "handler": "Unknown",
            "file_path": file_path, "auth": _guess_auth_type(content),
            "params": _extract_route_params(full_path), "notes": "Static route extraction (Rails)",
        })

    # Rails: resources :controller
    resources_pattern = re.compile(r"resources\s+:(['\"]?)(\w+)\1", re.I)
    for match in resources_pattern.finditer(content):
        resource = match.group(2)
        base = f"/{resource}"
        for m, p in [("GET", base), ("GET", f"{base}/:id"), ("POST", base), ("PATCH", f"{base}/:id"), ("DELETE", f"{base}/:id")]:
            full_path = _join_route_paths(prefix_override, p)
            routes.append({
                "method": m, "path": full_path, "handler": f"{resource}Controller",
                "file_path": file_path, "auth": _guess_auth_type(content),
                "params": _extract_route_params(full_path), "notes": "Static route extraction (Rails resources)",
            })
    return routes


def _extract_rust_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    """Extract Rust actix_web / rocket / axum routes."""
    routes = []

    # actix_web: #[route(method, path)] or #[get("/path")]
    actix_pattern = re.compile(r'#\[(\w+)\(\s*"([^"]+)"\s*\)', re.I)
    actix_methods = {"get": "GET", "post": "POST", "put": "PUT", "delete": "DELETE", "patch": "PATCH", "head": "HEAD", "options": "OPTIONS", "route": "ANY"}
    for match in actix_pattern.finditer(content):
        attr, path = match.group(1).lower(), match.group(2)
        method = actix_methods.get(attr)
        if not method:
            continue
        handler = _guess_handler_nearby(content, match.end()) or "Unknown"
        full_path = _join_route_paths(prefix_override, path)
        routes.append({
            "method": method, "path": full_path, "handler": _normalize_handler_name(handler),
            "file_path": file_path, "auth": _guess_auth_type(content),
            "params": _extract_route_params(full_path), "notes": "Static route extraction (Rust)",
        })

    # axum: .route("/path", get(handler)) / .route("/path", post(handler))
    axum_pattern = re.compile(r'\.route\(\s*"([^"]+)"\s*,\s*(get|post|put|delete|patch|head|options|any|any_method)\((\w+(?:::\w+)?)\)', re.I)
    for match in axum_pattern.finditer(content):
        path, method_str, handler = match.groups()
        method = method_str.upper() if method_str.lower() != "any" and method_str.lower() != "any_method" else "ANY"
        full_path = _join_route_paths(prefix_override, path)
        routes.append({
            "method": method, "path": full_path, "handler": _normalize_handler_name(handler),
            "file_path": file_path, "auth": _guess_auth_type(content),
            "params": _extract_route_params(full_path), "notes": "Static route extraction (Rust axum)",
        })
    return routes


def _extract_php_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    """Extract PHP Laravel and Symfony routes."""
    routes = []

    # Laravel: Route::get/post/put/delete/patch/any('/path', ...)
    laravel_pattern = re.compile(
        r"Route::(get|post|put|delete|patch|any|options|match)\(\s*['\"]([^'\"]+)['\"]",
        re.I,
    )
    for match in laravel_pattern.finditer(content):
        method_str, path = match.group(1).lower(), match.group(2)
        method = "ANY" if method_str in ("any", "match") else method_str.upper()
        full_path = _join_route_paths(prefix_override, path)
        routes.append({
            "method": method, "path": full_path, "handler": "Unknown",
            "file_path": file_path, "auth": _guess_auth_type(content),
            "params": _extract_route_params(full_path), "notes": "Static route extraction (Laravel)",
        })

    # Laravel: Route::resource('name', Controller)
    resource_pattern = re.compile(r"Route::resource\(\s*'([^']+)'", re.I)
    for match in resource_pattern.finditer(content):
        resource = match.group(1)
        base = f"/{resource}"
        for m, p in [("GET", base), ("GET", f"{base}/{{id}}"), ("POST", base), ("PUT", f"{base}/{{id}}"), ("PATCH", f"{base}/{{id}}"), ("DELETE", f"{base}/{{id}}")]:
            full_path = _join_route_paths(prefix_override, p)
            routes.append({
                "method": m, "path": full_path, "handler": "Unknown",
                "file_path": file_path, "auth": _guess_auth_type(content),
                "params": _extract_route_params(full_path), "notes": "Static route extraction (Laravel resource)",
            })

    # Symfony: #[Route('/path', methods: ['GET'])] or @Route("/path")
    symfony_pattern = re.compile(
        r"(?:#\[Route|@Route)\(\s*['\"]([^'\"]+)['\"].*?(?:methods:\s*\[([^\]]+)\]|methods\s*=\s*\{([^}]+)\})?",
        re.I,
    )
    for match in symfony_pattern.finditer(content):
        path = match.group(1)
        methods_str = match.group(2) or match.group(3) or ""
        methods = re.findall(r"'(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)'", methods_str, re.I)
        if not methods:
            methods = ["ANY"]
        for method in methods:
            full_path = _join_route_paths(prefix_override, path)
            routes.append({
                "method": method.upper(), "path": full_path, "handler": "Unknown",
                "file_path": file_path, "auth": _guess_auth_type(content),
                "params": _extract_route_params(full_path), "notes": "Static route extraction (Symfony)",
            })
    return routes


def _extract_python_async_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    """Extract FastAPI WebSocket, Tornado, aiohttp routes."""
    routes = []

    # FastAPI: @app.websocket("/path") or @router.websocket("/path")
    ws_pattern = re.compile(r'@(\w+)\.websocket\(\s*["\']([^"\']+)["\']', re.I)
    for match in ws_pattern.finditer(content):
        path = match.group(2)
        full_path = _join_route_paths(prefix_override, path)
        handler = _guess_handler_nearby(content, match.end()) or "Unknown"
        routes.append({
            "method": "WS", "path": full_path, "handler": _normalize_handler_name(handler),
            "file_path": file_path, "auth": _guess_auth_type(content),
            "params": [], "notes": "Static route extraction (WebSocket)",
        })

    # FastAPI: @app.api_route("/path", methods=[...])
    api_route_pattern = re.compile(r'@(\w+)\.api_route\(\s*["\']([^"\']+)["\'][^)]*methods\s*=\s*\[([^\]]+)\]', re.I)
    for match in api_route_pattern.finditer(content):
        _, path, methods_str = match.groups()
        methods = re.findall(r'"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)"', methods_str, re.I)
        handler = _guess_handler_nearby(content, match.end()) or "Unknown"
        for method in methods:
            full_path = _join_route_paths(prefix_override, path)
            routes.append({
                "method": method.upper(), "path": full_path, "handler": _normalize_handler_name(handler),
                "file_path": file_path, "auth": _guess_auth_type(content),
                "params": _extract_route_params(full_path), "notes": "Static route extraction (FastAPI api_route)",
            })

    # Tornado: (r"/path", Handler)
    tornado_pattern = re.compile(r'\(r?["\']([^"\']+)["\']\s*,\s*([A-Za-z_]\w*)\s*\)')
    for match in tornado_pattern.finditer(content):
        path, handler = match.group(1), match.group(2)
        if not path.startswith("/"):
            continue
        full_path = _join_route_paths(prefix_override, path)
        routes.append({
            "method": "ANY", "path": full_path, "handler": _normalize_handler_name(handler),
            "file_path": file_path, "auth": _guess_auth_type(content),
            "params": _extract_route_params(full_path), "notes": "Static route extraction (Tornado)",
        })

    # aiohttp: web.get("/path", handler) / web.post("/path", handler)
    aiohttp_pattern = re.compile(r'web\.(get|post|put|delete|patch|head|options|route)\(\s*["\']([^"\']+)["\']\s*,\s*(\w+)', re.I)
    for match in aiohttp_pattern.finditer(content):
        method_str, path, handler = match.groups()
        method = "ANY" if method_str.lower() == "route" else method_str.upper()
        full_path = _join_route_paths(prefix_override, path)
        routes.append({
            "method": method, "path": full_path, "handler": _normalize_handler_name(handler),
            "file_path": file_path, "auth": _guess_auth_type(content),
            "params": _extract_route_params(full_path), "notes": "Static route extraction (aiohttp)",
        })
    return routes


def _extract_drf_action_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    """Extract Django REST Framework @action decorated routes on ViewSets."""
    routes = []
    action_pattern = re.compile(
        r'@action\(([^)]*)\)',
        re.I,
    )
    for match in action_pattern.finditer(content):
        args = match.group(1)
        detail_match = re.search(r'detail\s*=\s*(True|False)', args, re.I)
        is_detail = detail_match and detail_match.group(1).lower() == "true" if detail_match else False
        url_path_match = re.search(r'url_path\s*=\s*["\']([^"\']+)["\']', args, re.I)
        url_path = url_path_match.group(1) if url_path_match else ""
        methods_match = re.findall(r'"(get|post|put|delete|patch|head|options)"', args, re.I)
        methods = [m.upper() for m in methods_match] if methods_match else ["ANY"]
        handler = _guess_handler_nearby(content, match.end()) or "Unknown"
        # detail actions use /{pk}/suffix, list actions use /suffix
        path = f"/{{pk}}/{url_path}" if is_detail and url_path else f"/{url_path}" if url_path else "/{pk}" if is_detail else "/"
        for method in methods:
            full_path = _join_route_paths(prefix_override, path)
            routes.append({
                "method": method, "path": full_path, "handler": _normalize_handler_name(handler),
                "file_path": file_path, "auth": _guess_auth_type(content),
                "params": _extract_route_params(full_path), "notes": "Static route extraction (DRF @action)",
            })
    return routes


def _looks_like_js_router_file(file_path: str, content: str) -> bool:
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        return False
    lowered = content.lower()
    return (
        "express.router(" in lowered
        or "router =" in lowered
        or ".router()" in lowered
        or "router.get(" in lowered
        or "router.post(" in lowered
        or "app.use(" in lowered
        or "router.use(" in lowered
    )


def _extract_js_router_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    routes = []
    lowered = content.lower()
    router_vars = {"app", "router", "api"}

    router_decl_patterns = [
        re.compile(r'(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*express\.router\(\s*\)', re.I),
        re.compile(r'(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*\w+\.router\(\s*\)', re.I),
        re.compile(r'(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*router\(\s*\)', re.I),
    ]
    for pattern in router_decl_patterns:
        for var_name in pattern.findall(content):
            router_vars.add(var_name)

    var_pattern = "|".join(sorted({re.escape(name) for name in router_vars}, key=len, reverse=True))
    route_pattern = re.compile(
        rf'\b({var_pattern})\.(get|post|put|delete|patch|options|head|all)\(\s*["\']([^"\']*)["\']',
        re.I,
    )

    for match in route_pattern.finditer(content):
        _, method, path = match.groups()
        routes.append(
            {
                "method": method.upper(),
                "path": _join_route_paths(prefix_override, path),
                "handler": _normalize_handler_name(_guess_handler_nearby(content, match.start()) or "Unknown"),
                "file_path": file_path,
                "auth": _guess_auth_type(content),
                "params": _extract_route_params(path),
                "notes": "Static route extraction (JS router)",
            }
        )

    return routes


def _extract_spring_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    routes = []
    class_base_path = ""

    class_mapping_match = re.search(
        r'@(?:RequestMapping|Controller)\(\s*(?:value\s*=\s*)?["\']([^"\']*)["\']',
        content,
        re.I,
    )
    if class_mapping_match:
        class_base_path = class_mapping_match.group(1)

    mapping_pattern = re.compile(
        r'@(?P<annotation>GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\((?P<args>[\s\S]{0,240}?)\)\s*(?:public|private|protected)\s+[^\(\n]+\s+(?P<handler>[A-Za-z_]\w*)\s*\(',
        re.I,
    )

    for match in mapping_pattern.finditer(content):
        annotation = match.group("annotation").lower()
        args = match.group("args") or ""
        handler = match.group("handler")
        method = "ANY"
        if "getmapping" in annotation:
            method = "GET"
        elif "postmapping" in annotation:
            method = "POST"
        elif "putmapping" in annotation:
            method = "PUT"
        elif "deletemapping" in annotation:
            method = "DELETE"
        elif "patchmapping" in annotation:
            method = "PATCH"
        else:
            method_match = re.search(r'RequestMethod\.(GET|POST|PUT|DELETE|PATCH)', args, re.I)
            if method_match:
                method = method_match.group(1).upper()

        path_match = re.search(r'(?:value|path)\s*=\s*["\']([^"\']*)["\']', args, re.I) or re.search(
            r'["\']([^"\']*)["\']',
            args,
            re.I,
        )
        method_path = path_match.group(1) if path_match else ""
        full_path = _join_route_paths(prefix_override, _join_route_paths(class_base_path, method_path))
        routes.append(
            {
                "method": method,
                "path": full_path,
                "handler": handler,
                "file_path": file_path,
                "auth": _guess_auth_type(content),
                "params": _extract_route_params(full_path),
                "notes": "Static route extraction (Spring)",
            }
        )

    return routes


def _extract_nestjs_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    routes = []
    controller_pattern = re.compile(
        r'@Controller\(\s*(?P<args>[\s\S]{0,200}?)\)\s*(?:export\s+)?class\s+(?P<class_name>[A-Za-z_]\w*)',
        re.I,
    )
    method_pattern = re.compile(
        r'@(?P<method>Get|Post|Put|Delete|Patch|Options|Head|All)\(\s*(?P<args>[\s\S]{0,200}?)\)\s*'
        r'(?:public\s+|private\s+|protected\s+|async\s+|static\s+)*'
        r'(?P<handler>[A-Za-z_]\w*)\s*\(',
        re.I,
    )

    for controller_match in controller_pattern.finditer(content):
        controller_args = controller_match.group("args") or ""
        controller_path = _extract_nestjs_path_from_args(controller_args)
        class_start = controller_match.end()
        next_controller = controller_pattern.search(content, class_start)
        class_block = content[class_start: next_controller.start() if next_controller else len(content)]

        for method_match in method_pattern.finditer(class_block):
            method = method_match.group("method").upper()
            handler = method_match.group("handler") or "Unknown"
            method_path = _extract_nestjs_path_from_args(method_match.group("args") or "")
            full_path = _join_route_paths(prefix_override, _join_route_paths(controller_path, method_path))
            routes.append(
                {
                    "method": "ANY" if method == "ALL" else method,
                    "path": full_path,
                    "handler": handler,
                    "file_path": file_path,
                    "auth": _guess_auth_type(content),
                    "params": _extract_route_params(full_path),
                    "notes": "Static route extraction (NestJS)",
                }
            )

    return routes


def _extract_nestjs_path_from_args(args: str) -> str:
    if not args:
        return ""
    string_match = re.search(r'["\']([^"\']*)["\']', args)
    if string_match:
        return string_match.group(1)
    path_match = re.search(r'\bpath\s*:\s*["\']([^"\']*)["\']', args, re.I)
    if path_match:
        return path_match.group(1)
    return ""


def _extract_nestjs_forroutes_bindings(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    routes = []
    binding_pattern = re.compile(
        r'consumer\.apply\((?P<middlewares>[\s\S]{0,400}?)\)\s*\.(?:exclude\([\s\S]{0,400}?\)\s*\.)*forRoutes\((?P<targets>[\s\S]{0,1200}?)\)',
        re.I,
    )

    for match in binding_pattern.finditer(content):
        middleware_text = re.sub(r'\s+', ' ', match.group("middlewares") or "").strip()
        middleware_text = middleware_text[:160]
        targets_text = match.group("targets") or ""
        binding_text = match.group(0) or ""
        excluded_targets = _extract_nestjs_exclude_targets(binding_text)
        for target in _extract_nestjs_forroutes_targets(targets_text):
            if _is_nestjs_target_excluded(target, excluded_targets):
                continue
            raw_path = target.get("path") or target.get("controller") or ""
            full_path = _join_route_paths(prefix_override, raw_path)
            handler = target.get("handler") or target.get("controller") or "Unknown"
            method = target.get("method") or "ANY"
            notes = "Static route extraction (NestJS forRoutes)"
            if middleware_text:
                notes += f" | middleware={middleware_text}"
            routes.append(
                {
                    "method": method,
                    "path": full_path,
                    "handler": handler,
                    "file_path": file_path,
                    "auth": _guess_auth_type(content),
                    "params": _extract_route_params(full_path),
                    "notes": notes,
                }
            )

    return routes


def _extract_nestjs_exclude_targets(binding_text: str) -> list[dict]:
    exclude_match = re.search(r'\.exclude\((?P<targets>[\s\S]{0,800}?)\)\s*\.forRoutes\(', binding_text, re.I)
    if not exclude_match:
        return []

    targets_text = exclude_match.group("targets") or ""
    exclusions = _extract_nestjs_forroutes_targets(targets_text)
    for raw_path in re.findall(r'["\']([^"\']+)["\']', targets_text):
        exclusions.append({"path": raw_path, "method": "ANY", "controller": "", "handler": ""})
    return _dedupe_nestjs_forroutes_targets(exclusions)


def _is_nestjs_target_excluded(target: dict, excluded_targets: list[dict]) -> bool:
    target_path = str(target.get("path", "")).strip("/")
    target_method = str(target.get("method", "ANY")).upper()
    target_controller = str(target.get("controller", "")).strip()

    for excluded in excluded_targets:
        excluded_path = str(excluded.get("path", "")).strip("/")
        excluded_method = str(excluded.get("method", "ANY")).upper()
        excluded_controller = str(excluded.get("controller", "")).strip()

        path_match = excluded_path and (
            excluded_path in {"*", "(.*)", "**"}
            or target_path == excluded_path
            or (excluded_path.endswith("*") and target_path.startswith(excluded_path[:-1]))
        )
        controller_match = excluded_controller and target_controller == excluded_controller
        method_match = excluded_method in {"ANY", target_method}
        if method_match and (path_match or controller_match):
            return True
    return False


def _extract_nestjs_forroutes_targets(targets_text: str) -> list[dict]:
    targets: list[dict] = []

    for object_text in _extract_top_level_object_literals(targets_text):
        path_match = re.search(r'\bpath\s*:\s*["\']([^"\']*)["\']', object_text, re.I)
        method_match = re.search(r'\bmethod\s*:\s*RequestMethod\.([A-Za-z_]\w*)', object_text, re.I)
        controller_match = re.search(r'\b(?:controller|name)\s*:\s*([A-Za-z_]\w*)', object_text, re.I)
        handler_match = re.search(r'\bhandler\s*:\s*([A-Za-z_]\w*)', object_text, re.I)
        if path_match or controller_match:
            targets.append(
                {
                    "path": path_match.group(1) if path_match else "",
                    "method": method_match.group(1).upper() if method_match else "ANY",
                    "controller": controller_match.group(1) if controller_match else "",
                    "handler": handler_match.group(1) if handler_match else "",
                }
            )

    controller_refs = re.findall(r'\b([A-Z][A-Za-z0-9_]*Controller)\b', targets_text)
    for controller_name in controller_refs:
        targets.append({"path": "", "method": "ANY", "controller": controller_name, "handler": ""})

    for raw_path in re.findall(r'["\']([^"\']+)["\']', targets_text):
        if raw_path in {"*", "(.*)"} or "/" in raw_path:
            targets.append({"path": raw_path, "method": "ANY", "controller": "", "handler": ""})

    return _dedupe_nestjs_forroutes_targets(targets)


def _dedupe_nestjs_forroutes_targets(targets: list[dict]) -> list[dict]:
    merged = []
    seen = set()
    for target in targets:
        key = (
            str(target.get("path", "")),
            str(target.get("method", "ANY")).upper(),
            str(target.get("controller", "")),
            str(target.get("handler", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        normalized = dict(target)
        normalized["method"] = str(normalized.get("method", "ANY")).upper()
        merged.append(normalized)
    return merged


def _build_nestjs_module_prefixes(project_dir: str, files: list[dict]) -> dict[str, str]:
    existing_paths = {
        file_node["path"].replace("\\", "/")
        for file_node in files
        if file_node["path"].lower().endswith((".ts", ".tsx", ".js"))
    }
    class_to_file: dict[str, str] = {}
    file_cache: dict[str, str] = {}

    for rel_path in existing_paths:
        full_path = os.path.join(project_dir, rel_path)
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception:
            continue
        file_cache[rel_path] = content
        for class_name in re.findall(r'(?:export\s+)?class\s+([A-Za-z_]\w*)', content):
            class_to_file.setdefault(class_name, rel_path)

    module_controllers: dict[str, list[str]] = {}
    module_routes: list[tuple[str, str]] = []

    for rel_path, content in file_cache.items():
        if "@Module" not in content:
            continue

        aliases = _extract_js_module_aliases(rel_path, content, existing_paths)
        module_match = re.search(
            r'@Module\(\s*(?P<args>[\s\S]{0,2500}?)\)\s*(?:export\s+)?class\s+(?P<class_name>[A-Za-z_]\w*)',
            content,
            re.I,
        )
        if not module_match:
            continue

        module_name = module_match.group("class_name")
        module_args = module_match.group("args") or ""
        controller_files: list[str] = []

        controllers_block = _extract_named_array_literal(module_args, "controllers")
        for controller_name in _extract_identifier_list(controllers_block):
            target_file = aliases.get(controller_name) or class_to_file.get(controller_name)
            if target_file:
                controller_files.append(target_file)
        module_controllers[module_name] = _merge_unique_paths(controller_files)

        imports_block = _extract_named_array_literal(module_args, "imports")
        for route_prefix, route_module in _extract_nestjs_router_module_routes(imports_block):
            module_routes.append((route_prefix, route_module))

    prefixes: dict[str, str] = {}
    for route_prefix, module_name in module_routes:
        for controller_file in module_controllers.get(module_name, []):
            current_prefix = prefixes.get(controller_file)
            next_prefix = _normalize_route_path(route_prefix or "/")
            if not current_prefix or len(next_prefix) < len(current_prefix):
                prefixes[controller_file] = next_prefix

    return prefixes


def _extract_named_array_literal(content: str, key: str) -> str:
    match = re.search(rf'\b{re.escape(key)}\s*:\s*\[', content, re.I)
    if not match:
        return ""
    return _extract_balanced_segment(content, match.end() - 1, "[", "]")


def _extract_balanced_segment(text: str, start_index: int, open_char: str, close_char: str) -> str:
    if start_index < 0 or start_index >= len(text) or text[start_index] != open_char:
        return ""
    depth = 0
    in_string = False
    quote_char = ""
    escaped = False

    for index in range(start_index, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote_char:
                in_string = False
            continue

        if char in {"'", '"', "`"}:
            in_string = True
            quote_char = char
            continue
        if char == open_char:
            depth += 1
            continue
        if char == close_char:
            depth -= 1
            if depth == 0:
                return text[start_index:index + 1]
    return ""


def _extract_identifier_list(array_literal: str) -> list[str]:
    if not array_literal:
        return []
    identifiers = re.findall(r'\b([A-Z][A-Za-z0-9_]*)\b', array_literal)
    return _merge_unique_paths(identifiers)


def _extract_nestjs_router_module_routes(imports_block: str) -> list[tuple[str, str]]:
    if not imports_block:
        return []

    routes: list[tuple[str, str]] = []
    register_pattern = re.compile(r'RouterModule\.register\s*\(', re.I)
    for match in register_pattern.finditer(imports_block):
        open_index = imports_block.find("(", match.start())
        if open_index < 0:
            continue
        register_args = _extract_balanced_segment(imports_block, open_index, "(", ")")
        if not register_args:
            continue
        routes.extend(_parse_nestjs_route_tree(register_args[1:-1], ""))
    return routes


def _parse_nestjs_route_tree(route_text: str, parent_prefix: str) -> list[tuple[str, str]]:
    routes: list[tuple[str, str]] = []
    for object_text in _extract_top_level_object_literals(route_text):
        path_match = re.search(r'\bpath\s*:\s*["\']([^"\']*)["\']', object_text, re.I)
        module_match = re.search(r'\bmodule\s*:\s*([A-Za-z_]\w*)', object_text, re.I)
        next_prefix = _join_route_paths(parent_prefix, path_match.group(1) if path_match else "")
        if module_match:
            routes.append((next_prefix, module_match.group(1)))

        children_match = re.search(r'\bchildren\s*:\s*\[', object_text, re.I)
        if children_match:
            child_array = _extract_balanced_segment(object_text, children_match.end() - 1, "[", "]")
            if child_array:
                routes.extend(_parse_nestjs_route_tree(child_array[1:-1], next_prefix))
    return routes


def _extract_top_level_object_literals(text: str) -> list[str]:
    objects: list[str] = []
    depth = 0
    start_index = -1
    in_string = False
    quote_char = ""
    escaped = False

    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote_char:
                in_string = False
            continue

        if char in {"'", '"', "`"}:
            in_string = True
            quote_char = char
            continue
        if char == "{":
            if depth == 0:
                start_index = index
            depth += 1
            continue
        if char == "}":
            depth -= 1
            if depth == 0 and start_index >= 0:
                objects.append(text[start_index:index + 1])
                start_index = -1
    return objects


def _merge_unique_paths(items: list[str]) -> list[str]:
    merged: list[str] = []
    seen = set()
    for item in items:
        normalized = str(item).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        merged.append(normalized)
    return merged


def _build_js_router_prefixes(project_dir: str, files: list[dict]) -> dict[str, str]:
    existing_paths = {file_node["path"].replace("\\", "/") for file_node in files}
    mounts_by_file: dict[str, list[tuple[str, str]]] = {}
    router_files: set[str] = set()

    for file_node in files:
        rel_path = file_node["path"]
        ext = os.path.splitext(rel_path)[1].lower()
        if ext not in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
            continue

        full_path = os.path.join(project_dir, rel_path)
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception:
            continue

        aliases = _extract_js_module_aliases(rel_path, content, existing_paths)
        use_pattern = re.compile(
            r'\b([A-Za-z_]\w*)\.use\(\s*["\']([^"\']*)["\']\s*,\s*([A-Za-z_]\w*)\s*\)',
            re.I,
        )
        mounts = []
        for parent_var, prefix, alias in use_pattern.findall(content):
            target = aliases.get(alias)
            if not target:
                continue
            mounts.append((parent_var, prefix, target))
            router_files.add(target)
        if mounts:
            mounts_by_file[rel_path] = mounts

    prefixes: dict[str, str] = {}
    changed = True
    while changed:
        changed = False
        for rel_path, mounts in mounts_by_file.items():
            parent_is_root = _looks_like_root_router_file(rel_path)
            parent_prefix = prefixes.get(rel_path, "")
            for parent_var, mount_prefix, target in mounts:
                base_prefix = parent_prefix
                if _is_root_router_var(parent_var) and parent_is_root:
                    base_prefix = ""
                elif rel_path not in prefixes and not parent_is_root:
                    continue
                combined_prefix = _join_route_paths(base_prefix, mount_prefix)
                if prefixes.get(target) != combined_prefix:
                    prefixes[target] = combined_prefix
                    changed = True

    return prefixes


def _is_root_router_var(name: str) -> bool:
    return name.lower() in {"app", "server", "api", "application"}


def _looks_like_root_router_file(rel_path: str) -> bool:
    normalized = rel_path.replace("\\", "/").lower()
    root_markers = [
        "main.", "app.", "server.", "index.", "bootstrap.", "entry.",
        "/main.", "/app.", "/server.", "/index.", "/bootstrap.", "/entry.",
    ]
    return any(marker in normalized for marker in root_markers)


def _extract_js_module_aliases(current_path: str, content: str, existing_paths: set[str]) -> dict[str, str]:
    aliases: dict[str, str] = {}

    import_pattern = re.compile(
        r'import\s+([A-Za-z_]\w*)\s+from\s+["\']([^"\']+)["\']',
        re.I,
    )
    named_import_pattern = re.compile(
        r'import\s*\{([^}]+)\}\s*from\s+["\']([^"\']+)["\']',
        re.I,
    )
    mixed_import_pattern = re.compile(
        r'import\s+([A-Za-z_]\w*)\s*,\s*\{([^}]+)\}\s*from\s+["\']([^"\']+)["\']',
        re.I,
    )
    require_pattern = re.compile(
        r'(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*require\(\s*["\']([^"\']+)["\']\s*\)',
        re.I,
    )

    for alias, module_path in import_pattern.findall(content):
        resolved = _resolve_js_module_to_relpath(current_path, module_path, existing_paths)
        if resolved:
            aliases[alias] = resolved

    for default_alias, named_imports, module_path in mixed_import_pattern.findall(content):
        resolved = _resolve_js_module_to_relpath(current_path, module_path, existing_paths)
        if not resolved:
            continue
        aliases[default_alias] = resolved
        for item in named_imports.split(","):
            value = item.strip()
            if not value:
                continue
            if " as " in value:
                name, alias = [part.strip() for part in value.split(" as ", 1)]
            else:
                name = alias = value
            if name and alias:
                aliases[alias] = resolved

    for named_imports, module_path in named_import_pattern.findall(content):
        resolved = _resolve_js_module_to_relpath(current_path, module_path, existing_paths)
        if not resolved:
            continue
        for item in named_imports.split(","):
            value = item.strip()
            if not value:
                continue
            if " as " in value:
                name, alias = [part.strip() for part in value.split(" as ", 1)]
            else:
                name = alias = value
            if name and alias:
                aliases[alias] = resolved

    for alias, module_path in require_pattern.findall(content):
        resolved = _resolve_js_module_to_relpath(current_path, module_path, existing_paths)
        if resolved:
            aliases[alias] = resolved

    return aliases


def _resolve_js_module_to_relpath(current_path: str, module_path: str, existing_paths: set[str]) -> str | None:
    if not module_path.startswith("."):
        return None

    current_dir = os.path.dirname(current_path).replace("\\", "/")
    base_dir = os.path.normpath(os.path.join(current_dir, module_path)).replace("\\", "/")
    candidates = [
        base_dir,
        f"{base_dir}.js",
        f"{base_dir}.ts",
        f"{base_dir}.jsx",
        f"{base_dir}.tsx",
        f"{base_dir}/index.js",
        f"{base_dir}/index.ts",
    ]
    for candidate in candidates:
        normalized = candidate.lstrip("./")
        if normalized and normalized in existing_paths:
            return normalized
    return None


def _extract_fastapi_local_prefix(content: str) -> str:
    match = re.search(r'APIRouter\((?P<args>[\s\S]{0,240}?)\)', content, re.I)
    if not match:
        return ""
    args = match.group("args") or ""
    prefix_match = re.search(r'prefix\s*=\s*["\']([^"\']*)["\']', args, re.I)
    return _normalize_route_path(prefix_match.group(1) or "") if prefix_match else ""


def _extract_flask_local_prefix(content: str) -> str:
    match = re.search(r'Blueprint\((?P<args>[\s\S]{0,240}?)\)', content, re.I)
    if not match:
        return ""
    args = match.group("args") or ""
    prefix_match = re.search(r'url_prefix\s*=\s*["\']([^"\']*)["\']', args, re.I)
    return _normalize_route_path(prefix_match.group(1) or "") if prefix_match else ""


def _extract_flask_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    routes = []
    blueprint_vars = {"app", "bp", "blueprint"}
    blueprint_decl_pattern = re.compile(
        r'(?:const\s+)?([A-Za-z_]\w*)\s*=\s*Blueprint\(',
        re.I,
    )
    for var_name in blueprint_decl_pattern.findall(content):
        blueprint_vars.add(var_name)

    var_pattern = "|".join(sorted({re.escape(name) for name in blueprint_vars}, key=len, reverse=True))
    if not var_pattern:
        return routes

    decorator_pattern = re.compile(
        rf'@(?P<target>{var_pattern})\.(?:route|get|post|put|delete|patch)\(\s*["\'](?P<path>[^"\']*)["\'](?P<args>[\s\S]{{0,240}}?)\)',
        re.I,
    )
    for match in decorator_pattern.finditer(content):
        args = match.group("args") or ""
        method = "ANY"
        explicit_methods = re.findall(r'["\'](GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)["\']', args, re.I)
        if explicit_methods:
            methods = [item.upper() for item in explicit_methods]
        else:
            methods = [method]
        handler = _guess_handler_nearby(content, match.start())
        for current_method in methods:
            routes.append(
                {
                    "method": current_method,
                    "path": _join_route_paths(prefix_override, match.group("path")),
                    "handler": _normalize_handler_name(handler or "Unknown"),
                    "file_path": file_path,
                    "auth": _guess_auth_type(content),
                    "params": _merge_params(
                        _extract_route_params(match.group("path")),
                        _extract_python_handler_params(content, _normalize_handler_name(handler or "Unknown")),
                    ),
                    "line_start": _line_number_from_offset(content, match.start()),
                    "source_kind": "flask_decorator",
                    "notes": "Static route extraction (Flask)",
                }
            )

    add_rule_pattern = re.compile(
        rf'\b(?P<target>{var_pattern})\.add_url_rule\(\s*["\'](?P<path>[^"\']*)["\'](?P<args>[\s\S]{{0,260}}?)\)',
        re.I,
    )
    for match in add_rule_pattern.finditer(content):
        args = match.group("args") or ""
        handler_match = re.search(r'view_func\s*=\s*([A-Za-z_][\w\.]*)', args, re.I)
        explicit_methods = re.findall(r'["\'](GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)["\']', args, re.I)
        methods = [item.upper() for item in explicit_methods] if explicit_methods else ["ANY"]
        for current_method in methods:
            routes.append(
                {
                    "method": current_method,
                    "path": _join_route_paths(prefix_override, match.group("path")),
                    "handler": _normalize_handler_name(handler_match.group(1) if handler_match else "Unknown"),
                    "file_path": file_path,
                    "auth": _guess_auth_type(content),
                    "params": _merge_params(
                        _extract_route_params(match.group("path")),
                        _extract_python_handler_params(content, _normalize_handler_name(handler_match.group(1) if handler_match else "Unknown")),
                    ),
                    "line_start": _line_number_from_offset(content, match.start()),
                    "source_kind": "flask_add_url_rule",
                    "notes": "Static route extraction (Flask add_url_rule)",
                }
            )

    return routes


def _build_flask_blueprint_prefixes(project_dir: str, files: list[dict]) -> dict[str, str]:
    existing_paths = {
        file_node["path"].replace("\\", "/")
        for file_node in files
        if file_node["path"].lower().endswith(".py")
    }
    mounts_by_file: dict[str, list[tuple[str, str]]] = {}
    prefixes: dict[str, str] = {}
    root_files: set[str] = set()

    for file_node in files:
        rel_path = file_node["path"]
        if not rel_path.lower().endswith(".py"):
            continue

        full_path = os.path.join(project_dir, rel_path)
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception:
            continue

        aliases = _extract_python_module_aliases(rel_path, content, existing_paths)
        if "Flask(" in content or _looks_like_root_router_file(rel_path):
            root_files.add(rel_path)

        register_pattern = re.compile(
            r'register_blueprint\(\s*([A-Za-z_][\w\.]*)\s*(?:,\s*(?P<args>[\s\S]{0,240}?))?\)',
            re.I,
        )
        mounts: list[tuple[str, str]] = []
        for match in register_pattern.finditer(content):
            blueprint_ref = match.group(1)
            args = match.group("args") or ""
            target_path = aliases.get(blueprint_ref)
            if not target_path:
                continue
            prefix_match = re.search(r'url_prefix\s*=\s*["\']([^"\']*)["\']', args, re.I)
            mounts.append((target_path, prefix_match.group(1) if prefix_match else ""))
        if mounts:
            mounts_by_file[rel_path] = mounts

    changed = True
    while changed:
        changed = False
        for rel_path, mounts in mounts_by_file.items():
            parent_prefix = prefixes.get(rel_path, "")
            if rel_path not in root_files and rel_path not in prefixes:
                continue
            for target_path, mount_prefix in mounts:
                combined_prefix = _join_route_paths(parent_prefix, mount_prefix)
                if prefixes.get(target_path) != combined_prefix:
                    prefixes[target_path] = combined_prefix
                    changed = True

    return prefixes


def _build_fastapi_router_prefixes(project_dir: str, files: list[dict]) -> dict[str, str]:
    prefixes: dict[str, str] = {}
    existing_paths = {
        file_node["path"].replace("\\", "/")
        for file_node in files
        if file_node["path"].lower().endswith(".py")
    }
    mounts_by_file: dict[str, list[tuple[str, str]]] = {}
    root_files: set[str] = set()

    for file_node in files:
        rel_path = file_node["path"]
        if not rel_path.lower().endswith(".py"):
            continue

        full_path = os.path.join(project_dir, rel_path)
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception:
            continue

        module_aliases = _extract_python_module_aliases(rel_path, content, existing_paths)
        if "FastAPI(" in content or _looks_like_root_router_file(rel_path):
            root_files.add(rel_path)
        if not module_aliases or "include_router" not in content:
            continue

        include_router_pattern = re.compile(
            r'include_router\(\s*([A-Za-z_][\w\.]*)\s*(?:,\s*(?P<args>[\s\S]{0,320}?))?\)',
            re.I,
        )
        mounts: list[tuple[str, str]] = []
        for match in include_router_pattern.finditer(content):
            router_ref = match.group(1)
            args = match.group("args") or ""
            target_path = module_aliases.get(router_ref)
            if not target_path and router_ref.endswith(".router"):
                target_path = module_aliases.get(router_ref.rsplit(".", 1)[0])
            if not target_path:
                continue

            prefix_match = re.search(r'prefix\s*=\s*["\']([^"\']*)["\']', args, re.I)
            mounts.append((target_path, prefix_match.group(1) if prefix_match else ""))
        if mounts:
            mounts_by_file[rel_path] = mounts

    changed = True
    while changed:
        changed = False
        for rel_path, mounts in mounts_by_file.items():
            parent_prefix = prefixes.get(rel_path, "")
            if rel_path not in root_files and rel_path not in prefixes:
                continue
            for target_path, mount_prefix in mounts:
                combined_prefix = _join_route_paths(parent_prefix, mount_prefix)
                existing_prefix = prefixes.get(target_path)
                if existing_prefix and len(existing_prefix) <= len(combined_prefix):
                    continue
                prefixes[target_path] = combined_prefix
                changed = True

    return prefixes


def _build_django_include_prefixes(project_dir: str, files: list[dict]) -> dict[str, str]:
    file_paths = {
        file_node["path"].replace("\\", "/")
        for file_node in files
        if file_node["path"].lower().endswith(".py")
    }
    include_graph: dict[str, list[tuple[str, str]]] = {}
    reverse_graph: dict[str, list[tuple[str, str]]] = {}
    root_candidates: set[str] = set()

    for rel_path in file_paths:
        full_path = os.path.join(project_dir, rel_path)
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception:
            continue

        if _looks_like_django_root_urls(rel_path):
            root_candidates.add(rel_path)

        aliases = _extract_python_module_aliases(rel_path, content, file_paths)
        pattern_list_targets = _extract_django_pattern_list_targets(content, aliases)
        include_targets = _extract_django_include_targets(content, aliases, pattern_list_targets)
        include_targets.extend(_extract_django_urlpattern_extensions(content, aliases, pattern_list_targets))
        if not include_targets:
            continue

        for include_prefix, target_path in include_targets:
            if target_path not in file_paths:
                continue
            include_graph.setdefault(rel_path, []).append((include_prefix, target_path))
            reverse_graph.setdefault(target_path, []).append((rel_path, include_prefix))

    if reverse_graph:
        inferred_roots = set(include_graph) - set(reverse_graph)
        root_candidates.update(inferred_roots)

    if not root_candidates:
        root_candidates = {path for path in file_paths if _looks_like_django_root_urls(path)}

    prefixes: dict[str, str] = {}
    visited_edges: set[tuple[str, str, str]] = set()

    def dfs(current_path: str, current_prefix: str) -> None:
        normalized_prefix = _normalize_route_path(current_prefix or "/")
        existing = prefixes.get(current_path)
        if existing:
            if len(normalized_prefix) >= len(existing):
                return
        prefixes[current_path] = normalized_prefix

        for child_prefix, target_path in include_graph.get(current_path, []):
            edge = (current_path, child_prefix, target_path)
            if edge in visited_edges:
                continue
            visited_edges.add(edge)
            dfs(target_path, _join_route_paths(normalized_prefix, child_prefix))

    for root_path in sorted(root_candidates):
        dfs(root_path, "/")

    return prefixes


def _looks_like_django_root_urls(rel_path: str) -> bool:
    normalized = rel_path.replace("\\", "/").lower()
    if not normalized.endswith("urls.py"):
        return False
    return (
        normalized.count("/") <= 1
        or normalized.endswith("/config/urls.py")
        or normalized.endswith("/project/urls.py")
        or normalized.endswith("/settings/urls.py")
    )


def _extract_django_include_targets(
    content: str,
    aliases: dict[str, str],
    pattern_list_targets: dict[str, list[tuple[str, str]]] | None = None,
) -> list[tuple[str, str]]:
    targets: list[tuple[str, str]] = []
    pattern_list_targets = pattern_list_targets or {}
    include_path_pattern = re.compile(
        r'(?:path|re_path)\(\s*r?["\']([^"\']*)["\']\s*,\s*include\(\s*(?:\(\s*)?["\']([^"\']+)["\']',
        re.I,
    )
    include_tuple_path_pattern = re.compile(
        r'(?:path|re_path)\(\s*r?["\']([^"\']*)["\']\s*,\s*include\(\s*\(\s*["\']([^"\']+)["\']\s*,',
        re.I,
    )
    include_alias_pattern = re.compile(
        r'(?:path|re_path)\(\s*r?["\']([^"\']*)["\']\s*,\s*include\(\s*(?:\(\s*)?([A-Za-z_][\w\.]*)',
        re.I,
    )
    include_tuple_alias_pattern = re.compile(
        r'(?:path|re_path)\(\s*r?["\']([^"\']*)["\']\s*,\s*include\(\s*\(\s*([A-Za-z_][\w\.]*)\s*,',
        re.I,
    )
    include_var_pattern = re.compile(
        r'(?:path|re_path)\(\s*r?["\']([^"\']*)["\']\s*,\s*include\(\s*([A-Za-z_][\w]*)\s*[\),]',
        re.I,
    )

    for raw_prefix, module_name in include_path_pattern.findall(content):
        target_path = _python_module_to_relpath(module_name)
        if target_path:
            targets.append((raw_prefix, target_path))

    for raw_prefix, module_name in include_tuple_path_pattern.findall(content):
        target_path = _python_module_to_relpath(module_name)
        if target_path:
            targets.append((raw_prefix, target_path))

    for raw_prefix, module_ref in include_alias_pattern.findall(content):
        target_path = aliases.get(module_ref)
        if target_path:
            targets.append((raw_prefix, target_path))

    for raw_prefix, module_ref in include_tuple_alias_pattern.findall(content):
        target_path = aliases.get(module_ref)
        if target_path:
            targets.append((raw_prefix, target_path))

    for raw_prefix, module_ref in include_var_pattern.findall(content):
        target_path = aliases.get(module_ref)
        if target_path:
            targets.append((raw_prefix, target_path))
        for nested_prefix, nested_target in pattern_list_targets.get(module_ref, []):
            targets.append((_join_route_paths(raw_prefix, nested_prefix), nested_target))

    return targets


def _extract_django_pattern_list_targets(
    content: str,
    aliases: dict[str, str],
) -> dict[str, list[tuple[str, str]]]:
    pattern_lists: dict[str, list[tuple[str, str]]] = {}
    assignment_pattern = re.compile(r'\b([A-Za-z_]\w*)\s*=\s*\[', re.I)

    for match in assignment_pattern.finditer(content):
        var_name = match.group(1)
        array_literal = _extract_balanced_segment(content, match.end() - 1, "[", "]")
        if not array_literal:
            continue
        nested_targets = _extract_django_include_targets(array_literal, aliases, {})
        if nested_targets:
            pattern_lists[var_name] = nested_targets

    return pattern_lists


def _extract_django_urlpattern_extensions(
    content: str,
    aliases: dict[str, str],
    pattern_list_targets: dict[str, list[tuple[str, str]]] | None = None,
) -> list[tuple[str, str]]:
    targets: list[tuple[str, str]] = []
    pattern_list_targets = pattern_list_targets or {}
    extension_pattern = re.compile(r'urlpatterns\s*\+=\s*([A-Za-z_][\w]*)', re.I)
    assignment_concat_pattern = re.compile(r'urlpatterns\s*=\s*([A-Za-z_][\w]*(?:\s*\+\s*[A-Za-z_][\w]*)+)', re.I)

    for alias in extension_pattern.findall(content):
        target_path = aliases.get(alias)
        if target_path and target_path.lower().endswith("urls.py"):
            targets.append(("", target_path))
        targets.extend(pattern_list_targets.get(alias, []))

    for expression in assignment_concat_pattern.findall(content):
        for alias in re.findall(r'[A-Za-z_][\w]*', expression):
            target_path = aliases.get(alias)
            if target_path and target_path.lower().endswith("urls.py"):
                targets.append(("", target_path))
            targets.extend(pattern_list_targets.get(alias, []))

    return targets


def _resolve_prefix_for_path(rel_path: str, prefixes: dict[str, str]) -> str:
    if rel_path in prefixes:
        return prefixes[rel_path]

    basename = os.path.basename(rel_path)
    if basename in prefixes:
        return prefixes[basename]

    return ""


def _extract_python_module_aliases(current_path: str, content: str, existing_paths: set[str] | None = None) -> dict[str, str]:
    aliases: dict[str, str] = {}

    from_import_pattern = re.compile(r'from\s+([A-Za-z_][\w\.]*)\s+import\s+([^\n]+)')
    relative_from_import_pattern = re.compile(r'from\s+(\.+[A-Za-z_][\w\.]*)\s+import\s+([^\n]+)')
    for module_base, imported in from_import_pattern.findall(content):
        for part in imported.split(","):
            item = part.strip()
            if not item:
                continue

            if " as " in item:
                name, alias = [value.strip() for value in item.split(" as ", 1)]
            else:
                name = alias = item

            target = _resolve_python_import_target(module_base, name, current_path=current_path, existing_paths=existing_paths)
            if target:
                aliases[alias] = target

    for module_base, imported in relative_from_import_pattern.findall(content):
        for part in imported.split(","):
            item = part.strip()
            if not item:
                continue

            if " as " in item:
                name, alias = [value.strip() for value in item.split(" as ", 1)]
            else:
                name = alias = item

            target = _resolve_python_import_target(module_base, name, current_path=current_path, existing_paths=existing_paths)
            if target:
                aliases[alias] = target

    import_pattern = re.compile(r'import\s+([A-Za-z_][\w\.]*)(?:\s+as\s+([A-Za-z_]\w*))?')
    for module_name, alias in import_pattern.findall(content):
        target = _python_module_to_relpath(module_name, current_path=current_path, existing_paths=existing_paths)
        if not target:
            continue
        aliases[alias or module_name.split(".")[-1]] = target

    return aliases


def _extract_python_wildcard_import_paths(current_path: str, content: str, existing_paths: set[str] | None = None) -> list[str]:
    targets: list[str] = []
    wildcard_pattern = re.compile(r'from\s+([A-Za-z_\.][\w\.]*)\s+import\s+\*')
    for module_base in wildcard_pattern.findall(content):
        target = _python_module_to_relpath(module_base, current_path=current_path, existing_paths=existing_paths)
        if target:
            targets.append(target)
    return _dedupe_preserve_order(targets)


def _enrich_python_route_metadata(
    route: dict,
    *,
    current_path: str,
    current_content: str,
    file_contents: dict[str, str],
    existing_paths: set[str],
) -> dict:
    if not isinstance(route, dict):
        return route
    handler = str(route.get("handler", "") or "").strip()
    if not handler or handler == "Unknown":
        return route

    handler_name = handler.split(".")[-1].replace(".as_view", "").strip()
    target_path = current_path
    target_content = current_content

    if f"def {handler_name}(" not in current_content and f"async def {handler_name}(" not in current_content:
        aliases = _extract_python_module_aliases(current_path, current_content, existing_paths)
        wildcard_targets = _extract_python_wildcard_import_paths(current_path, current_content, existing_paths)
        dotted_base = handler.split(".", 1)[0] if "." in handler else ""

        if dotted_base and dotted_base in aliases:
            candidate_path = aliases.get(dotted_base)
            candidate_content = file_contents.get(candidate_path or "", "")
            if candidate_path and candidate_content:
                target_path = candidate_path
                target_content = candidate_content
        else:
            for candidate_path in wildcard_targets:
                candidate_content = file_contents.get(candidate_path, "")
                if f"def {handler_name}(" in candidate_content or f"async def {handler_name}(" in candidate_content:
                    target_path = candidate_path
                    target_content = candidate_content
                    break

    handler_defined = (
        f"def {handler_name}(" in target_content
        or f"async def {handler_name}(" in target_content
    )
    if not handler_defined:
        return route

    params = _extract_python_handler_params(target_content, handler_name)
    if target_path and target_path != current_path:
        route["handler_file_path"] = target_path
    if params:
        route["params"] = _merge_params(route.get("params", []) if isinstance(route.get("params"), list) else [], params)
    target_auth = _guess_auth_type(target_content)
    if target_auth and str(route.get("auth", "Unknown")).lower() in {"none", "unknown", ""}:
        route["auth"] = target_auth
    return route


def _resolve_python_import_target(
    module_base: str,
    imported_name: str | None = None,
    current_path: str | None = None,
    existing_paths: set[str] | None = None,
) -> str | None:
    imported_name = (imported_name or "").strip()
    if imported_name in {"urlpatterns", "app_name"}:
        return _python_module_to_relpath(module_base, current_path=current_path, existing_paths=existing_paths)
    if imported_name.endswith("_urlpatterns") or imported_name.endswith("_urls"):
        return _python_module_to_relpath(module_base, current_path=current_path, existing_paths=existing_paths)
    if imported_name in ROUTE_EXPORT_NAMES:
        return _python_module_to_relpath(module_base, current_path=current_path, existing_paths=existing_paths)
    return _python_module_to_relpath(
        module_base,
        imported_name or None,
        current_path=current_path,
        existing_paths=existing_paths,
    )


def _python_module_to_relpath(
    module_base: str,
    imported_name: str | None = None,
    current_path: str | None = None,
    existing_paths: set[str] | None = None,
) -> str | None:
    imported_name = (imported_name or "").strip()
    current_parts = [part for part in str(current_path or "").replace("\\", "/").split("/") if part]
    if current_parts and current_parts[-1].endswith(".py"):
        current_parts = current_parts[:-1]

    if module_base.startswith("."):
        level = len(module_base) - len(module_base.lstrip("."))
        remainder = module_base[level:]
        base_parts = current_parts[: max(len(current_parts) - max(level - 1, 0), 0)]
        module_parts = base_parts + [part for part in remainder.split(".") if part]
    else:
        module_parts = [part for part in module_base.split(".") if part]

    if not module_parts:
        return None

    candidates: list[str] = []
    module_path = "/".join(module_parts)
    if imported_name and imported_name not in ROUTE_EXPORT_NAMES:
        imported_parts = [part for part in imported_name.split(".") if part]
        if imported_parts:
            candidates.append("/".join(module_parts + imported_parts) + ".py")
            candidates.append("/".join(module_parts + imported_parts + ["urls"]) + ".py")
    candidates.append(module_path + ".py")
    candidates.append(module_path + "/urls.py")
    candidates.append(module_path + "/__init__.py")

    if existing_paths:
        for candidate in candidates:
            normalized = candidate.replace("\\", "/").lstrip("./")
            resolved = _match_existing_python_path(normalized, existing_paths)
            if resolved:
                return resolved

    return candidates[0] if candidates else None


def _match_existing_python_path(candidate: str, existing_paths: set[str]) -> str | None:
    normalized = candidate.replace("\\", "/").lstrip("./")
    if normalized in existing_paths:
        return normalized
    suffix = "/" + normalized
    matches = sorted(path for path in existing_paths if path.endswith(suffix))
    return matches[0] if matches else None


def _extract_gin_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    routes = []
    group_paths = {
        "engine": "",
        "gin": prefix_override,
        "router": prefix_override,
        "r": prefix_override,
        "v1": prefix_override,
    }

    assignment_pattern = re.compile(
        r'(\w+)\s*:?=\s*(\w+)\.Group\(\s*["`]([^"`]+)["`]\s*\)',
        re.I,
    )
    method_pattern = re.compile(
        r'(\w+)\.(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|Any|ANY)\(\s*["`]([^"`]+)["`]\s*,\s*([A-Za-z_][\w\.]*)',
        re.I,
    )

    changed = True
    while changed:
        changed = False
        for match in assignment_pattern.finditer(content):
            var_name, parent_name, segment = match.groups()
            parent_path = group_paths.get(parent_name)
            if parent_path is None:
                continue
            full_path = _join_route_paths(parent_path, segment)
            if group_paths.get(var_name) != full_path:
                group_paths[var_name] = full_path
                changed = True

    for match in method_pattern.finditer(content):
        group_name, method, segment, handler = match.groups()
        base_path = group_paths.get(group_name)
        if base_path is None:
            continue
        routes.append(
            {
                "method": method.upper(),
                "path": _join_route_paths(base_path, segment),
                "handler": _normalize_handler_name(handler),
                "file_path": file_path,
                "auth": _guess_auth_type(content),
                "params": _merge_params(
                    _extract_route_params(segment),
                    _extract_handler_params(content, _normalize_handler_name(handler)),
                ),
                "notes": "Static route extraction (Gin)",
            }
        )

    return routes


def _build_gin_api_prefixes(project_dir: str, files: list[dict]) -> dict[str, str]:
    prefixes: dict[str, str] = {}
    api_receivers: dict[str, str] = {}
    file_contents: dict[str, str] = {}

    for file_node in files:
        rel_path = file_node["path"]
        full_path = os.path.join(project_dir, rel_path)
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception:
            continue
        file_contents[rel_path] = content

        receiver_match = re.search(
            r"func\s+\((\w+)\s+(\w+)\)\s+API\s*\(\s*\w+\s+\*gin\.RouterGroup\s*\)",
            content,
        )
        if receiver_match:
            recv_var, recv_type = receiver_match.groups()
            api_receivers[_normalize_controller_name(recv_var)] = rel_path
            api_receivers[_normalize_controller_name(recv_type)] = rel_path

    for rel_path, content in file_contents.items():
        group_paths = _extract_gin_group_paths(content)
        for controller_name, group_var in re.findall(r"api\.(\w+)\.API\((\w+)\)", content):
            target_path = api_receivers.get(_normalize_controller_name(controller_name))
            if not target_path:
                continue
            prefix = group_paths.get(group_var, "")
            if prefix:
                prefixes[target_path] = prefix

    return prefixes


def _extract_gin_group_paths(content: str) -> dict[str, str]:
    group_paths = {"engine": "", "gin": "", "router": "", "r": "", "v1": ""}
    assignment_pattern = re.compile(
        r'(\w+)\s*:?=\s*(\w+)\.Group\(\s*["`]([^"`]+)["`]\s*\)',
        re.I,
    )

    changed = True
    while changed:
        changed = False
        for match in assignment_pattern.finditer(content):
            var_name, parent_name, segment = match.groups()
            parent_path = group_paths.get(parent_name)
            if parent_path is None:
                continue
            full_path = _join_route_paths(parent_path, segment)
            if group_paths.get(var_name) != full_path:
                group_paths[var_name] = full_path
                changed = True

    return group_paths


def _normalize_controller_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", name.lower())


def _normalize_handler_name(handler: str) -> str:
    return handler.replace("api.", "").strip()


def _extract_handler_params(content: str, handler: str) -> list[str]:
    method_name = handler.split(".")[-1].strip()
    if not method_name or method_name == "Unknown":
        return []

    patterns = [
        re.compile(
            rf"func\s+\(\s*\w+\s+\w+\s*\)\s+{re.escape(method_name)}\s*\([^)]*\)\s*\{{",
            re.M,
        ),
        re.compile(
            rf"func\s+{re.escape(method_name)}\s*\([^)]*\)\s*\{{",
            re.M,
        ),
    ]

    start = -1
    for pattern in patterns:
        match = pattern.search(content)
        if match:
            start = match.end() - 1
            break

    if start == -1:
        return []

    body = _extract_go_block(content, start)
    if not body:
        return []

    params = []
    query_patterns = [
        re.compile(r'\.\s*(?:Query|DefaultQuery|GetQuery)\(\s*"([^"]+)"'),
        re.compile(r'\.\s*(?:PostForm|GetPostForm|DefaultPostForm)\(\s*"([^"]+)"'),
        re.compile(r'\.\s*Param\(\s*"([^"]+)"'),
        re.compile(r'\.\s*Header\(\s*"([^"]+)"'),
    ]
    for pattern in query_patterns:
        for name in pattern.findall(body):
            params.append(name)

    bind_patterns = [
        (re.compile(r'BindJson\(\s*\w+\s*,\s*&\w+\.(\w+)\s*\{?\s*\}\s*\)'), "body"),
        (re.compile(r'BindQuery\(\s*\w+\s*,\s*&\w+\.(\w+)\s*\{?\s*\}\s*\)'), "query"),
        (re.compile(r'ShouldBindJSON\(\s*&\w+\.(\w+)\s*\{?\s*\}\s*\)'), "body"),
        (re.compile(r'ShouldBindQuery\(\s*&\w+\.(\w+)\s*\{?\s*\}\s*\)'), "query"),
    ]
    for pattern, source in bind_patterns:
        for type_name in pattern.findall(body):
            params.append(f"{source}:*{type_name}")

    return _dedupe_preserve_order(params)


def _extract_python_handler_params(content: str, handler: str) -> list[str]:
    handler_name = str(handler or "").split(".")[-1].strip()
    if not handler_name or handler_name == "Unknown":
        return []

    patterns = [
        re.compile(rf"def\s+{re.escape(handler_name)}\s*\([^)]*\)\s*:", re.M),
        re.compile(rf"async\s+def\s+{re.escape(handler_name)}\s*\([^)]*\)\s*:", re.M),
    ]
    match = None
    for pattern in patterns:
        match = pattern.search(content)
        if match:
            break
    if not match:
        return []

    body = _extract_python_block(content, match.end())
    if not body:
        return []

    params: list[str] = []
    token_patterns = [
        re.compile(r'request\.(?:GET|get|query_params|args)\.get\(\s*["\']([^"\']+)["\']', re.I),
        re.compile(r'request\.(?:POST|post|form|data|json|headers|cookies)\.get\(\s*["\']([^"\']+)["\']', re.I),
        re.compile(r'req\.(?:query|params|body|headers|cookies)\.get\(\s*["\']([^"\']+)["\']', re.I),
        re.compile(r'request\.(?:GET|POST|args|form|files|headers|cookies)\s*\[\s*["\']([^"\']+)["\']\s*\]', re.I),
        re.compile(r'req\.(?:query|params|body|headers|cookies)\s*\[\s*["\']([^"\']+)["\']\s*\]', re.I),
    ]
    for pattern in token_patterns:
        params.extend(pattern.findall(body))

    return _dedupe_preserve_order(params)


def _extract_go_block(content: str, brace_start: int) -> str:
    if brace_start < 0 or brace_start >= len(content) or content[brace_start] != "{":
        return ""

    depth = 0
    for index in range(brace_start, len(content)):
        char = content[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return content[brace_start + 1:index]
    return ""


def _extract_python_block(content: str, body_start: int) -> str:
    if body_start < 0 or body_start >= len(content):
        return ""
    lines = content[body_start:].splitlines()
    collected: list[str] = []
    base_indent = None
    for line in lines:
        if not line.strip():
            if collected:
                collected.append(line)
            continue
        indent = len(line) - len(line.lstrip(" \t"))
        if base_indent is None:
            base_indent = indent
        if indent < base_indent and collected:
            break
        collected.append(line)
    return "\n".join(collected)


def _merge_params(*param_groups: list[str]) -> list[str]:
    merged = []
    for group in param_groups:
        merged.extend(group or [])
    return _dedupe_preserve_order(merged)


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    result = []
    seen = set()
    for item in items:
        normalized = str(item).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return result


def _guess_handler_nearby(content: str, start_idx: int) -> str:
    window = content[start_idx : start_idx + 400]
    func_match = re.search(r"def\s+([A-Za-z_]\w*)\s*\(", window)
    if func_match:
        return func_match.group(1)
    js_match = re.search(r"(?:async\s+)?function\s+([A-Za-z_]\w*)\s*\(", window)
    if js_match:
        return js_match.group(1)
    arrow_match = re.search(r"([A-Za-z_]\w*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>", window)
    if arrow_match:
        return arrow_match.group(1)
    return "Unknown"


def _guess_auth_type(content: str) -> str:
    lowered = content.lower()
    if re.search(r"\bjwt\b|\bbearer\b", lowered):
        return "JWT"
    if re.search(r"\boauth\b", lowered):
        return "OAuth"
    if re.search(r"\bcookie\b|\bsessionmiddleware\b|\brequest\.session\b|\bset_cookie\b", lowered):
        return "Session"
    if re.search(r"\bauth\b|\blogin_required\b|\bauthorize\b", lowered):
        return "Unknown"
    return "None"


def _extract_route_params(path: str) -> list[str]:
    params = re.findall(r"{([^}]+)}|<([^>]+)>|:([A-Za-z_]\w*)", path)
    cleaned = []
    for group in params:
        for item in group:
            if item:
                cleaned.append(item)
    return cleaned


def _line_number_from_offset(content: str, offset: int) -> int:
    if offset <= 0:
        return 1
    return content.count("\n", 0, min(offset, len(content))) + 1


def _is_comment_or_docstring_match(content: str, offset: int) -> bool:
    line_start = content.rfind("\n", 0, offset) + 1
    line_end = content.find("\n", offset)
    if line_end == -1:
        line_end = len(content)
    line = content[line_start:line_end].strip()
    if line.startswith("#"):
        return True
    prefix = content[:offset]
    if prefix.count('"""') % 2 == 1:
        return True
    if prefix.count("'''") % 2 == 1:
        return True
    return False


def _normalize_route_path(path: str) -> str:
    path = re.sub(r"\s+", "", path.strip())
    if not path:
        return "/"
    if not path.startswith("/"):
        path = "/" + path
    path = re.sub(r"/{2,}", "/", path)
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return path


def _join_route_paths(base: str, segment: str) -> str:
    base = base.strip()
    segment = segment.strip()
    if not segment:
        return _normalize_route_path(base or "/")
    if not base:
        return _normalize_route_path(segment)
    return _normalize_route_path(base.rstrip("/") + "/" + segment.lstrip("/"))


def _split_file(file_path: str, content: str, max_size: int) -> list[dict]:
    """Split a large file into smaller chunks by line boundaries."""
    lines = content.split("\n")
    chunks = []
    current_lines = []
    current_size = 0
    start_line = 1

    for i, line in enumerate(lines, 1):
        line_size = len(line) + 1
        if current_size + line_size > max_size and current_lines:
            chunks.append(
                _build_chunk(
                    f"{file_path}#L{start_line}-{i - 1}",
                    "\n".join(current_lines),
                    base_file_path=file_path,
                    chunk_type="split",
                )
            )
            current_lines = []
            current_size = 0
            start_line = i

        current_lines.append(line)
        current_size += line_size

    if current_lines:
        chunks.append(
            _build_chunk(
                f"{file_path}#L{start_line}-{len(lines)}",
                "\n".join(current_lines),
                base_file_path=file_path,
                chunk_type="split",
            )
        )

    return chunks


def _build_chunk(file_path: str, content: str, base_file_path: str | None = None, chunk_type: str = "full") -> dict:
    content = content or ""
    metadata = _compute_chunk_risk(str(base_file_path or file_path), content)
    return {
        "file_path": file_path,
        "base_file_path": str(base_file_path or file_path),
        "chunk_type": chunk_type,
        "content": content,
        **metadata,
    }


_COMMENT_STRIP_PATTERNS = [
    (re.compile(r'/\*.*?\*/', re.DOTALL), ' '),
    (re.compile(r'//[^\n]*'), ' '),
    (re.compile(r'#[^\n]*'), ' '),
    (re.compile(r'""".*?"""', re.DOTALL), '""'),
    (re.compile(r"'''.*?'''", re.DOTALL), "''"),
]


def _strip_comments_and_strings(content: str) -> str:
    for pattern, replacement in _COMMENT_STRIP_PATTERNS:
        content = pattern.sub(replacement, content)
    return content


def _compute_chunk_risk(file_path: str, content: str) -> dict:
    stripped = _strip_comments_and_strings(content[:12000])
    haystack = f"{file_path.lower()}\n{stripped.lower()}"
    matched_labels: list[str] = []
    risk_score = 0

    for label, keywords in RISK_KEYWORDS.items():
        hits = sum(1 for keyword in keywords if keyword in haystack)
        if hits:
            matched_labels.append(label)
            risk_score += min(hits, 4) * 3

    high_signal_paths = [
        "/router", "/routers/", "/routes/", "/api/", "/controller", "/controllers/",
        "/middleware", "/auth", "/security", "/admin/", "urls.py", "views.py",
        "config", "settings", ".env", "requirements", "package.json",
    ]
    path_hits = sum(1 for keyword in high_signal_paths if keyword in file_path.lower())
    risk_score += path_hits * 2

    if any(file_path.lower().endswith(ext) for ext in [".php", ".py", ".java", ".go", ".rb", ".cs", ".js", ".ts", ".vue"]):
        risk_score += 1

    return {
        "risk_score": risk_score,
        "risk_labels": matched_labels,
    }


def _build_oversized_file_chunks(file_path: str, content: str) -> list[dict]:
    chunks: list[dict] = []
    lines = content.splitlines()
    if not lines:
        return chunks

    head = "\n".join(lines[: min(len(lines), 45)]).strip()
    if head:
        chunks.append(
            _build_chunk(
                f"{file_path}#head",
                _truncate_by_chars(head, OVERSIZED_HEAD_CHARS),
                base_file_path=file_path,
                chunk_type="oversized_head",
            )
        )

    windows = _extract_oversized_signal_windows(lines)
    for index, (start, end) in enumerate(windows, 1):
        window_text = "\n".join(lines[start:end]).strip()
        if not window_text:
            continue
        chunks.append(
            _build_chunk(
                f"{file_path}#signal{index}:L{start + 1}-{end}",
                window_text,
                base_file_path=file_path,
                chunk_type="oversized_signal",
            )
        )

    tail = "\n".join(lines[max(0, len(lines) - 35):]).strip()
    if tail:
        chunks.append(
            _build_chunk(
                f"{file_path}#tail",
                _truncate_tail_by_chars(tail, OVERSIZED_TAIL_CHARS),
                base_file_path=file_path,
                chunk_type="oversized_tail",
            )
        )

    if not chunks:
        chunks.append(
            _build_chunk(
                f"{file_path}#excerpt",
                _truncate_by_chars(content, max(OVERSIZED_HEAD_CHARS, OVERSIZED_TAIL_CHARS)),
                base_file_path=file_path,
                chunk_type="oversized_excerpt",
            )
        )

    deduped: list[dict] = []
    seen = set()
    for chunk in chunks:
        key = (chunk.get("file_path"), chunk.get("content"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(chunk)
    return deduped


def _extract_oversized_signal_windows(lines: list[str]) -> list[tuple[int, int]]:
    windows: list[tuple[int, int]] = []
    flattened_keywords = [keyword for keywords in RISK_KEYWORDS.values() for keyword in keywords]

    for index, line in enumerate(lines):
        lowered = line.lower()
        if any(keyword in lowered for keyword in flattened_keywords):
            windows.append(
                (
                    max(0, index - OVERSIZED_WINDOW_RADIUS),
                    min(len(lines), index + OVERSIZED_WINDOW_RADIUS + 1),
                )
            )

    merged: list[list[int]] = []
    for start, end in windows:
        if not merged or start > merged[-1][1] + 3:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)

    return [(start, end) for start, end in merged[:OVERSIZED_MAX_WINDOWS]]


def _truncate_by_chars(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 32)] + "\n... (truncated)\n"


def _truncate_tail_by_chars(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return "\n... (truncated)\n" + text[-max(0, limit - 32):]


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

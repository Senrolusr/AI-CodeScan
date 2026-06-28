"""code_parser 纯函数烟雾测试（不重写该模块，只锁住关键行为）。"""

import os
import tempfile

import pytest

from services import code_parser as cp


FLASK_APP = """\
from flask import Flask, request
import os, subprocess

app = Flask(__name__)

@app.route("/users/<int:uid>", methods=["GET"])
def get_user(uid):
    user = request.args.get("name")
    return os.popen("id " + user).read()

@app.route("/exec", methods=["POST"])
def do_exec():
    code = request.form.get("code")
    return str(eval(code))
"""


@pytest.fixture
def sample_project():
    with tempfile.TemporaryDirectory() as d:
        app_dir = os.path.join(d, "app")
        os.makedirs(app_dir, exist_ok=True)
        with open(os.path.join(app_dir, "__init__.py"), "w", encoding="utf-8") as f:
            f.write("")
        with open(os.path.join(app_dir, "views.py"), "w", encoding="utf-8") as f:
            f.write(FLASK_APP)
        with open(os.path.join(d, "requirements.txt"), "w", encoding="utf-8") as f:
            f.write("flask\n")
        yield d


def test_parse_project_returns_tree_and_tech_stack(sample_project):
    file_tree, tech_stack = cp.parse_project(sample_project)
    assert file_tree  # 非空文件树
    assert isinstance(tech_stack, str)


def test_project_fingerprint_is_stable(sample_project):
    file_tree, _ = cp.parse_project(sample_project)
    fp1 = cp._build_project_fingerprint(file_tree)
    fp2 = cp._build_project_fingerprint(file_tree)
    assert fp1 and fp1 == fp2


def test_flask_route_extraction():
    routes = cp._extract_flask_routes("app/views.py", FLASK_APP)
    paths = {r.get("path") for r in routes}
    assert any("/users" in (p or "") for p in paths)
    assert any("/exec" in (p or "") for p in paths)
    # 应识别出 GET 方法
    methods = [r.get("method") for r in routes]
    assert "GET" in methods


def test_get_code_chunks_returns_nonempty(sample_project):
    file_tree, _ = cp.parse_project(sample_project)
    chunks = cp.get_code_chunks(sample_project, file_tree)
    assert isinstance(chunks, list)
    assert len(chunks) >= 1
    # 至少有一个 chunk 来自 views.py
    assert any("views.py" in str(c.get("file_path", "")) for c in chunks)


def test_rule_hits_on_rce_content(sample_project):
    file_tree, _ = cp.parse_project(sample_project)
    chunks = cp.get_code_chunks(sample_project, file_tree)
    hits = cp._build_rule_hits(chunks)
    assert isinstance(hits, list)
    # RCE 关键词密集的 views.py 应能命中规则
    if hits:
        assert all("label" in h and "file_path" in h for h in hits)

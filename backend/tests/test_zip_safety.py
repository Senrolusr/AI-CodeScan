"""ZIP 解压安全测试：防 ZIP Slip / 文件数 / 单文件大小 / 总大小 / 压缩比 / 噪声跳过。"""

import os
import tempfile
import zipfile

import pytest
from fastapi import HTTPException

import routers.projects as projects


def _write_zip(zip_path: str, members: dict[str, bytes], *, compress=zipfile.ZIP_DEFLATED) -> None:
    with zipfile.ZipFile(zip_path, "w", compression=compress) as zf:
        for name, data in members.items():
            zf.writestr(name, data)


def _extract(tmpdir: str, members: dict[str, bytes], **limit_overrides):
    zip_path = os.path.join(tmpdir, "source.zip")
    target = os.path.join(tmpdir, "out")
    os.makedirs(target, exist_ok=True)
    _write_zip(zip_path, members)
    for key, value in limit_overrides.items():
        setattr(projects, key, value)
    try:
        projects._safe_extract_zip(zip_path, target)
    finally:
        for key in limit_overrides:
            # 还原为模块默认（从 settings 重算）
            from services import config

            setattr(projects, key, getattr(config, key))
    return target


def test_normal_zip_extracts_ok():
    with tempfile.TemporaryDirectory() as tmp:
        target = _extract(
            tmp,
            {"app/main.py": b"print('hi')\n", "README.md": b"hello"},
        )
        assert os.path.isfile(os.path.join(target, "app", "main.py"))
        assert os.path.isfile(os.path.join(target, "README.md"))


def test_zip_slip_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        with pytest.raises(HTTPException) as exc:
            _extract(tmp, {"../evil.txt": b"pwned"})
        assert exc.value.status_code == 400


def test_file_count_cap_rejected():
    members = {f"file_{i}.py": b"x" for i in range(6)}
    with tempfile.TemporaryDirectory() as tmp:
        with pytest.raises(HTTPException) as exc:
            _extract(tmp, members, MAX_EXTRACTED_FILE_COUNT=5)
        assert exc.value.status_code == 400


def test_per_member_size_cap_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        with pytest.raises(HTTPException) as exc:
            _extract(
                tmp,
                {"big.bin": b"A" * 500},
                MAX_MEMBER_FILE_BYTES=50,
            )
        assert exc.value.status_code == 400


def test_total_extracted_size_cap_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        with pytest.raises(HTTPException) as exc:
            _extract(
                tmp,
                {"a.bin": b"A" * 400, "b.bin": b"B" * 400},
                MAX_EXTRACTED_BYTES=500,
            )
        assert exc.value.status_code == 400


def test_compression_ratio_cap_rejected():
    # 高度可压缩内容 → 解压比远超阈值 → 判定为 zip bomb
    payload = b"A" * 20000
    with tempfile.TemporaryDirectory() as tmp:
        with pytest.raises(HTTPException) as exc:
            _extract(
                tmp,
                {"bomb.txt": payload},
                MAX_COMPRESSION_RATIO=5,
            )
        assert exc.value.status_code == 400


def test_noise_members_skipped():
    with tempfile.TemporaryDirectory() as tmp:
        target = _extract(
            tmp,
            {
                "__MACOSX/._app.py": b"junk",
                ".DS_Store": b"junk",
                "app/main.py": b"print('ok')\n",
            },
        )
        assert os.path.isfile(os.path.join(target, "app", "main.py"))
        assert not os.path.exists(os.path.join(target, "__MACOSX"))
        assert not os.path.exists(os.path.join(target, ".DS_Store"))

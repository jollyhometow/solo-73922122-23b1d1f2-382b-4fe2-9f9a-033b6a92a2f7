"""pytest 公共夹具与测试辅助。"""

from __future__ import annotations

import hashlib
import io
import json
import stat
import zipfile
from pathlib import Path

import pytest

from app import main as main_module
from app.config import Settings


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    """每个测试独立的数据目录，并重置 main 的惰性缓存。"""
    home = tmp_path / "evidence-home"
    s = Settings(
        home=home,
        db_path=home / "evidence.db",
        files_dir=home / "files",
        staging_dir=home / "staging",
        tmp_dir=home / "tmp",
    )
    main_module._settings = s
    main_module._samples = None
    yield s
    main_module._settings = None
    main_module._samples = None


@pytest.fixture()
def client(settings):
    from fastapi.testclient import TestClient

    with TestClient(main_module.app) as c:
        yield c


def make_zip(entries: list[tuple[str, bytes]], *, symlinks=None) -> bytes:
    """在内存中构造 ZIP。symlinks: {条目名: 链接目标}。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            zf.writestr(name, data)
        for name, target in (symlinks or {}).items():
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, target)
    return buf.getvalue()


def make_manifest(entries: list[tuple[str, bytes]], *, overrides=None) -> bytes:
    """根据 (path, data) 生成正确清单；overrides 可替换某路径的 sha256。"""
    overrides = overrides or {}
    doc = {
        "files": [
            {
                "path": path,
                "sha256": overrides.get(path, hashlib.sha256(data).hexdigest()),
            }
            for path, data in entries
        ]
    }
    return json.dumps(doc).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

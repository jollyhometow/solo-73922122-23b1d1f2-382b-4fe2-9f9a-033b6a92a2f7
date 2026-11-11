"""演示用样例（由服务端可信代码在内存中生成）。

提供三个取证包，首页可直接下载：

1. ``benign``   —— 正常包：ZIP 与清单完全一致，可成功发布；
2. ``malicious``—— 恶意包：ZIP 内同时含软链接条目与 ``..`` 路径穿越条目，
   解压阶段即被拒绝，不会写入任何文件；
3. ``tampered`` —— 篡改包：ZIP 结构合法，但清单 SHA-256 与实际内容不符，
   哈希核验阶段被拒绝。
"""

from __future__ import annotations

import hashlib
import io
import json
import stat
import zipfile
from dataclasses import dataclass


@dataclass(frozen=True)
class Sample:
    sample_id: str
    title: str
    description: str
    zip_name: str
    manifest_name: str
    zip_bytes: bytes
    manifest_bytes: bytes


def _manifest_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    doc = {
        "files": [
            {"path": path, "sha256": hashlib.sha256(data).hexdigest()}
            for path, data in entries
        ]
    }
    return json.dumps(doc, ensure_ascii=False, indent=2).encode("utf-8")


def _zip_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


def _build_benign() -> Sample:
    entries = [
        (
            "case-notes/README.md",
            b"# Case notes\n\nThis bundle is well-formed and should publish.\n",
        ),
        ("evidence/alpha.txt", b"alpha evidence payload\n" * 4),
        ("logs/run.log", b"2026-11-11T08:00:00Z boot ok\n2026-11-11T08:05:00Z done\n"),
    ]
    return Sample(
        sample_id="benign",
        title="正常样例（应发布成功）",
        description="普通文件、ASCII 相对路径，清单 SHA-256 与实际内容完全一致。",
        zip_name="benign-bundle.zip",
        manifest_name="benign-manifest.json",
        zip_bytes=_zip_bytes(entries),
        manifest_bytes=_manifest_bytes(entries),
    )


def _build_malicious() -> Sample:
    """软链接 + 路径穿越，另带一个正常条目做掩护。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # 1) 软链接条目：Unix S_IFLNK，内容是链接目标。
        link_info = zipfile.ZipInfo("evil-link")
        link_info.create_system = 3  # Unix
        link_info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(link_info, "/etc/passwd")

        # 2) 路径穿越条目：企图写到版本目录之外。
        zf.writestr("../pwned.txt", b"escaped via parent directory\n")

        # 3) 掩护用正常文件。
        zf.writestr("notes/ok.txt", b"a regular file used as cover\n")

    # 清单只描述掩护文件（即便如此，ZIP 结构校验也会先失败）。
    manifest = {
        "files": [
            {
                "path": "notes/ok.txt",
                "sha256": hashlib.sha256(b"a regular file used as cover\n").hexdigest(),
            }
        ]
    }
    return Sample(
        sample_id="malicious",
        title="恶意样例（软链接 + 路径穿越，必须被拒绝）",
        description=(
            "ZIP 内含 Unix 软链接 evil-link（指向 /etc/passwd）与 "
            "../pwned.txt 路径穿越条目；接收流程在解压阶段拒绝，"
            "暂存区不会留下任何文件，当前版本不变。"
        ),
        zip_name="malicious-bundle.zip",
        manifest_name="malicious-manifest.json",
        zip_bytes=buf.getvalue(),
        manifest_bytes=json.dumps(manifest, indent=2).encode("utf-8"),
    )


def _build_tampered() -> Sample:
    real = b"original disk image checksum payload\n"
    entries = [("images/disk.img", real)]
    zip_bytes = _zip_bytes(entries)

    # 清单故意写成另一个哈希，模拟传输/制作环节被篡改。
    fake_hash = hashlib.sha256(b"attacker-controlled content").hexdigest()
    manifest = {"files": [{"path": "images/disk.img", "sha256": fake_hash}]}
    return Sample(
        sample_id="tampered",
        title="篡改样例（清单哈希与实际内容不符）",
        description=(
            "ZIP 结构与路径全部合法，但清单声明的 SHA-256 与分块解压后"
            "计算出的实际哈希不一致，发布被拒绝。"
        ),
        zip_name="tampered-bundle.zip",
        manifest_name="tampered-manifest.json",
        zip_bytes=zip_bytes,
        manifest_bytes=json.dumps(manifest, indent=2).encode("utf-8"),
    )


def build_samples() -> dict[str, Sample]:
    samples = (_build_benign(), _build_malicious(), _build_tampered())
    return {s.sample_id: s for s in samples}

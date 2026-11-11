"""独立 JSON 清单解析。

清单格式（UTF-8、JSON）::

    {
      "files": [
        {"path": "report/notes.txt", "sha256": "<64位小写十六进制>"},
        ...
      ]
    }

清单与 ZIP 互不信任：路径要过与 ZIP 完全相同的相对路径规则，
哈希必须是 64 位十六进制；清单自身也不允许重复路径或文件/目录冲突。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from .errors import EvidenceError
from .security import detect_conflicts, validate_relative_path

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ManifestEntry:
    path: str
    sha256: str  # 统一转小写后存储


def parse_manifest(raw: bytes, *, max_entries: int) -> list[ManifestEntry]:
    """解析并校验清单字节串。"""
    if not raw:
        raise EvidenceError("清单内容为空")

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceError(f"清单不是合法 UTF-8: {exc}") from exc

    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"清单不是合法 JSON: {exc.msg} (第{exc.lineno}行)") from exc

    if not isinstance(doc, dict) or "files" not in doc:
        raise EvidenceError("清单顶层必须是含 files 字段的对象")

    files = doc["files"]
    if not isinstance(files, list):
        raise EvidenceError("清单 files 字段必须是数组")
    if not files:
        raise EvidenceError("清单为空，至少需要一个文件")
    if len(files) > max_entries:
        raise EvidenceError(f"清单条目数 {len(files)} 超过上限 {max_entries}")

    entries: list[ManifestEntry] = []
    for index, item in enumerate(files):
        if not isinstance(item, dict):
            raise EvidenceError(f"清单第 {index + 1} 项不是对象")

        path = item.get("path")
        sha256 = item.get("sha256")
        if not isinstance(path, str) or not isinstance(sha256, str):
            raise EvidenceError(f"清单第 {index + 1} 项缺少 path 或 sha256 字符串字段")

        normalized = validate_relative_path(path)
        digest = sha256.strip().lower()
        if not _SHA256_RE.match(digest):
            raise EvidenceError(
                f"清单中 {path!r} 的 sha256 必须是 64 位十六进制字符串"
            )
        entries.append(ManifestEntry(path=normalized, sha256=digest))

    # 清单自身的重复/冲突检查（与 ZIP 同规则）。
    detect_conflicts([e.path for e in entries])
    return entries

"""清单解析测试。"""

from __future__ import annotations

import json

import pytest

from app.errors import EvidenceError
from app.manifest import parse_manifest


def parse(doc):
    return parse_manifest(json.dumps(doc).encode("utf-8"), max_entries=100)


def test_manifest_valid():
    entries = parse({"files": [{"path": "a/b.txt", "sha256": "a" * 64}]})
    assert entries[0].path == "a/b.txt"
    assert entries[0].sha256 == "a" * 64


def test_manifest_uppercase_hash_normalized():
    entries = parse({"files": [{"path": "a", "sha256": "A" * 64}]})
    assert entries[0].sha256 == "a" * 64


@pytest.mark.parametrize(
    "doc",
    [
        {},
        {"files": "nope"},
        {"files": []},
        {"files": [{"path": "a"}]},
        {"files": [{"path": "a", "sha256": "short"}]},
        {"files": [{"path": "a", "sha256": "z" * 64}]},  # 非十六进制
        {"files": [{"path": 1, "sha256": "a" * 64}]},
        {"files": [{"path": "/abs", "sha256": "a" * 64}]},
        {"files": [{"path": "a\\b", "sha256": "a" * 64}]},
        {"files": [{"path": "../x", "sha256": "a" * 64}]},
        {"files": [{"path": "中文", "sha256": "a" * 64}]},
        # 重复路径
        {"files": [
            {"path": "a", "sha256": "a" * 64},
            {"path": "a", "sha256": "b" * 64},
        ]},
        # 文件/目录冲突
        {"files": [
            {"path": "a", "sha256": "a" * 64},
            {"path": "a/b", "sha256": "b" * 64},
        ]},
    ],
)
def test_manifest_rejects_invalid(doc):
    with pytest.raises(EvidenceError):
        parse(doc)


def test_manifest_bad_json_bytes():
    with pytest.raises(EvidenceError, match="JSON"):
        parse_manifest(b"{not json", max_entries=100)


def test_manifest_non_utf8():
    with pytest.raises(EvidenceError, match="UTF-8"):
        parse_manifest(b"\xff\xfe\x00\x01", max_entries=100)


def test_manifest_empty():
    with pytest.raises(EvidenceError):
        parse_manifest(b"", max_entries=100)

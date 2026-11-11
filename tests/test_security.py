"""路径校验与安全解压的单元测试。"""

from __future__ import annotations

import stat
import zipfile
from pathlib import Path

import pytest

from app.config import MAX_TOTAL_BYTES
from app.errors import EvidenceError
from app.security import safe_extract, validate_relative_path


def test_validate_relative_path_accepts_normal_ascii():
    assert validate_relative_path("a/b/c.txt") == "a/b/c.txt"
    assert validate_relative_path("file.txt") == "file.txt"
    assert validate_relative_path("x/y_1/z-2.bin") == "x/y_1/z-2.bin"


@pytest.mark.parametrize(
    "bad",
    [
        "/etc/passwd",        # 绝对路径
        "a\\b.txt",           # 反斜杠
        "a//b",               # 空分量
        "a/./b",              # . 分量
        "a/../b",             # .. 分量
        "../escape",          # 父目录穿越
        "a/b/",               # 末尾空分量
        ".",
        "..",
        "C:/windows/x",       # 盘符
        "a/\u4e2d\u6587.txt",  # 非 ASCII
        "",
    ],
)
def test_validate_relative_path_rejects_dangerous(bad):
    with pytest.raises(EvidenceError):
        validate_relative_path(bad)


def _extract(tmp_path: Path, raw_zip: bytes):
    z = tmp_path / "in.zip"
    z.write_bytes(raw_zip)
    dest = tmp_path / "out"
    dest.mkdir()
    return safe_extract(z, dest), dest


def test_safe_extract_basic(tmp_path):
    entries = [("a.txt", b"hello"), ("dir/b.bin", b"\x00\x01\x02")]
    from tests.conftest import make_zip

    results, dest = _extract(tmp_path, make_zip(entries))
    assert {f.rel_path for f in results} == {"a.txt", "dir/b.bin"}
    a = next(f for f in results if f.rel_path == "a.txt")
    assert a.size == 5
    assert a.sha256 == sha256(b"hello")
    assert (dest / "a.txt").read_bytes() == b"hello"
    assert (dest / "dir/b.bin").read_bytes() == b"\x00\x01\x02"


def sha256(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def test_safe_extract_rejects_symlink(tmp_path):
    from tests.conftest import make_zip

    raw = make_zip(
        [("ok.txt", b"ok")],
        symlinks={"evil": "/etc/passwd"},
    )
    with pytest.raises(EvidenceError, match="软链接"):
        _extract(tmp_path, raw)


def test_safe_extract_rejects_parent_traversal(tmp_path):
    from tests.conftest import make_zip

    raw = make_zip([("../pwned", b"x"), ("ok", b"y")])
    with pytest.raises(EvidenceError, match=r"\.\."):
        _extract(tmp_path, raw)


def test_safe_extract_rejects_absolute(tmp_path):
    from tests.conftest import make_zip

    raw = make_zip([("/tmp/x", b"x")])
    with pytest.raises(EvidenceError, match="绝对路径"):
        _extract(tmp_path, raw)


def test_safe_extract_rejects_backslash(tmp_path):
    from tests.conftest import make_zip

    # ZIP 中直接写入带反斜杠的条目名。
    raw = make_zip([("a\\b.txt", b"x")])
    with pytest.raises(EvidenceError, match="反斜杠"):
        _extract(tmp_path, raw)


def test_safe_extract_rejects_duplicate_paths(tmp_path):
    import io

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", b"1")
        zf.writestr("a.txt", b"2")
    with pytest.raises(EvidenceError, match="重复路径"):
        _extract(tmp_path, buf.getvalue())


def test_safe_extract_rejects_file_dir_conflict(tmp_path):
    from tests.conftest import make_zip

    # a 既是文件又是另一个条目的目录前缀。
    raw = make_zip([("a", b"x"), ("a/b", b"y")])
    with pytest.raises(EvidenceError, match="文件与目录冲突"):
        _extract(tmp_path, raw)


def test_safe_extract_rejects_directory_entry(tmp_path):
    import io

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        # 无尾斜杠、仅靠 Unix 外部属性标记为目录，验证目录识别不只依赖名称。
        info = zipfile.ZipInfo("dir")
        info.create_system = 3
        info.external_attr = (stat.S_IFDIR | 0o755) << 16
        zf.writestr(info, b"")
        zf.writestr("dir/f", b"x")
    with pytest.raises(EvidenceError, match="目录条目"):
        _extract(tmp_path, buf.getvalue())


def test_safe_extract_rejects_encrypted(tmp_path):
    import io

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", b"secret")
        info = zf.infolist()[0]
        info.flag_bits |= 0x1  # 标记加密位
    with pytest.raises(EvidenceError, match="加密"):
        _extract(tmp_path, buf.getvalue())


def test_safe_extract_enforces_actual_byte_limit(tmp_path):
    """声明大小不可信：实际累计字节超过 16 MiB 必须中止。"""
    from tests.conftest import make_zip

    big = b"a" * (MAX_TOTAL_BYTES + 1024)
    raw = make_zip([("big.bin", big)])
    with pytest.raises(EvidenceError, match="16 MiB|上限"):
        _extract(tmp_path, raw)

    # 拒绝后暂存目录里不应留下半截文件。
    dest = tmp_path / "out"
    assert not [p for p in dest.rglob("*") if p.is_file()]


def test_safe_extract_rejects_bad_zip(tmp_path):
    z = tmp_path / "in.zip"
    z.write_bytes(b"not a zip at all")
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(EvidenceError, match="合法的 ZIP"):
        safe_extract(z, dest)


def test_safe_extract_rejects_empty_zip(tmp_path):
    import io

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w"):
        pass
    with pytest.raises(EvidenceError, match="为空"):
        _extract(tmp_path, buf.getvalue())


def test_safe_extract_unix_non_regular_rejected(tmp_path):
    import io

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("fifo")
        info.create_system = 3
        info.external_attr = (stat.S_IFIFO | 0o644) << 16
        zf.writestr(info, b"")
    with pytest.raises(EvidenceError, match="非常规文件|软链接"):
        _extract(tmp_path, buf.getvalue())

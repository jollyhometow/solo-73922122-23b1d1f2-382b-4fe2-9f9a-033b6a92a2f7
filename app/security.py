"""ZIP 安全解压与路径校验。

威胁模型：取证包来自不可信外部人员，ZIP 与清单均为攻击面。
本模块保证：

1. 条目名仅含 ASCII，必须是相对路径；拒绝绝对路径、反斜杠、
   空分量、``.``、``..``、盘符、重复路径、文件/目录冲突。
2. ZIP 只接受普通文件条目：拒绝目录、软链接及其他非常规类型、
   加密条目。
3. 分块流式解压，按**实际读出字节**累计计数，超过 16 MiB 立即中止；
   ZIP 头里声明的大小一律不作为放行依据（防 zip-bomb / 声明大小欺骗）。
4. 解压同时计算 SHA-256，供与清单逐项核对。

调用方传入的 ``dest`` 必须是一个全新的空目录（暂存区），
解压使用 ``O_CREAT|O_EXCL`` 语义，不会覆盖任何既有文件。
"""

from __future__ import annotations

import hashlib
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .config import MAX_ENTRIES, MAX_TOTAL_BYTES, CHUNK_SIZE
from .errors import EvidenceError

# Unix st_mode 中的文件类型位掩码（Python 的 stat.S_IFMT 是函数，不是掩码）。
_S_IFMT_MASK = 0o170000


@dataclass(frozen=True)
class ExtractedFile:
    """一个已落盘文件的核验结果。"""

    rel_path: str       # 规范化后的相对路径（``/`` 分隔）
    disk_path: Path     # 暂存区中的绝对路径
    sha256: str         # 实际内容的 SHA-256（小写十六进制）
    size: int           # 实际字节数


def validate_relative_path(name: str) -> str:
    """校验一个相对路径字符串，返回规范化后的 POSIX 形式。

    拒绝条件（任一命中即拒绝整个包）：
      * 非 ASCII（含名称无法按 ASCII 编码的情况）；
      * 绝对路径（``/`` 开头）或 Windows 盘符/UNC 路径；
      * 含反斜杠 ``\\``；
      * 空分量（``a//b``、首尾斜杠）；
      * 分量为 ``.`` 或 ``..``。
    """
    if not isinstance(name, str) or not name:
        raise EvidenceError("路径为空或类型非法")
    try:
        name.encode("ascii")
    except UnicodeEncodeError as exc:
        raise EvidenceError(f"路径含非 ASCII 字符: {name!r}") from exc

    if "\\" in name:
        raise EvidenceError(f"路径不允许反斜杠: {name!r}")
    if name.startswith("/"):
        raise EvidenceError(f"拒绝绝对路径: {name!r}")
    # Windows 盘符（C:）与 UNC/传统设备名前缀（// 已被绝对路径规则覆盖）。
    drive = PurePosixPath(name).drive
    if drive or (len(name) >= 2 and name[1] == ":"):
        raise EvidenceError(f"拒绝带盘符的路径: {name!r}")

    parts = name.split("/")
    if any(part == "" for part in parts):
        raise EvidenceError(f"路径含空分量: {name!r}")
    for part in parts:
        if part in (".", ".."):
            raise EvidenceError(f"路径含 . 或 .. 分量: {name!r}")

    normalized = "/".join(parts)
    if normalized != name:
        # 理论上前面的规则已覆盖，这里做防御性兜底。
        raise EvidenceError(f"路径未通过规范化检查: {name!r}")
    return normalized


def detect_conflicts(names: list[str]) -> None:
    """检查重复路径与文件/目录冲突。

    * 重复：两个条目规范化后路径相同；
    * 冲突：存在 ``a`` 和 ``a/b``——普通文件不能同时充当目录，
      即使 ZIP 把其中一个标成目录条目也一样拒绝（目录条目本身也被拒绝）。
    """
    seen_files: set[str] = set()
    parent_dirs: set[str] = set()

    for name in names:
        if name in seen_files:
            raise EvidenceError(f"ZIP 中存在重复路径: {name!r}")
        if name in parent_dirs:
            raise EvidenceError(f"文件与目录冲突: {name!r}")
        seen_files.add(name)

        path = PurePosixPath(name)
        for parent in path.parents:
            parent_str = parent.as_posix()
            if parent_str == ".":
                continue
            if parent_str in seen_files:
                raise EvidenceError(f"文件与目录冲突: {name!r} 与 {parent_str!r}")
            parent_dirs.add(parent_str)


def _is_unix_symlink(info: zipfile.ZipInfo) -> bool:
    """识别 Unix 系统生成的软链接条目。"""
    # create_system 低字节为 3 表示 Unix；外部属性高 16 位是 Unix mode。
    if (info.create_system & 0xFF) == 3:
        return stat.S_ISLNK(info.external_attr >> 16)
    return False


def safe_extract(
    zip_path: Path,
    dest: Path,
    *,
    max_total_bytes: int = MAX_TOTAL_BYTES,
    max_entries: int = MAX_ENTRIES,
    chunk_size: int = CHUNK_SIZE,
) -> list[ExtractedFile]:
    """把 ZIP 安全解压到空目录 ``dest``，返回每个文件的实际哈希。

    整个过程分两遍：先做**零写入**的全量结构校验，再流式落盘，
    保证任何拒绝都不会在暂存区留下半包数据（已写入部分由调用方整体删除）。
    """
    if not dest.is_dir() or any(dest.iterdir()):
        raise EvidenceError("暂存目录必须为空目录")

    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as exc:
        raise EvidenceError(f"不是合法的 ZIP 文件: {exc}") from exc

    with zf:
        infos = zf.infolist()
        if not infos:
            raise EvidenceError("ZIP 为空，至少需要一个普通文件")
        if len(infos) > max_entries:
            raise EvidenceError(f"ZIP 条目数 {len(infos)} 超过上限 {max_entries}")

        # ---- 第一遍：结构校验（不写任何文件） ----
        normalized_names: list[str] = []
        for info in infos:
            name = validate_relative_path(info.filename)

            if info.flag_bits & 0x1:
                raise EvidenceError(f"拒绝加密条目: {name!r}")
            if info.is_dir():
                raise EvidenceError(f"ZIP 仅允许普通文件，拒绝目录条目: {name!r}")
            if _is_unix_symlink(info):
                raise EvidenceError(f"拒绝软链接条目: {name!r}")
            if (info.create_system & 0xFF) == 3:
                unix_mode = info.external_attr >> 16
                # 外部属性显式标成目录（即便名称没有尾斜杠，is_dir 漏检）。
                if stat.S_ISDIR(unix_mode):
                    raise EvidenceError(
                        f"ZIP 仅允许普通文件，拒绝目录条目: {name!r}"
                    )
                # 非常规文件（设备、FIFO、套接字等）。纯 Python writestr
                # 写出的普通条目只有权限位（如 0o600）、类型位为零，需先判空。
                if (unix_mode & _S_IFMT_MASK) != 0 and not stat.S_ISREG(unix_mode):
                    raise EvidenceError(f"拒绝非常规文件条目: {name!r}")

            normalized_names.append(name)

        detect_conflicts(normalized_names)

        # ---- 第二遍：分块流式解压 + 实际字节计数 + 实时哈希 ----
        results: list[ExtractedFile] = []
        total = 0

        try:
            for info, name in zip(infos, normalized_names):
                disk_path = dest / Path(name)
                disk_path.parent.mkdir(parents=True, exist_ok=True)

                hasher = hashlib.sha256()
                size = 0
                # "x" = O_CREAT|O_EXCL|O_WRONLY：路径已存在则失败，杜绝覆盖。
                with zf.open(info, "r") as src, open(disk_path, "xb") as out:
                    while True:
                        chunk = src.read(chunk_size)
                        if not chunk:
                            break
                        size += len(chunk)
                        total += len(chunk)
                        # 以实际读到的字节为准，info.file_size 声明值不参与判断。
                        if total > max_total_bytes:
                            raise EvidenceError(
                                f"解压内容累计超过 {max_total_bytes} 字节上限"
                                "（按实际字节统计，不信任声明大小）"
                            )
                        hasher.update(chunk)
                        out.write(chunk)

                # zipfile 在流关闭时已按 CRC-32 校验数据完整性；
                # 损坏或被截断的包会在读取/关闭时抛出 BadZipFile。
                results.append(
                    ExtractedFile(
                        rel_path=name,
                        disk_path=disk_path,
                        sha256=hasher.hexdigest(),
                        size=size,
                    )
                )
        except (EvidenceError, zipfile.BadZipFile, OSError) as exc:
            # 出错即清掉已落盘的半截文件，保证暂存区不残留半包数据。
            for written in dest.rglob("*"):
                if written.is_file():
                    written.unlink(missing_ok=True)
            if isinstance(exc, EvidenceError):
                raise
            raise EvidenceError(f"ZIP 数据损坏或被截断: {exc}") from exc

    return results

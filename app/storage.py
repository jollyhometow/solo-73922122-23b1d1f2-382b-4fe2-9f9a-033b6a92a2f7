"""SQLite 持久化与原子版本发布。

并发模型（两个 worker 进程共享同一个数据库文件）：

* 数据库开启 WAL，允许读写并发；写事务一律 ``BEGIN IMMEDIATE``
  立即取得保留锁，配合 ``busy_timeout`` 与应用层短重试。
* 提交采用**乐观版本号**：请求方携带“预期当前版本”，在写事务内
  重新读取当前版本比对。两个进程同时基于同一版本提交时，
  先拿锁的提交成功并把版本 +1，后拿锁的读到新版本 → 冲突失败，
  当前版本保持不变。

崩溃安全（不暴露半包）：

* 所有核验都在独立暂存目录进行，未通过则整目录删除；
* 通过后先把文件移入 ``files/<case>/v<n>/``，再提交数据库事务；
  提交失败会回收该目录；
* 进程在“移动后、提交前”被杀死会留下磁盘孤儿目录，但没有数据库
  记录，任何页面/API 都看不到它；服务启动时统一清理暂存区与
  临时上传区，孤儿版本目录也由启动清理回收。
"""

from __future__ import annotations

import re
import shutil
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .config import CASE_ID_PATTERN, Settings
from .errors import ConflictError, EvidenceError
from .manifest import ManifestEntry
from .security import ExtractedFile

_CASE_ID_RE = re.compile(f"^{CASE_ID_PATTERN}$")
_BUSY_RETRY_ATTEMPTS = 200
_BUSY_RETRY_SLEEP = 0.05

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    case_id         TEXT PRIMARY KEY,
    current_version INTEGER NOT NULL CHECK (current_version >= 0),
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS versions (
    case_id    TEXT NOT NULL,
    version    INTEGER NOT NULL CHECK (version >= 1),
    created_at TEXT NOT NULL,
    PRIMARY KEY (case_id, version)
);
CREATE TABLE IF NOT EXISTS files (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     TEXT NOT NULL,
    version     INTEGER NOT NULL,
    rel_path    TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    size        INTEGER NOT NULL CHECK (size >= 0),
    stored_name TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    UNIQUE (case_id, version, rel_path)
);
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _connect(settings: Settings) -> sqlite3.Connection:
    conn = sqlite3.connect(settings.db_path, timeout=5.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(settings: Settings) -> None:
    """创建目录与表结构，并启用 WAL（持久模式，多进程共享）。"""
    for directory in (settings.home, settings.files_dir, settings.staging_dir, settings.tmp_dir):
        directory.mkdir(parents=True, exist_ok=True)

    conn = _connect(settings)
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.executescript(_SCHEMA)
    finally:
        conn.close()


def cleanup_workspace(settings: Settings) -> None:
    """启动时回收所有暂存/临时目录与未提交的孤儿版本目录。

    已发布版本以数据库记录为准：磁盘上存在但库里没有的
    ``files/<case>/v<n>`` 目录均视为崩溃残留，直接删除。

    两个 worker 进程会几乎同时启动，这里用 ``flock`` 互斥锁保证
    清理逻辑在同一数据卷上只完整执行一次，避免并发清理互相干扰。
    """
    import fcntl

    init_db(settings)
    lock_path = settings.home / ".cleanup.lock"
    with open(lock_path, "w") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            _cleanup_locked(settings)
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _cleanup_locked(settings: Settings) -> None:
    # 两个 worker 可能并发启动并清理同一目录，文件消失属正常竞态，忽略即可。
    for scratch in (settings.staging_dir, settings.tmp_dir):
        for child in scratch.iterdir():
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
            else:
                try:
                    child.unlink()
                except FileNotFoundError:
                    pass

    conn = _connect(settings)
    try:
        published: set[str] = {
            f"{row['case_id']}/v{row['version']}"
            for row in conn.execute("SELECT case_id, version FROM versions")
        }
    finally:
        conn.close()

    if not settings.files_dir.exists():
        return
    for case_dir in settings.files_dir.iterdir():
        if not case_dir.is_dir():
            continue
        for version_dir in case_dir.iterdir():
            if not version_dir.is_dir():
                continue
            rel = f"{case_dir.name}/{version_dir.name}"
            if rel not in published:
                shutil.rmtree(version_dir, ignore_errors=True)
        # 一个版本都没发布成功的空案件目录。
        try:
            if not any(case_dir.iterdir()):
                case_dir.rmdir()
        except (FileNotFoundError, OSError):
            pass


def new_staging_dir(settings: Settings) -> Path:
    path = settings.staging_dir / uuid.uuid4().hex
    path.mkdir(parents=True)
    return path


def _validate_case_id(case_id: str) -> None:
    if not isinstance(case_id, str) or not _CASE_ID_RE.fullmatch(case_id):
        raise EvidenceError(
            "案件号必须为 1-64 位 ASCII 字母、数字、下划线或短横线"
        )


def _validate_expected_version(expected: object) -> int:
    if isinstance(expected, bool) or not isinstance(expected, int):
        raise EvidenceError("预期当前版本必须是整数")
    if expected < 0:
        raise EvidenceError("预期当前版本不能为负数（首次提交请填 0）")
    return expected


def publish(
    settings: Settings,
    case_id: str,
    expected_version: int,
    manifest_entries: list[ManifestEntry],
    extracted: list[ExtractedFile],
) -> int:
    """核验通过后发布新版本，返回新版本号。

    抛出 :class:`EvidenceError` / :class:`ConflictError` 时当前版本不变。
    """
    _validate_case_id(case_id)
    expected_version = _validate_expected_version(expected_version)

    # ---- 清单与实际文件一一对应：路径集合相等且哈希全部吻合 ----
    manifest_map = {e.path: e.sha256 for e in manifest_entries}
    extracted_map = {f.rel_path: f for f in extracted}

    manifest_paths = set(manifest_map)
    extracted_paths = set(extracted_map)
    if manifest_paths != extracted_paths:
        only_manifest = sorted(manifest_paths - extracted_paths)
        only_zip = sorted(extracted_paths - manifest_paths)
        details = []
        if only_manifest:
            details.append(f"清单有但 ZIP 缺少: {only_manifest}")
        if only_zip:
            details.append(f"ZIP 有但清单缺少: {only_zip}")
        raise EvidenceError("清单与 ZIP 文件不能一一对应；" + "；".join(details))

    for path, expected_hash in manifest_map.items():
        actual = extracted_map[path].sha256
        if actual != expected_hash:
            raise EvidenceError(
                f"文件 {path!r} 的实际 SHA-256 ({actual}) 与清单声明 "
                f"({expected_hash}) 不一致"
            )

    case_dir = settings.files_dir / case_id
    now = _utc_now()

    # ---- 跨进程写事务：BEGIN IMMEDIATE + 乐观版本号 ----
    last_error: sqlite3.OperationalError | None = None
    for _ in range(_BUSY_RETRY_ATTEMPTS):
        conn = _connect(settings)
        version_dir: Path | None = None
        try:
            conn.execute("BEGIN IMMEDIATE")

            row = conn.execute(
                "SELECT current_version FROM cases WHERE case_id = ?",
                (case_id,),
            ).fetchone()
            current = row["current_version"] if row else 0

            if current != expected_version:
                raise ConflictError(
                    f"版本冲突：预期当前版本为 {expected_version}，"
                    f"实际当前版本为 {current}，请刷新后基于最新版本重新提交"
                )

            new_version = current + 1
            # 目录创建放在写锁内：并发首提时只有拿到锁的进程会建目录。
            case_dir.mkdir(parents=True, exist_ok=True)
            version_dir = case_dir / f"v{new_version}"
            if version_dir.exists():
                raise EvidenceError(f"目标版本目录已存在: {version_dir}")
            version_dir.mkdir()

            # 暂存区 → 不可变版本目录（同卷 rename，原子且不再触碰旧版本）。
            for f in extracted:
                target = version_dir / Path(f.rel_path)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(f.disk_path), target)

            if row is None:
                conn.execute(
                    "INSERT INTO cases (case_id, current_version, created_at, updated_at)"
                    " VALUES (?, ?, ?, ?)",
                    (case_id, new_version, now, now),
                )
            else:
                conn.execute(
                    "UPDATE cases SET current_version = ?, updated_at = ?"
                    " WHERE case_id = ?",
                    (new_version, now, case_id),
                )

            conn.execute(
                "INSERT INTO versions (case_id, version, created_at) VALUES (?, ?, ?)",
                (case_id, new_version, now),
            )
            conn.executemany(
                "INSERT INTO files (case_id, version, rel_path, sha256, size,"
                " stored_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        case_id,
                        new_version,
                        f.rel_path,
                        f.sha256,
                        f.size,
                        f.rel_path,
                        now,
                    )
                    for f in extracted
                ],
            )
            conn.execute("COMMIT")
            return new_version

        except sqlite3.OperationalError as exc:
            # SQLITE_BUSY：另一个进程持锁，短暂等待后重试。
            last_error = exc
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            if version_dir is not None:
                shutil.rmtree(version_dir, ignore_errors=True)
            time.sleep(_BUSY_RETRY_SLEEP)
            continue
        except EvidenceError:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            if version_dir is not None:
                shutil.rmtree(version_dir, ignore_errors=True)
            raise
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            if version_dir is not None:
                shutil.rmtree(version_dir, ignore_errors=True)
            raise
        finally:
            conn.close()

    raise ConflictError(f"数据库写入锁竞争超时，请重试: {last_error}")


def list_cases(settings: Settings) -> list[dict]:
    """首页清单：所有案件及其当前版本。"""
    conn = _connect(settings)
    try:
        rows = conn.execute(
            """
            SELECT c.case_id, c.current_version, c.created_at, c.updated_at,
                   (SELECT COUNT(*) FROM files f
                     WHERE f.case_id = c.case_id AND f.version = c.current_version)
                       AS file_count,
                   (SELECT COALESCE(SUM(size), 0) FROM files f
                     WHERE f.case_id = c.case_id AND f.version = c.current_version)
                       AS total_size
              FROM cases c
             ORDER BY c.case_id
            """
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_case(settings: Settings, case_id: str) -> dict | None:
    """案件详情：全部已发布版本（不可变）及各版本附件。"""
    conn = _connect(settings)
    try:
        case = conn.execute(
            "SELECT * FROM cases WHERE case_id = ?", (case_id,)
        ).fetchone()
        if case is None:
            return None

        versions = []
        for vrow in conn.execute(
            "SELECT version, created_at FROM versions"
            " WHERE case_id = ? ORDER BY version",
            (case_id,),
        ).fetchall():
            files = [
                dict(row)
                for row in conn.execute(
                    "SELECT rel_path, sha256, size FROM files"
                    " WHERE case_id = ? AND version = ? ORDER BY rel_path",
                    (case_id, vrow["version"]),
                ).fetchall()
            ]
            versions.append(
                {
                    "version": vrow["version"],
                    "created_at": vrow["created_at"],
                    "file_count": len(files),
                    "total_size": sum(f["size"] for f in files),
                    "files": files,
                }
            )

        result = dict(case)
        result["versions"] = versions
        return result
    finally:
        conn.close()


def get_file(
    settings: Settings, case_id: str, version: int, rel_path: str
) -> tuple[Path, sqlite3.Row] | None:
    """定位某个已发布版本中的附件，返回磁盘路径与元数据。"""
    conn = _connect(settings)
    try:
        row = conn.execute(
            "SELECT rel_path, sha256, size, stored_name FROM files"
            " WHERE case_id = ? AND version = ? AND rel_path = ?",
            (case_id, version, rel_path),
        ).fetchone()
        if row is None:
            return None

        version_dir = (settings.files_dir / case_id / f"v{version}").resolve()
        target = (version_dir / row["stored_name"]).resolve()
        # 防御性校验：最终路径必须仍在该版本目录之内。
        if version_dir not in target.parents or not target.is_file():
            raise EvidenceError("附件路径异常，拒绝下载")
        return target, row
    finally:
        conn.close()

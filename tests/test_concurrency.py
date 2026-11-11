"""跨线程/跨进程并发发布与崩溃恢复测试。"""

from __future__ import annotations

import multiprocessing as mp
import threading

import pytest

from app.errors import ConflictError
from app.manifest import ManifestEntry
from app.security import ExtractedFile
from app import storage


def _prepare_bundle(staging_root, index):
    """构造一份合法的暂存文件 + 清单条目（每个线程/进程独立目录）。"""
    staging = staging_root / f"job-{index}"
    extract = staging / "extracted"
    extract.mkdir(parents=True)
    payload = f"payload-{index}\n".encode()
    import hashlib

    (extract / "f.txt").write_bytes(payload)
    entry = ManifestEntry(path="f.txt", sha256=hashlib.sha256(payload).hexdigest())
    extracted = ExtractedFile(
        rel_path="f.txt",
        disk_path=extract / "f.txt",
        sha256=hashlib.sha256(payload).hexdigest(),
        size=len(payload),
    )
    return staging, [entry], [extracted]


def test_concurrent_threads_only_one_succeeds(settings):
    storage.init_db(settings)
    results: list[str] = []
    errors: list[str] = []
    lock = threading.Lock()

    def worker(i):
        staging, entries, extracted = _prepare_bundle(settings.staging_dir, i)
        try:
            version = storage.publish(
                settings, "CASE-CONC", 0, entries, extracted
            )
            with lock:
                results.append(f"ok-v{version}")
        except ConflictError as exc:
            with lock:
                errors.append(str(exc))
        except Exception as exc:  # pragma: no cover
            with lock:
                errors.append(f"unexpected: {exc!r}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results == ["ok-v1"], results
    assert len(errors) == 11
    detail = storage.get_case(settings, "CASE-CONC")
    assert detail["current_version"] == 1
    assert len(detail["versions"]) == 1


def _child_publish(home_dict, case_id, expected, index, queue):
    """子进程入口：重新构造 Settings 后发布。"""
    from pathlib import Path

    from app.config import Settings

    home = Path(home_dict["home"])
    s = Settings(
        home=home,
        db_path=home / "evidence.db",
        files_dir=home / "files",
        staging_dir=home / "staging",
        tmp_dir=home / "tmp",
    )
    staging, entries, extracted = _prepare_bundle(s.staging_dir, index)
    try:
        version = storage.publish(s, case_id, expected, entries, extracted)
        queue.put(("ok", version))
    except ConflictError as exc:
        queue.put(("conflict", str(exc)))
    except Exception as exc:  # pragma: no cover
        queue.put(("error", repr(exc)))


def test_concurrent_processes_only_one_succeeds(settings):
    """模拟两个服务进程基于同一当前版同时提交。"""
    storage.init_db(settings)
    ctx = mp.get_context("fork")
    queue = ctx.Queue()
    procs = [
        ctx.Process(
            target=_child_publish,
            args=(
                {"home": str(settings.home)},
                "CASE-MPROC",
                0,
                i,
                queue,
            ),
        )
        for i in range(4)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=60)
        assert p.exitcode == 0

    outcomes = [queue.get() for _ in procs]
    oks = [o for o in outcomes if o[0] == "ok"]
    conflicts = [o for o in outcomes if o[0] == "conflict"]
    assert len(oks) == 1, outcomes
    assert oks[0][1] == 1
    assert len(conflicts) == 3

    detail = storage.get_case(settings, "CASE-MPROC")
    assert detail["current_version"] == 1
    # 只有胜出者的版本目录存在。
    v1 = settings.files_dir / "CASE-MPROC" / "v1"
    assert v1.is_dir() and (v1 / "f.txt").is_file()
    assert not (settings.files_dir / "CASE-MPROC" / "v2").exists()


def test_cleanup_removes_orphan_and_scratch(settings):
    # 先发布一个正常版本。
    storage.init_db(settings)
    staging, entries, extracted = _prepare_bundle(settings.staging_dir, 0)
    storage.publish(settings, "CASE-KEEP", 0, entries, extracted)

    # 模拟“移动后、提交前崩溃”：磁盘有 v2 目录但数据库无记录。
    orphan = settings.files_dir / "CASE-KEEP" / "v2"
    (orphan / "deep").mkdir(parents=True)
    (orphan / "deep" / "half.bin").write_bytes(b"half")

    # 模拟暂存区与上传临时区残留。
    stale_stage = settings.staging_dir / "stale-job"
    stale_stage.mkdir(parents=True)
    (stale_stage / "x").write_bytes(b"x")
    (settings.tmp_dir / "upload.tmp").write_bytes(b"t")

    storage.cleanup_workspace(settings)

    assert not orphan.exists()
    assert not stale_stage.exists()
    assert not (settings.tmp_dir / "upload.tmp").exists()

    # 已发布版本完好无损、仍可下载定位。
    found = storage.get_file(settings, "CASE-KEEP", 1, "f.txt")
    assert found is not None
    detail = storage.get_case(settings, "CASE-KEEP")
    assert detail["current_version"] == 1
    assert len(detail["versions"]) == 1


def test_failed_publish_changes_nothing(settings):
    storage.init_db(settings)
    # 首次发布成功。
    staging, entries, extracted = _prepare_bundle(settings.staging_dir, 1)
    storage.publish(settings, "CASE-STABLE", 0, entries, extracted)

    # 基于过期版本再次提交：失败且文件/版本数不变。
    staging2, entries2, extracted2 = _prepare_bundle(settings.staging_dir, 2)
    with pytest.raises(ConflictError):
        storage.publish(settings, "CASE-STABLE", 0, entries2, extracted2)

    detail = storage.get_case(settings, "CASE-STABLE")
    assert detail["current_version"] == 1
    assert not (settings.files_dir / "CASE-STABLE" / "v2").exists()
    # 冲突路径在事务提交前返回，不会创建任何版本目录；
    # 暂存区由上层请求（main 的 finally）负责清理，发布层不删除调用方目录。
    assert not (settings.files_dir / "CASE-STABLE" / "v2").exists()
    assert len(detail["versions"]) == 1

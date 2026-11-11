"""FastAPI 入口：证据接收页面、接收 API、版本清单与附件下载。

服务以两个独立进程（gunicorn + 2 个 uvicorn worker）运行，
共享同一 ``EVIDENCE_HOME`` 卷；并发提交的一致性由 storage 层保证。
"""

from __future__ import annotations

import os
import shutil
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import storage
from .config import MAX_MANIFEST_BYTES, Settings, load_settings
from .errors import ConflictError, EvidenceError
from .manifest import parse_manifest
from .samples import Sample, build_samples
from .security import safe_extract

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

_settings: Settings | None = None
_samples: dict[str, Sample] | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = load_settings()
    return _settings


def get_samples() -> dict[str, Sample]:
    global _samples
    if _samples is None:
        _samples = build_samples()
    return _samples


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动即清理半包残留，再初始化数据库（每个 worker 进程各执行一次，
    # 清理本身幂等，SQLite 建表使用 IF NOT EXISTS）。
    settings = get_settings()
    storage.cleanup_workspace(settings)
    yield


app = FastAPI(
    title="取证证据接收系统",
    description="安全接收外包取证 ZIP 与独立清单，核验通过后原子发布不可变新版本",
    version="1.0.0",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/intake", include_in_schema=False)
def intake_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "intake.html")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "pid": os.getpid()}


@app.get("/api/cases")
def api_cases() -> list[dict]:
    """首页：已发布案件与版本清单。"""
    return storage.list_cases(get_settings())


@app.get("/api/cases/{case_id}")
def api_case_detail(case_id: str) -> JSONResponse:
    detail = storage.get_case(get_settings(), case_id)
    if detail is None:
        return JSONResponse(status_code=404, content={"detail": "案件不存在"})
    return JSONResponse(content=detail)


@app.get("/api/samples")
def api_samples() -> list[dict]:
    """样例元数据（不含二进制），供首页渲染下载链接。"""
    return [
        {
            "id": s.sample_id,
            "title": s.title,
            "description": s.description,
            "zip_url": f"/api/samples/{s.sample_id}/bundle",
            "manifest_url": f"/api/samples/{s.sample_id}/manifest",
        }
        for s in get_samples().values()
    ]


@app.get("/api/samples/{sample_id}/bundle")
def api_sample_bundle(sample_id: str):
    sample = get_samples().get(sample_id)
    if sample is None:
        return JSONResponse(status_code=404, content={"detail": "样例不存在"})
    return _bytes_response(sample.zip_bytes, sample.zip_name, "application/zip")


@app.get("/api/samples/{sample_id}/manifest")
def api_sample_manifest(sample_id: str):
    sample = get_samples().get(sample_id)
    if sample is None:
        return JSONResponse(status_code=404, content={"detail": "样例不存在"})
    return _bytes_response(
        sample.manifest_bytes, sample.manifest_name, "application/json"
    )


def _bytes_response(data: bytes, filename: str, media_type: str) -> Response:
    return Response(
        content=data,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


async def _save_upload(upload: UploadFile, dest_dir: Path, limit: int) -> Path:
    """流式保存上传文件，按实际字节计数，超限立即拒绝。"""
    dest = dest_dir / f"{uuid.uuid4().hex}_{upload.filename or 'unnamed'}"
    written = 0
    with open(dest, "wb") as out:
        while True:
            chunk = await upload.read(64 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > limit:
                raise EvidenceError(f"上传文件超过 {limit} 字节上限")
            out.write(chunk)
    return dest


@app.post("/api/intake")
async def api_intake(
    case_id: str = Form(...),
    expected_version: int = Form(...),
    zip_file: UploadFile = File(...),
    manifest_file: UploadFile = File(...),
) -> JSONResponse:
    """证据接收主流程。

    任何一步失败都返回 4xx 且不改变当前版本；全部通过才发布新版本。
    """
    settings = get_settings()
    staging = storage.new_staging_dir(settings)
    temp_files: list[Path] = []
    try:
        # 1) 上传落到独立临时目录（同样按实际字节限制大小）。
        try:
            zip_path = await _save_upload(
                zip_file, settings.tmp_dir, settings.max_upload_bytes
            )
            temp_files.append(zip_path)
        finally:
            await zip_file.close()
        try:
            manifest_path = await _save_upload(
                manifest_file, settings.tmp_dir, MAX_MANIFEST_BYTES
            )
            temp_files.append(manifest_path)
        finally:
            await manifest_file.close()

        # 2) 解析独立 JSON 清单。
        manifest_entries = parse_manifest(
            manifest_path.read_bytes(), max_entries=settings.max_entries
        )

        # 3) 分块解压并按实际内容核验（路径/类型/大小/哈希由安全模块兜底）。
        extract_dir = staging / "extracted"
        extract_dir.mkdir()
        extracted = safe_extract(
            zip_path,
            extract_dir,
            max_total_bytes=settings.max_total_bytes,
            max_entries=settings.max_entries,
            chunk_size=settings.chunk_size,
        )

        # 4) 清单一一对应 + 哈希核对，通过后在写事务内原子发布。
        new_version = storage.publish(
            settings,
            case_id=case_id,
            expected_version=expected_version,
            manifest_entries=manifest_entries,
            extracted=extracted,
        )
        return JSONResponse(
            status_code=201,
            content={
                "case_id": case_id,
                "version": new_version,
                "file_count": len(extracted),
                "message": f"证据核验通过，已发布版本 v{new_version}",
            },
        )
    except ConflictError as exc:
        return JSONResponse(status_code=409, content={"detail": str(exc)})
    except EvidenceError as exc:
        return JSONResponse(status_code=400, content={"detail": str(exc)})
    finally:
        # 无论成功失败，本请求的暂存区与上传临时文件都不残留
        #（成功时文件已 move 走）。只清理自己创建的文件，
        # 不能清空整个共享临时目录，以免影响其他进程的在途请求。
        shutil.rmtree(staging, ignore_errors=True)
        for tmp in temp_files:
            tmp.unlink(missing_ok=True)


@app.get(
    "/api/cases/{case_id}/versions/{version}/files/{rel_path:path}",
    include_in_schema=False,
    response_model=None,
)
def api_download(case_id: str, version: int, rel_path: str):
    """附件下载：仅限已发布的案件+版本，强制 attachment，不提供目录浏览。"""
    settings = get_settings()
    try:
        found = storage.get_file(settings, case_id, version, rel_path)
    except EvidenceError as exc:
        return JSONResponse(status_code=400, content={"detail": str(exc)})
    if found is None:
        return JSONResponse(status_code=404, content={"detail": "附件不存在"})

    disk_path, row = found
    download_name = rel_path.rsplit("/", 1)[-1] or "file"
    return FileResponse(
        disk_path,
        media_type="application/octet-stream",
        filename=download_name,
        content_disposition_type="attachment",
        headers={"X-SHA256": row["sha256"]},
    )

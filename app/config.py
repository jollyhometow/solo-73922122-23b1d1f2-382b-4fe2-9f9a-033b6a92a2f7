"""运行配置。

所有路径都基于 ``EVIDENCE_HOME`` 环境变量（默认 ``./data``），
容器内由 docker-compose 挂载为命名卷，两个 worker 进程共享同一目录。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# 解压后全部文件的累计上限（16 MiB）。按“实际读出的字节”统计，
# 不相信 ZIP 本地头/中央目录里声明的大小。
MAX_TOTAL_BYTES = 16 * 1024 * 1024

# 单次上传（ZIP / JSON 各自）请求体上限，防止磁盘被灌满。
MAX_UPLOAD_BYTES = 64 * 1024 * 1024

# 单条目数量上限，避免恶意清单/压缩包消耗过多句柄与内存。
MAX_ENTRIES = 10_000

# 每次分块读取 64 KiB。
CHUNK_SIZE = 64 * 1024

# 案件号允许字符：ASCII 字母、数字、下划线、短横线，1-64 位。
CASE_ID_PATTERN = r"[A-Za-z0-9_-]{1,64}"

# 清单 JSON 最大 4 MiB（纯文本，足够万级条目）。
MAX_MANIFEST_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class Settings:
    home: Path
    db_path: Path
    files_dir: Path       # 已发布文件
    staging_dir: Path     # 正在核验的暂存区（启动时清空）
    tmp_dir: Path         # 上传临时文件
    max_total_bytes: int = MAX_TOTAL_BYTES
    max_upload_bytes: int = MAX_UPLOAD_BYTES
    max_entries: int = MAX_ENTRIES
    chunk_size: int = CHUNK_SIZE


def load_settings() -> Settings:
    home = Path(os.environ.get("EVIDENCE_HOME", "data")).resolve()
    return Settings(
        home=home,
        db_path=home / "evidence.db",
        files_dir=home / "files",
        staging_dir=home / "staging",
        tmp_dir=home / "tmp",
    )

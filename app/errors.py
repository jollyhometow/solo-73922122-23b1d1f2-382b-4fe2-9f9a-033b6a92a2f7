"""领域错误。

所有接收流程中可预期的失败都抛出 :class:`EvidenceError`，
API 层统一转成 ``400``；版本冲突用 :class:`ConflictError` 转成 ``409``。
失败路径不会触碰已发布版本。
"""

from __future__ import annotations


class EvidenceError(Exception):
    """证据核验失败（清单/路径/哈希/大小等）。"""


class ConflictError(EvidenceError):
    """预期版本与当前版本不一致，或 SQLite 写入锁竞争失败。"""

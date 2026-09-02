"""FS errors — доменные ошибки модуля (ADR-002 §2.1, §10, §3.1).

# Перенесено из mia-workspace, источник: modules/workspace/fs.py
"""
from __future__ import annotations

__all__ = ["FsError", "FS_QUOTA_EXCEEDED", "NOT_SHAREABLE", "UID_EXHAUSTED", "UNIX_ACCOUNT_MISMATCH"]


class FsError(Exception):
    def __init__(self, message: str, code: str = "FS_ERROR") -> None:
        self.code = code
        super().__init__(message)


# Коды ревизии 6 (§3.1) и ревизии 5 (§5.6, §10): доменные, не security-события
UID_EXHAUSTED = "UID_EXHAUSTED"                    # пул 10000..60000 исчерпан
UNIX_ACCOUNT_MISMATCH = "UNIX_ACCOUNT_MISMATCH"    # login занят чужим UID — ручная чистка
NOT_SHAREABLE = "NOT_SHAREABLE"                    # путь вне живых линковок владельца / rel=''
FS_QUOTA_EXCEEDED = "FS_QUOTA_EXCEEDED"            # живых грантов владельца ≥ 1000

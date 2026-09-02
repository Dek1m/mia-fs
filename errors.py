"""FS errors — доменные ошибки модуля (ADR-002 §2.1).

# Перенесено из mia-workspace, источник: modules/workspace/fs.py
"""
from __future__ import annotations

__all__ = ["FsError"]


class FsError(Exception):
    def __init__(self, message: str, code: str = "FS_ERROR") -> None:
        self.code = code
        super().__init__(message)

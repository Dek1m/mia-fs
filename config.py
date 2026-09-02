"""FsConfig — env модуля (ADR-002 §13). MiaConfig не расширяется."""
from __future__ import annotations

import os
from dataclasses import dataclass

__all__ = ["FsConfig"]


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


@dataclass
class FsConfig:
    """Настройки fs. FS_HOME_ROOT с fallback на WORKSPACE_HOME_ROOT (переходный период, §13)."""

    home_root: str = "/home"              # FS_HOME_ROOT
    max_write_bytes: int = 10 * 1024**2   # FS_MAX_WRITE_BYTES
    max_list_entries: int = 5000          # FS_MAX_LIST_ENTRIES
    max_resolve_inputs: int = 50          # FS_MAX_RESOLVE_INPUTS (шаг 5)
    default_page_size: int = 50           # FS_DEFAULT_PAGE_SIZE
    max_page_size: int = 200              # FS_MAX_PAGE_SIZE
    git_timeout: float = 3.0              # FS_GIT_TIMEOUT

    @classmethod
    def from_env(cls) -> "FsConfig":
        return cls(
            home_root=os.getenv("FS_HOME_ROOT") or os.getenv("WORKSPACE_HOME_ROOT") or "/home",
            max_write_bytes=_int_env("FS_MAX_WRITE_BYTES", 10 * 1024**2),
            max_list_entries=_int_env("FS_MAX_LIST_ENTRIES", 5000),
            max_resolve_inputs=_int_env("FS_MAX_RESOLVE_INPUTS", 50),
            default_page_size=_int_env("FS_DEFAULT_PAGE_SIZE", 50),
            max_page_size=_int_env("FS_MAX_PAGE_SIZE", 200),
            git_timeout=_float_env("FS_GIT_TIMEOUT", 3.0),
        )

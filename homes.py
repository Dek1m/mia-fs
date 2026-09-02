# Перенесено из mia-workspace, источник: modules/workspace/homes.py
"""Unix-пользователь и листинг ~/ в контейнере бэка (ADR-002 §2.1)."""
from __future__ import annotations

import os
import pwd
import re
import subprocess
from pathlib import Path
from typing import Any

from .errors import FsError
from .fs import deny_component_symlinks, folder_stats, join_rel, mkdir, safe_name, touch

__all__ = ["unix_name", "ensure_unix_home", "list_home", "own_path", "ensure_nested"]

_SAFE = re.compile(r"[^a-z0-9_-]")
_DIR_MODE = 0o755
_FILE_MODE = 0o644


def unix_name(raw: str) -> str:
    name = _SAFE.sub("", raw.strip().lower())
    if not name:
        name = "user"
    if name[0].isdigit():
        name = "u" + name
    return name[:32]


def ensure_unix_home(name: str, home_root: str = "/home") -> str:
    safe = unix_name(name)
    home = Path(home_root) / safe
    try:
        pwd.getpwnam(safe)
    except KeyError:
        subprocess.run(
            ["useradd", "-m", "-d", str(home), "-s", "/usr/sbin/nologin", safe],
            check=False,
            capture_output=True,
        )
    home.mkdir(parents=True, exist_ok=True)
    own_path(home, safe)
    return str(home)


def own_path(path: Path, unix: str) -> None:
    """Владелец — unix-пользователь albedo, права 0755/0644."""
    try:
        info = pwd.getpwnam(unix_name(unix))
        os.chown(path, info.pw_uid, info.pw_gid)
        os.chmod(path, _DIR_MODE if path.is_dir() else _FILE_MODE)
    except (KeyError, PermissionError, OSError):
        pass


def ensure_nested(home: str, rel: str, kind: str, unix: str) -> dict[str, Any]:
    """Создать вложенный путь. kind=folder|file. Родители — всегда папки."""
    rel = rel.strip().lstrip("/")
    if not rel or ".." in rel:
        raise FsError("invalid path", "INVALID_NAME")
    root = Path(home).resolve()
    # Symlink-guard до создания: существующие префиксы — только реальные каталоги
    deny_component_symlinks(root, rel)
    parts = [safe_name(part) for part in rel.split("/") if part]
    acc: list[str] = []
    last = len(parts) - 1
    path = root
    for index, part in enumerate(parts):
        acc.append(part)
        current = "/".join(acc)
        if index == last and kind == "file":
            path = touch(root, current)
        else:
            path = mkdir(root, current)
        own_path(path, unix)
    return {
        "name": parts[-1],
        "kind": kind,
        "rel_path": "/".join(parts),
    }


def list_home(
    home: str,
    rel: str = "",
    *,
    include_hidden: bool = False,
    include_size: bool = False,
    max_entries: int | None = None,
) -> list[dict[str, Any]]:
    root = Path(home).resolve()
    path = join_rel(root, rel) if rel else root
    if not path.is_dir():
        raise FsError("not a directory", "NOT_FOUND")
    items: list[dict[str, Any]] = []
    for child in sorted(path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
        # Лимит до дорогой обработки ребёнка: обход прерываем, не копим список
        if max_entries is not None and len(items) >= max_entries:
            raise FsError("listing too large", "LIST_TOO_LARGE")
        if child.name == "Trash":
            continue
        if child.name.startswith(".") and not include_hidden:
            continue
        kind = "folder" if child.is_dir() else "file"
        size = 0
        files = 0
        if include_size:
            if kind == "folder":
                files, size = folder_stats(child)
            else:
                try:
                    size = child.stat().st_size
                except OSError:
                    size = 0
        items.append({
            "name": child.name,
            "kind": kind,
            "rel_path": str(child.relative_to(root)),
            "size_bytes": size,
            "file_count": files,
        })
    return items

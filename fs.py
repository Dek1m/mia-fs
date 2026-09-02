# Перенесено из mia-workspace, источник: modules/workspace/fs.py
"""Реальные папки/файлы FS. Путь только внутри песочницы владельца (ADR-002 §10)."""
from __future__ import annotations

import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from .errors import FsError

__all__ = [
    "safe_name",
    "ensure_dir",
    "join_rel",
    "mkdir",
    "touch",
    "remove",
    "folder_stats",
    "trash_move",
    "move_into",
    "dir_child_count",
    "rename_path",
]

_NAME = re.compile(r"^[^/\\]{1,255}$")


def safe_name(name: str) -> str:
    value = name.strip()
    if not value or value in {".", ".."} or not _NAME.match(value) or ".." in value:
        raise FsError("invalid name", "INVALID_NAME")
    return value


def ensure_dir(path: Path) -> str:
    path.mkdir(parents=True, exist_ok=True)
    return str(path)


def join_rel(root: Path, rel: str) -> Path:
    target = (root / rel).resolve() if rel else root.resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError as exc:
        raise FsError("path escape", "PATH_ESCAPE") from exc
    return target


def mkdir(root: Path, rel: str) -> Path:
    path = join_rel(root, rel)
    path.mkdir(parents=True, exist_ok=True)
    return path


def touch(root: Path, rel: str) -> Path:
    path = join_rel(root, rel)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)
    return path


def remove(root: Path, rel: str) -> None:
    path = join_rel(root, rel)
    if path.is_dir():
        shutil.rmtree(path)
        return
    if path.exists():
        path.unlink()


def trash_move(home: Path, rel: str) -> str:
    """Перенести путь в ~/Trash/belle/{utc}/{rel}. Не rm."""
    rel = rel.strip().lstrip("/")
    if not rel or rel in {".", ".."} or rel.startswith("Trash/") or ".." in rel:
        raise FsError("cannot trash this path", "INVALID_NAME")
    src = join_rel(home, rel)
    if not src.exists():
        raise FsError("not found", "NOT_FOUND")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    dest = (home.resolve() / "Trash" / "belle" / stamp / rel).resolve()
    try:
        dest.relative_to(home.resolve())
    except ValueError as exc:
        raise FsError("path escape", "PATH_ESCAPE") from exc
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        dest = dest.with_name(f"{dest.name}.{stamp}")
    shutil.move(str(src), str(dest))
    return str(dest.relative_to(home.resolve()))


def folder_stats(path: Path) -> tuple[int, int]:
    files = 0
    size = 0
    if not path.is_dir():
        return 0, 0
    for dirpath, _dirnames, filenames in os.walk(path):
        files += len(filenames)
        for name in filenames:
            try:
                size += (Path(dirpath) / name).stat().st_size
            except OSError:
                continue
    return files, size


def dir_child_count(path: Path) -> int:
    if not path.is_dir():
        return 0
    return sum(1 for _ in path.iterdir())


def move_into(home: Path, src_rel: str, dest_dir_rel: str) -> str:
    """Перенести src в каталог dest_dir. Оба пути относительно home."""
    src_rel = src_rel.strip().lstrip("/")
    dest_dir_rel = dest_dir_rel.strip().lstrip("/")
    if not src_rel or ".." in src_rel or ".." in dest_dir_rel:
        raise FsError("invalid path", "INVALID_NAME")
    root = home.resolve()
    src = join_rel(root, src_rel)
    dest_dir = join_rel(root, dest_dir_rel) if dest_dir_rel else root
    if not src.exists():
        raise FsError("not found", "NOT_FOUND")
    if not dest_dir.is_dir():
        raise FsError("destination is not a folder", "NOT_FOUND")
    dest = dest_dir / src.name
    if dest.resolve() == src.resolve():
        return str(src.relative_to(root))
    try:
        dest.resolve().relative_to(src.resolve())
        raise FsError("cannot move into itself", "INVALID_NAME")
    except ValueError:
        pass
    if dest.exists():
        raise FsError("already exists", "ALREADY_EXISTS")
    shutil.move(str(src), str(dest))
    return str(dest.resolve().relative_to(root))


def rename_path(home: Path, src_rel: str, new_name: str) -> str:
    src_rel = src_rel.strip().lstrip("/")
    clean = safe_name(new_name)
    root = home.resolve()
    src = join_rel(root, src_rel)
    if not src.exists():
        raise FsError("not found", "NOT_FOUND")
    dest = src.parent / clean
    if dest.resolve() == src.resolve():
        return src_rel
    if dest.exists():
        raise FsError("already exists", "ALREADY_EXISTS")
    shutil.move(str(src), str(dest))
    return str(dest.resolve().relative_to(root))

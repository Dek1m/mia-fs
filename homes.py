# Перенесено из mia-workspace, источник: modules/workspace/homes.py
"""Unix-аккаунт и листинг ~/ в контейнере бэка (ADR-002 §2.1, §3.1).

username в путях as-is (ревизия 6, вердикт Мастера — вариант C): регистр и
кириллица сохраняются, биекцию путей гарантирует UNIQUE(username) в auth.
Функция unix_name() с lower() УСТРАНЕНА — нормализации путей не существует.
"""
from __future__ import annotations

import os
import pwd
import subprocess
from pathlib import Path
from typing import Any

from .errors import FsError
from .fs import deny_component_symlinks, folder_stats, join_rel, mkdir, safe_name, touch

__all__ = ["ensure_unix_home", "list_home", "own_path", "ensure_nested"]

_DIR_MODE = 0o700
_FILE_MODE = 0o600


def own_path(path: Path, uid: int, gid: int | None = None) -> None:
    """Владелец — unix-аккаунт из fs.unix_accounts: chown {uid}:{gid} + 700/600.

    gid не задан (до useradd-записи) — берётся из passwd по uid. Ошибки chown
    не глотаются молча: привязка тома — часть контракта провижининга (§3.1)."""
    if gid is None:
        gid = pwd.getpwuid(uid).pw_gid
    os.chown(path, uid, gid)
    os.chmod(path, _DIR_MODE if path.is_dir() else _FILE_MODE)


def ensure_unix_home(
    uid: int,
    login: str,
    username: str,
    home_root: str = "/home",
) -> str:
    """useradd -M -N -u {uid} -l -s nologin -d /home/{username} {login} + mkdir + chown + chmod.

    Ветвления §3.1:
    - «already exists» (крах прошлого прогона между useradd и INSERT):
      id -u {login} == uid → догоняем диск и запись; ≠ uid → UNIX_ACCOUNT_MISMATCH
      (внешнее вмешательство в том — ручная чистка + security-событие);
    - каталог уже существует (миграция): mkdir -p no-op, chown/chmod поверх,
      контент не трогается.

    Запись в fs.unix_accounts пишет вызывающий (accounts_repository.insert) —
    идемпотентный retry ловит UNIQUE на своей стороне."""
    home = Path(home_root) / username
    try:
        pwd.getpwnam(login)
    except KeyError:
        proc = subprocess.run(
            [
                "useradd", "-M", "-N", "-u", str(uid), "-l",
                "-s", "/usr/sbin/nologin", "-d", str(home), login,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0 and "already exists" in (proc.stderr or "").lower():
            # Крах прошлого прогона: сверяем UID существующего аккаунта
            try:
                existing = pwd.getpwnam(login).pw_uid
            except KeyError as exc:
                raise FsError("unix account vanished", "UNIX_ACCOUNT_MISMATCH") from exc
            if existing != uid:
                raise FsError(
                    f"unix account {login} owned by uid {existing}, expected {uid}",
                    "UNIX_ACCOUNT_MISMATCH",
                )
        elif proc.returncode != 0:
            raise FsError(f"useradd failed: {(proc.stderr or '').strip()[:200]}", "FS_ERROR")
    home.mkdir(parents=True, exist_ok=True)
    own_path(home, uid)
    return str(home)


def ensure_nested(home: str, rel: str, kind: str, uid: int, gid: int | None = None) -> dict[str, Any]:
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
        own_path(path, uid, gid)
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

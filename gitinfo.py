# Перенесено из mia-workspace, источник: modules/workspace/gitinfo.py
"""Git-статус каталогов пользователя. Только чтение (ADR-002 §2.1)."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .fs import join_rel

__all__ = ["list_repos"]


def list_repos(home: str, rel_paths: list[str], *, timeout: float = 3.0) -> list[dict[str, Any]]:
    root = Path(home).resolve()
    seen: set[str] = set()
    items: list[dict[str, Any]] = []
    for rel in rel_paths:
        start = join_rel(root, rel) if rel else root
        git_root = _find_git(start, root)
        if git_root is None:
            continue
        key = str(git_root)
        if key in seen:
            continue
        seen.add(key)
        info = _describe(git_root, root, timeout)
        if info is not None:
            items.append(info)
    return items


def _find_git(start: Path, home: Path) -> Path | None:
    current = start.resolve()
    home = home.resolve()
    while True:
        try:
            current.relative_to(home)
        except ValueError:
            return None
        if (current / ".git").exists():
            return current
        if current == home:
            return None
        parent = current.parent
        if parent == current:
            return None
        current = parent


def _run(cwd: Path, timeout: float, *args: str) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(cwd), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip()


def _describe(git_root: Path, home: Path, timeout: float) -> dict[str, Any] | None:
    branch = _run(git_root, timeout, "rev-parse", "--abbrev-ref", "HEAD")
    if not branch:
        return None
    dirty = bool(_run(git_root, timeout, "status", "--porcelain"))
    origin = _run(git_root, timeout, "remote", "get-url", "origin")
    rel = str(git_root.relative_to(home))
    if rel == ".":
        rel = ""
    return {
        "rel_path": rel,
        "branch": branch,
        "dirty": dirty,
        "url": _github_url(origin, branch),
    }


def _github_url(origin: str, branch: str) -> str | None:
    if not origin:
        return None
    value = origin.strip().removesuffix(".git")
    path = ""
    if value.startswith("git@github.com:"):
        path = value.split(":", 1)[1]
    elif "github.com/" in value:
        path = value.split("github.com/", 1)[1]
    elif "github.com:" in value:
        path = value.split("github.com:", 1)[1]
    else:
        return None
    path = path.lstrip("/")
    if not path:
        return None
    return f"https://github.com/{path}/tree/{quote(branch, safe='/_-')}"

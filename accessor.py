"""FsAccessor — фасад state.fs (ADR-002 §3).

Домен fs — один пользователь-владелец за вызов. Первый аргумент user —
uid (uuid) или username; нормализуется через auth и unix_name. Никаких
путей вне песочницы: join_rel валидирует resolve() внутри home.
"""
from __future__ import annotations

import asyncio
import inspect
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .config import FsConfig
from .errors import FsError
from .fs import (
    dir_child_count,
    folder_stats,
    join_rel,
    move_into,
    read_file,
    remove,
    rename_path,
    trash_move,
    write_file,
)
from .gitinfo import list_repos
from .homes import ensure_nested, ensure_unix_home, list_home, unix_name

__all__ = ["FsAccessor"]

# Security-коды: отказ песочницы/ACL — observation error + security event (§10)
_SECURITY_CODES = frozenset({
    "PATH_ESCAPE",
    "SYMLINK_ESCAPE",
    "ACL_DENIED",
    "INVALID_NAME",
    "INTERNAL_PATH_FORBIDDEN",
})


def _run_coro(coro: Any) -> Any:
    """Запустить корутину из sync-контекста io-задачи (приём workspace.provider)."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result(timeout=10)


class FsAccessor:
    """Провижининг home + дисковые операции в песочнице владельца."""

    def __init__(
        self,
        config: FsConfig,
        log: Any,
        database: Any | None = None,
        auth: Any | None = None,
    ) -> None:
        self._config = config
        self._log = log
        self._database = database
        self._auth = auth

    # ── Нормализация пользователя ───────────────────────────

    def _username(self, raw: str) -> str:
        """uid (uuid) → username через auth; без auth — как есть (тестовый режим, §3).

        Fail-closed: auth задан, но резолв упал или пуст → AUTH_RESOLVE_FAILED.
        Raw-фолбэк запрещён — иначе uuid оседает как unix_name и песочницы
        расходятся с идентичностью (ревью Литы №8)."""
        if self._auth is None:
            return raw
        try:
            fn = inspect.unwrap(self._auth.get_user)
            row = (
                _run_coro(fn(self._auth, raw))
                if inspect.iscoroutinefunction(fn)
                else fn(self._auth, raw)
            )
            username = str(row["username"]) if isinstance(row, dict) and row.get("username") else ""
        except Exception:
            username = ""
        if not username:
            self._log.warning("fs_auth_resolve_failed", extra={"user": str(raw)[:64]})
            raise FsError("auth resolve failed", "AUTH_RESOLVE_FAILED")
        return username

    def _home(self, user: str) -> Path:
        return Path(self._config.home_root) / unix_name(self._username(user))

    def _scope(self, user: str, owner: str | None) -> Path:
        """Песочница операции: своя — или отказ до ACL-машины (шаг 5, §5.7).

        Сравнение identity по uuid: unix_name коллизирует ("Иван"/"ivan" → ivan).
        Ни одна роль не даёт доступ к чужим папкам: без гранта (пока без
        ACL-lookup вообще) чужой owner всегда denied — fail closed.
        """
        if not owner:
            return self._home(user)
        if self._auth is not None:
            same = user == owner
        else:
            same = unix_name(self._username(user)) == unix_name(self._username(owner))
        if same:
            return self._home(user)
        # TODO(ADR-002 шаг 5): ACL-lookup по fs.nodes/fs.acl (машина §5.4);
        # сейчас грантов нет ни у кого — чужая песочница запрещена.
        raise FsError("acl lookup not available", "ACL_DENIED")

    @contextmanager
    def _measure(self, operation: str, rel_path: str, user: str) -> Iterator[None]:
        """Метрики + логи операции (§11, §12). Путь в мете — атакующая строка,
        обрезка 512 (§10); содержимое файлов не логируется никогда."""
        started = time.monotonic()
        try:
            yield
        except FsError as exc:
            denied = exc.code in _SECURITY_CODES
            from .metrics import fs_operation_duration_seconds, fs_operations_total, fs_security_violations_total

            outcome = "denied" if denied else "error"
            fs_operations_total.labels(operation=operation, outcome=outcome).inc()
            fs_operation_duration_seconds.labels(operation=operation).observe(time.monotonic() - started)
            if denied:
                fs_security_violations_total.labels(kind=exc.code).inc()
                # Security-событие WARN без stack trace (§10, §12)
                self._log.warning(
                    "fs_security_violation",
                    extra={
                        "kind": exc.code,
                        "user_id": user,
                        "rel_path": rel_path[:512],
                        "operation": operation,
                        "code": exc.code,
                    },
                )
            else:
                self._log.error(
                    "fs_operation_failed",
                    extra={
                        "operation": operation,
                        "error_type": exc.code,
                        "duration_ms": round((time.monotonic() - started) * 1000, 1),
                    },
                )
            raise
        except Exception as exc:
            from .metrics import fs_operation_duration_seconds, fs_operations_total

            fs_operations_total.labels(operation=operation, outcome="error").inc()
            fs_operation_duration_seconds.labels(operation=operation).observe(time.monotonic() - started)
            self._log.error(
                "fs_operation_failed",
                extra={
                    "operation": operation,
                    "error_type": type(exc).__name__,
                    "duration_ms": round((time.monotonic() - started) * 1000, 1),
                },
            )
            raise
        else:
            from .metrics import fs_operation_duration_seconds, fs_operations_total

            fs_operations_total.labels(operation=operation, outcome="ok").inc()
            fs_operation_duration_seconds.labels(operation=operation).observe(time.monotonic() - started)
            self._log.info(
                "fs_operation",
                extra={
                    "operation": operation,
                    "rel_path": rel_path[:512],
                    "duration_ms": round((time.monotonic() - started) * 1000, 1),
                },
            )

    # ── Провижининг ─────────────────────────────────────────

    def ensure_home(self, user: str) -> dict[str, Any]:
        """useradd + mkdir + chown, идемпотентно. → {home, unix_name}."""
        username = unix_name(self._username(user))
        home = self._home(user)
        with self._measure("ensure_home", "", user):
            if not home.exists():
                ensure_unix_home(username, self._config.home_root)
                self._log.info(
                    "fs_home_provisioned",
                    extra={"unix_name": username, "home": str(home)},
                )
        return {"home": str(home), "unix_name": username}

    def home_for(self, user: str) -> str:
        """Резолв пути без создания (валидация unix_name)."""
        return str(self._home(user))

    # ── Диск (rel — относительно home) ──────────────────────

    def exists(self, user: str, rel: str, *, owner: str | None = None) -> bool:
        with self._measure("exists", rel, user):
            return join_rel(self._scope(user, owner), rel).exists()

    def resolve(self, user: str, rel: str, *, owner: str | None = None) -> Path:
        """Canonical путь + проверка песочницы владельца."""
        with self._measure("resolve", rel, user):
            return join_rel(self._scope(user, owner), rel)

    def list(self, user: str, rel: str, *, include_hidden: bool = False, include_size: bool = False,
             owner: str | None = None) -> list[dict[str, Any]]:
        with self._measure("list", rel, user):
            # Лимит проверяется на обходе: не строим весь список ради отказа
            return list_home(
                str(self._scope(user, owner)),
                rel,
                include_hidden=include_hidden,
                include_size=include_size,
                max_entries=self._config.max_list_entries,
            )

    def stat(self, user: str, rel: str, *, owner: str | None = None) -> dict[str, Any]:
        with self._measure("stat", rel, user):
            path = join_rel(self._scope(user, owner), rel)
            if path.is_dir():
                return {"rel_path": rel, "kind": "folder", "child_count": dir_child_count(path)}
            if not path.exists():
                raise FsError("not found", "NOT_FOUND")
            return {"rel_path": rel, "kind": "file", "size": path.stat().st_size}

    def ensure_nested(self, user: str, rel: str, kind: str, *, owner: str | None = None) -> dict[str, Any]:
        if kind not in {"folder", "file"}:
            raise FsError("invalid kind", "INVALID_NAME")
        with self._measure("ensure_nested", rel, user):
            home = self._scope(user, owner)
            return ensure_nested(str(home), rel, kind, unix_name(self._username(user)))

    def read(self, user: str, rel: str, *, owner: str | None = None) -> dict[str, Any]:
        """Содержимое файла b64; лимит max_write_bytes на payload (§10 п.6)."""
        import base64

        with self._measure("read", rel, user):
            path = join_rel(self._scope(user, owner), rel)
            if not path.is_file():
                raise FsError("not found", "NOT_FOUND")
            size = path.stat().st_size
            if size > self._config.max_write_bytes:
                raise FsError("file too large", "PAYLOAD_TOO_LARGE")
            # O_NOFOLLOW: подменённая между stat и чтением ссылка не читается
            return {"content_b64": base64.b64encode(read_file(path)).decode(), "size": size}

    def write(self, user: str, rel: str, content_b64: str, *, owner: str | None = None) -> dict[str, Any]:
        import base64

        with self._measure("write", rel, user):
            try:
                content = base64.b64decode(content_b64, validate=True)
            except Exception as exc:
                raise FsError("invalid base64", "INVALID_NAME") from exc
            if len(content) > self._config.max_write_bytes:
                raise FsError("payload too large", "PAYLOAD_TOO_LARGE")
            # Symlink-guard компонентов + O_NOFOLLOW финального (ревью Литы №4)
            write_file(self._scope(user, owner), rel, content)
            return {"rel_path": rel, "size": len(content)}

    def move(self, user: str, src: str, dest_dir: str, *, owner: str | None = None) -> str:
        with self._measure("move", src, user):
            home = self._scope(user, owner)
            new_rel = move_into(home, src, dest_dir)
            # TODO(ADR-002 шаг 5): UPDATE fs.nodes.path/display_name (§5.2) через FsRepository.
            return new_rel

    def rename(self, user: str, src: str, new_name: str, *, owner: str | None = None) -> str:
        with self._measure("rename", src, user):
            home = self._scope(user, owner)
            new_rel = rename_path(home, src, new_name)
            # TODO(ADR-002 шаг 5): UPDATE fs.nodes.path/display_name (§5.2) через FsRepository.
            return new_rel

    def trash(self, user: str, rel: str, *, owner: str | None = None) -> str:
        with self._measure("trash", rel, user):
            home = self._scope(user, owner)
            trashed_rel = trash_move(home, rel)
            # TODO(ADR-002 шаг 5): UPDATE fs.nodes.deleted_at (§5.2) через FsRepository.
            return trashed_rel

    def remove_outside_home(self, path: Path) -> None:
        """Для workspace.delete_workspace: root вне home_root (§3).

        Guard по контракту метода: внутренние пути удаляются через trash (§5)."""
        with self._measure("remove_outside_home", str(path), ""):
            if path.resolve().is_relative_to(Path(self._config.home_root).resolve()):
                raise FsError("internal path forbidden", "INTERNAL_PATH_FORBIDDEN")
            remove(path.parent, path.name)

    def git_repos(self, user: str, rel_paths: list[str], *, owner: str | None = None) -> list[dict[str, Any]]:
        with self._measure("git_status", ",".join(rel_paths)[:512], user):
            home = self._scope(user, owner)
            join_rel(home, "")  # песочница корня — валидация до git-обхода
            return list_repos(str(home), rel_paths, timeout=self._config.git_timeout)

    # ── Статистика (для refresh_home-фасада workspace) ──────

    def folder_stats(self, path: Path) -> tuple[int, int]:
        return folder_stats(path)

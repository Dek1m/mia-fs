"""FsAccessor — фасад state.fs (ADR-002 §3).

Домен fs — один пользователь-владелец за вызов. Первый аргумент user —
uid (uuid) или username; резолвится в identity через auth. Домашняя папка —
/home/{username} as-is (ревизия 6: ни lower, ни вырезаний; биекцию путей
гарантирует UNIQUE(username) в auth). Unix-аккаунт (UID, login) — системная
привязка в fs.unix_accounts, identity пользователя не является. Никаких путей
вне песочницы: join_rel валидирует resolve() внутри home.
"""
from __future__ import annotations

import asyncio
import inspect
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .accounts_repository import UnixAccountsRepository
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
from .homes import ensure_nested, ensure_unix_home, list_home

__all__ = ["FsAccessor"]

# Security-коды: отказ песочницы/ACL — observation error + security event (§10)
_SECURITY_CODES = frozenset({
    "PATH_ESCAPE",
    "SYMLINK_ESCAPE",
    "ACL_DENIED",
    "INVALID_NAME",
    "INTERNAL_PATH_FORBIDDEN",
    "UNIX_ACCOUNT_MISMATCH",
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
        self._accounts = UnixAccountsRepository(database) if database is not None else None

    # ── Нормализация пользователя ───────────────────────────

    def _auth_call(self, method: str, arg: str) -> dict[str, Any] | None:
        fn = inspect.unwrap(getattr(self._auth, method))
        if inspect.iscoroutinefunction(fn):
            return _run_coro(fn(self._auth, arg))
        # unwrap у @task снимает wrapper и boundness; живой bound-метод — самодостаточен
        if hasattr(fn, "__self__"):
            return fn(arg)
        return fn(self._auth, arg)

    def _identity(self, raw: str) -> tuple[str, str]:
        """raw (uuid | username) → (user_id, username) через auth.

        Без auth — raw как есть по обеим осям (тестовый режим, §3).
        Fail-closed: auth задан, но резолв упал или пуст → AUTH_RESOLVE_FAILED —
        иначе uuid/username оседают вперемешку и песочницы расходятся
        с идентичностью (ревью Литы №8)."""
        if self._auth is None:
            return raw, raw
        row: dict[str, Any] | None = None
        try:
            if len(raw) == 36 and raw.count("-") == 4:
                row = self._auth_call("get_user", raw)
            else:
                row = self._auth_call("get_user_by_username", raw)
        except Exception:
            row = None
        if not isinstance(row, dict) or not row.get("id") or not row.get("username"):
            self._log.warning("fs_auth_resolve_failed", extra={"user": str(raw)[:64]})
            raise FsError("auth resolve failed", "AUTH_RESOLVE_FAILED")
        return str(row["id"]), str(row["username"])

    def _root_for(self, username: str) -> Path:
        """Корень песочницы владельца: /home/{username} as-is, без нормализации."""
        return Path(self._config.home_root) / username

    def _sandbox(self, user: str, owner: str | None, rel: str) -> tuple[Path, str]:
        """Песочница операции: (канонический корень, канонический rel).

        Порядок обязательный (аксиома §5.4): join_rel (песочница) →
        канонический rel → ACL-машина → диск. Сырой rel от клиента в ACL
        не попадает никогда — иначе LIKE-префикс открывает обход через `..`."""
        requester_id, requester_name = self._identity(user)
        owner_id, owner_name = (requester_id, requester_name)
        if owner is not None:
            owner_id, owner_name = self._identity(owner)
        root = self._root_for(owner_name).resolve()
        resolved = join_rel(root, rel)
        canon_rel = resolved.relative_to(root).as_posix()
        if owner_id != requester_id:
            # TODO(ADR-002 шаг 5): ACL-lookup fs.nodes/fs.acl (машина §5.4)
            raise FsError("acl lookup not available", "ACL_DENIED")
        return root, canon_rel

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

    # ── Провижининг (§3.1) ──────────────────────────────────

    def ensure_home(self, user: str) -> dict[str, Any]:
        """Флоу ensure_unix_home: fast path → локи → uid → useradd → chown → INSERT.

        → {home, username, unix_uid, login}; идемпотентен на любом шаге."""
        user_id, username = self._identity(user)
        with self._measure("ensure_home", "", user):
            account = self._ensure_unix_account(user_id, username)
            self._log.info(
                "fs_home_provisioned",
                extra={"username": username, "home": account["home_path"], "login": account["login"]},
            )
            self._log.debug(
                "fs_home_uid",
                extra={"username": username, "unix_uid": account["unix_uid"]},
            )
        return {
            "home": account["home_path"],
            "username": username,
            "unix_uid": int(account["unix_uid"]),
            "login": account["login"],
        }

    def _ensure_unix_account(self, user_id: str, username: str) -> dict[str, Any]:
        """Шаги 1–5 флоу §3.1. Идемпотентен: fast path, double-check под локом,
        retry по UNIQUE. Требует database (без БД — только тест-контур без привязки)."""
        if self._accounts is None:
            raise FsError("unix accounts require database", "FS_ERROR")
        # 1. fast path: запись есть → вернуть без дисковых операций
        existing = self._accounts.find_by_user_id(user_id)
        if existing:
            return existing
        login = "mia-" + user_id.replace("-", "")[:8]
        home_path = str(self._root_for(username))
        while True:
            try:
                with self._database.transaction() as conn:
                    # 2. оба xact-лока в фиксированном порядке fs_uid → per-user
                    self._accounts.acquire_provision_locks(user_id, conn=conn)
                    # double-check: запись могла появиться, пока ждали лок
                    raced = self._accounts.find_by_user_id(user_id, conn=conn)
                    if raced:
                        return raced
                    uid = self._accounts.next_uid(
                        self._config.uid_min, self._config.uid_max, conn=conn,
                    )
                    # 3–4. useradd + mkdir + chown 700; идемпотентно, контент
                    # существующего каталога (миграция) не трогается
                    ensure_unix_home(uid, login, username, self._config.home_root)
                    # 5. INSERT записи; UNIQUE-гонка → retry-lookup
                    self._accounts.insert(user_id, uid, login, home_path, conn=conn)
                    created = self._accounts.find_by_user_id(user_id, conn=conn)
                    if created:
                        return created
                    # INSERT не закрепился (ON CONFLICT) — повтор с fast path
                    raise _RetryProvision()
            except _RetryProvision:
                continue
            except Exception as exc:
                # UNIQUE(login/unix_uid/home_path) → второй воркер читает строку
                if _is_unique_violation(exc):
                    retry = self._accounts.find_by_user_id(user_id)
                    if retry:
                        return retry
                    continue
                raise

    def home_for(self, user: str) -> str:
        """Резолв home_path из fs.unix_accounts без создания (§10).

        Нет записи (провижининг не выполнялся) — /home/{username} as-is:
        путь детерминирован username, привязка нужна только для UID."""
        _user_id, username = self._identity(user)
        if self._accounts is not None:
            account = self._accounts.find_by_user_id(_user_id)
            if account:
                return str(account["home_path"])
        return str(self._root_for(username))

    # ── Диск (rel — относительно home) ──────────────────────

    def exists(self, user: str, rel: str, *, owner: str | None = None) -> bool:
        with self._measure("exists", rel, user):
            root, canon_rel = self._sandbox(user, owner, rel)
            path = root / canon_rel if canon_rel else root
            return path.exists()

    def resolve(self, user: str, rel: str, *, owner: str | None = None) -> Path:
        """Canonical путь + проверка песочницы владельца."""
        with self._measure("resolve", rel, user):
            root, canon_rel = self._sandbox(user, owner, rel)
            return root / canon_rel if canon_rel else root

    def list(self, user: str, rel: str, *, include_hidden: bool = False, include_size: bool = False,
             owner: str | None = None) -> list[dict[str, Any]]:
        with self._measure("list", rel, user):
            root, canon_rel = self._sandbox(user, owner, rel)
            # Лимит проверяется на обходе: не строим весь список ради отказа
            return list_home(
                str(root),
                canon_rel,
                include_hidden=include_hidden,
                include_size=include_size,
                max_entries=self._config.max_list_entries,
            )

    def stat(self, user: str, rel: str, *, owner: str | None = None) -> dict[str, Any]:
        with self._measure("stat", rel, user):
            root, canon_rel = self._sandbox(user, owner, rel)
            path = root / canon_rel if canon_rel else root
            if path.is_dir():
                return {"rel_path": canon_rel, "kind": "folder", "child_count": dir_child_count(path)}
            if not path.exists():
                raise FsError("not found", "NOT_FOUND")
            return {"rel_path": canon_rel, "kind": "file", "size": path.stat().st_size}

    def ensure_nested(self, user: str, rel: str, kind: str, *, owner: str | None = None) -> dict[str, Any]:
        if kind not in {"folder", "file"}:
            raise FsError("invalid kind", "INVALID_NAME")
        with self._measure("mkdir" if kind == "folder" else "touch", rel, user):
            root, _canon_rel = self._sandbox(user, owner, rel)
            uid = self._uid_for_chown(owner or user)
            # raw rel: lstat-guard §10 п.3 обязан видеть symlink-компоненты
            return ensure_nested(str(root), rel, kind, uid)

    def _uid_for_chown(self, user: str) -> int:
        """UID владельца для chown созданных путей. Нет привязки → uid воркера:
        привязка тома для v1 не критична, воркер пишет своим uid."""
        import os

        if self._accounts is None:
            return os.getuid()
        user_id, _username = self._identity(user)
        account = self._accounts.find_by_user_id(user_id)
        return int(account["unix_uid"]) if account else os.getuid()

    def read(self, user: str, rel: str, *, owner: str | None = None) -> dict[str, Any]:
        """Содержимое файла b64; лимит max_write_bytes на payload (§10 п.6)."""
        import base64

        with self._measure("read", rel, user):
            root, canon_rel = self._sandbox(user, owner, rel)
            path = root / canon_rel if canon_rel else root
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
            root, _canon_rel = self._sandbox(user, owner, rel)
            # raw rel в write_file: O_NOFOLLOW + lstat-guard (§10 п.3)
            write_file(root, rel, content)
            return {"rel_path": _canon_rel, "size": len(content)}

    def move(self, user: str, src: str, dest_dir: str, *, owner: str | None = None) -> str:
        with self._measure("move", src, user):
            root, _canon_src = self._sandbox(user, owner, src)
            _dest_root, _canon_dest = self._sandbox(user, owner, dest_dir)
            new_rel = move_into(root, src, dest_dir)
            self._registry_after_move(root, new_rel)
            return new_rel

    def rename(self, user: str, src: str, new_name: str, *, owner: str | None = None) -> str:
        with self._measure("rename", src, user):
            root, _canon_src = self._sandbox(user, owner, src)
            new_rel = rename_path(root, src, new_name)
            self._registry_after_move(root, new_rel)
            return new_rel

    def _registry_after_move(self, root: Path, new_rel: str) -> None:
        # TODO(ADR-002 шаг 5): UPDATE fs.nodes.path/display_name (§5.2) — FsRepository
        return None

    def trash(self, user: str, rel: str, *, owner: str | None = None) -> str:
        with self._measure("trash", rel, user):
            root, _canon_rel = self._sandbox(user, owner, rel)
            trashed_rel = trash_move(root, rel)
            # TODO(ADR-002 шаг 5): UPDATE fs.nodes.deleted_at (§5.2) — FsRepository
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
            root, _rel = self._sandbox(user, owner, "")
            return list_repos(str(root), rel_paths, timeout=self._config.git_timeout)

    # ── Статистика (для refresh_home-фасада workspace) ──────

    def folder_stats(self, path: Path) -> tuple[int, int]:
        return folder_stats(path)


class _RetryProvision(Exception):
    """Внутренний сигнал: INSERT не закрепился — повторить флоу с fast path."""


def _is_unique_violation(exc: BaseException) -> bool:
    """psycopg UniqueViolation (23505): UNIQUE(login/unix_uid/home_path)."""
    current: BaseException | None = exc
    while current is not None:
        if getattr(current, "pgcode", None) == "23505":
            return True
        current = current.__cause__
    return False

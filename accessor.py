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
from .homes import account_in_passwd, ensure_nested, ensure_unix_home, list_home, own_path

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
        notification: Any | None = None,
    ) -> None:
        self._config = config
        self._log = log
        self._database = database
        self._auth = auth
        self._accounts = UnixAccountsRepository(database) if database is not None else None
        from .repository import FsRepository

        self._repo = FsRepository(database, log) if database is not None else None
        self._notification = notification

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

    def _sandbox(self, user: str, owner: str | None, rel: str, need: str = "viewer") -> tuple[Path, str]:
        """Песочница операции: (канонический корень, канонический rel).

        Порядок обязательный (аксиома §5.4): join_rel (песочница) →
        канонический rel → ACL-машина → диск. Сырой rel от клиента в ACL
        не попадает никогда — иначе LIKE-префикс `shared/%` открывает
        `shared/../secret` (находка 2 Литы). Машина смотрит только uuid;
        unix-UID ей не виден (ревизия 6)."""
        requester_id, requester_name = self._identity(user)
        owner_id, owner_name = (requester_id, requester_name)
        if owner is not None:
            owner_id, owner_name = self._identity(owner)
        root = self._root_for(owner_name).resolve()
        resolved = join_rel(root, rel)
        canon_rel = resolved.relative_to(root).as_posix()
        if canon_rel == ".":
            canon_rel = ""
        if owner_id != requester_id:
            self._require_grant(requester_id, owner_id, canon_rel, need)
        return root, canon_rel

    def _require_grant(self, requester: str, owner: str, canon_rel: str, need: str) -> None:
        """Гибридная проверка §5.4: префикс-предки × самый специфичный грант.

        Никакого админ-обхода (§5.7): ни одна роль не проходит машину мимо грантов."""
        from .repository import LEVELS

        # write-операции передают editor; чтение — viewer (алиас read → viewer)
        need_level = "editor" if need in {"editor", "write"} else "viewer"
        if self._repo is None:
            raise FsError("access denied", "ACL_DENIED")
        level = self._repo.effective_level(owner, canon_rel, requester)
        if level is None or LEVELS[level] < LEVELS[need_level]:
            self._log.warning(
                "fs_acl_denied",
                extra={
                    "user_id": requester,
                    "owner": owner,
                    "rel_path": canon_rel[:512],
                    "required_level": need,
                },
            )
            raise FsError("access denied", "ACL_DENIED")

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
        # 1. fast path: запись есть. passwd мог сгореть с образом — чиним useradd.
        existing = self._accounts.find_by_user_id(user_id)
        if existing:
            self._repair_passwd_if_missing(existing, username, require_useradd=True)
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
            root, _canon_rel = self._sandbox(user, owner, rel, need="editor")
            uid = self._uid_for_chown(owner or user)
            # raw rel: lstat-guard §10 п.3 обязан видеть symlink-компоненты
            return ensure_nested(str(root), rel, kind, uid)

    def _repair_passwd_if_missing(
        self,
        account: dict[str, Any],
        username: str,
        *,
        require_useradd: bool = False,
    ) -> None:
        """Строка в unix_accounts есть, /etc/passwd пуст → повторный useradd.

        mkdir/touch/write не ждут passwd: числовой chown достаточен.
        require_useradd=True (ensure_home) — падаем, если useradd снова не смог."""
        uid = int(account["unix_uid"])
        login = str(account["login"])
        if account_in_passwd(uid, login):
            return
        self._log.warning(
            "unix_account_missing_passwd",
            extra={"unix_uid": uid, "login": login},
        )
        try:
            ensure_unix_home(uid, login, username, self._config.home_root)
        except FsError as exc:
            self._log.error(
                "unix_account_useradd_failed",
                extra={"unix_uid": uid, "login": login, "error": str(exc)[:200]},
            )
            if require_useradd or exc.code == "UNIX_ACCOUNT_MISMATCH":
                raise

    def _uid_for_chown(self, user: str) -> int:
        """UID владельца для chown созданных путей. Нет привязки → uid воркера:
        привязка тома для v1 не критична, воркер пишет своим uid."""
        import os

        if self._accounts is None:
            return os.getuid()
        user_id, username = self._identity(user)
        account = self._accounts.find_by_user_id(user_id)
        if not account:
            return os.getuid()
        self._repair_passwd_if_missing(account, username)
        return int(account["unix_uid"])

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
            root, _canon_rel = self._sandbox(user, owner, rel, need="editor")
            # raw rel в write_file: O_NOFOLLOW + lstat-guard (§10 п.3)
            path = write_file(root, rel, content)
            own_path(path, self._uid_for_chown(owner or user))
            return {"rel_path": _canon_rel, "size": len(content)}

    def move(self, user: str, src: str, dest_dir: str, *, owner: str | None = None) -> str:
        with self._measure("move", src, user):
            # Двухпутевая проверка (§4, находка 3): ACL на ОБА пути, оба ≥ уровня
            root, canon_src = self._sandbox(user, owner, src, need="editor")
            _dest_root, _canon_dest = self._sandbox(user, owner, dest_dir, need="editor")
            new_rel = move_into(root, src, dest_dir)
            self._registry_after_move(user, "move", src, new_rel)
            return new_rel

    def rename(self, user: str, src: str, new_name: str, *, owner: str | None = None) -> str:
        with self._measure("rename", src, user):
            # Однопутевая проверка (§4): dest в том же каталоге, каталог не меняется
            root, _canon_src = self._sandbox(user, owner, src, need="editor")
            new_rel = rename_path(root, src, new_name)
            self._registry_after_move(user, "rename", src, new_rel)
            return new_rel

    def _registry_after_move(self, user: str, operation: str, old_rel: str, new_rel: str) -> None:
        """UPDATE fs.nodes после диска (§5.2): rename/move — path; из Trash — restore.

        Ошибка UPDATE не откатывает диск (§5.2 п.4): WARN + метрика,
        рассинхронизация самотерапевтична следующей операцией владельца."""
        if self._repo is None:
            return
        from .metrics import fs_nodes_update_failed

        owner_id, _username = self._identity(user)
        try:
            updated = self._repo.update_path(owner_id, old_rel, new_rel)
            if updated:
                self._log.info(
                    "fs_nodes_registry_updated",
                    extra={"operation": operation, "path": new_rel[:512]},
                )
        except Exception as exc:
            fs_nodes_update_failed.labels(operation=operation).inc()
            self._log.warning(
                "fs_nodes_update_failed",
                extra={"operation": operation, "error_type": exc.__class__.__name__},
            )

    def trash(self, user: str, rel: str, *, owner: str | None = None) -> str:
        with self._measure("trash", rel, user):
            root, _canon_rel = self._sandbox(user, owner, rel, need="editor")
            trashed_rel = trash_move(root, rel)
            # destination в Trash создаётся воркером и получателем не проверяется (§4)
            self._registry_trashed(user, rel)
            return trashed_rel

    def _registry_trashed(self, user: str, rel: str) -> None:
        if self._repo is None:
            return
        from .metrics import fs_nodes_update_failed

        owner_id, _username = self._identity(user)
        try:
            if self._repo.mark_deleted(owner_id, rel):
                self._log.info(
                    "fs_nodes_registry_updated",
                    extra={"operation": "trash", "path": rel[:512]},
                )
        except Exception as exc:
            fs_nodes_update_failed.labels(operation="trash").inc()
            self._log.warning(
                "fs_nodes_update_failed",
                extra={"operation": "trash", "error_type": exc.__class__.__name__},
            )

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

    # ── Shareable roots (§5.6) — внутренние методы для workspace ──

    def register_shareable_root(self, user: str, rel: str) -> dict[str, Any]:
        """Линковка воркспейса: exists + узел c is_shareable_root=TRUE (§5.6.2).

        rel='' → NOT_SHAREABLE (гранта на весь home не существует как класс).
        Путь не существует → NOT_FOUND (линковка несуществующего невозможна).
        Идемпотентен: повторная линковка возвращает флаг в TRUE."""
        with self._measure("register_shareable_root", rel, user):
            user_id, _username = self._identity(user)
            rel = rel.strip().lstrip("/").rstrip("/")
            if not rel:
                raise FsError("home root is not shareable", "NOT_SHAREABLE")
            root, canon_rel = self._sandbox(user, None, rel, need="editor")
            path = root / canon_rel if canon_rel else root
            if not path.exists():
                raise FsError("path not found", "NOT_FOUND")
            if self._repo is None:
                raise FsError("registry unavailable", "FS_ERROR")
            node_type = "dir" if path.is_dir() else "file"
            existing = self._repo.find_node(user_id, canon_rel)
            already = bool(existing and existing["is_shareable_root"])
            if already:
                node_uuid = str(existing["node_uuid"])
            else:
                if not self._repo.mark_shareable_root(user_id, canon_rel):
                    node_uuid = self._repo.ensure_node(user_id, canon_rel, node_type, True)
                else:
                    node_uuid = str(self._repo.find_node(user_id, canon_rel)["node_uuid"])
            self._log.info(
                "fs_nodes_registry_updated",
                extra={"operation": "register", "node_uuid": node_uuid, "path": canon_rel[:512]},
            )
            return {"node_uuid": node_uuid, "path": canon_rel, "already_registered": already}

    def unregister_shareable_root(self, user: str, rel: str) -> dict[str, Any]:
        """Отлинковка: флаг снимается, узел и гранты живут (политика §5.6.3).

        Идемпотентный no-op, если узла/флага нет → unmarked: False."""
        with self._measure("unregister_shareable_root", rel, user):
            user_id, _username = self._identity(user)
            rel = rel.strip().lstrip("/").rstrip("/")
            if not rel:
                raise FsError("home root is not shareable", "NOT_SHAREABLE")
            root, canon_rel = self._sandbox(user, None, rel, need="editor")
            if self._repo is None:
                raise FsError("registry unavailable", "FS_ERROR")
            node = self._repo.find_node(user_id, canon_rel)
            unmarked = self._repo.clear_shareable_root(user_id, canon_rel)
            node_uuid = str(node["node_uuid"]) if node else None
            if unmarked:
                self._log.info(
                    "fs_nodes_registry_updated",
                    extra={"operation": "unregister", "node_uuid": node_uuid, "path": canon_rel[:512]},
                )
            return {"node_uuid": node_uuid, "unmarked": unmarked}

    # ── Шаринг: share_* / list_shared / resolve_entities ────

    def share_add(self, user: str, path: str, grantees: list[dict[str, str]], level: str) -> dict[str, Any]:
        """Выдать доступ (§8.1): валидации до INSERT, идемпотентно, added/skipped.

        Порядок: canon rel → NOT_SHAREABLE-проверки → узел → квота → INSERT →
        COMMIT → уведомления по added[] (graceful, §8.2 ADR-003)."""
        from .errors import FS_QUOTA_EXCEEDED, NOT_SHAREABLE
        from .metrics import fs_share_grants_added, fs_share_operations_total
        from .repository import GRANT_QUOTA, LEVELS

        try:
            if level not in LEVELS:
                raise FsError("invalid level", "INVALID_NAME")
            owner_id, owner_name = self._identity(user)
            # share_* — только владелец (§5.7): requester обязан быть owner
            self._own_scope(user, owner_id)
            if not grantees or not isinstance(grantees, list):
                raise FsError("grantees required", "VALIDATION")
            try:
                clean = [{"type": str(g["type"]), "id": str(g["id"])} for g in grantees]
            except (KeyError, TypeError) as exc:
                raise FsError("grantees required", "VALIDATION") from exc
            if any(g["type"] not in {"user", "group"} for g in clean):
                raise FsError("invalid grantee type", "VALIDATION")
            root, canon_rel = self._sandbox(user, None, path, need="editor")
            # Валидация §5.6.3: rel='' → NOT_SHAREABLE немедленно; иначе — живой корень
            if not canon_rel:
                raise FsError("home root is not shareable", NOT_SHAREABLE)
            if self._repo is None:
                raise FsError("registry unavailable", "FS_ERROR")
            if not self._repo.shareable_root_exists(owner_id, canon_rel):
                raise FsError("path is not under a linked workspace root", NOT_SHAREABLE)
            disk_path = root / canon_rel
            if not disk_path.exists():
                raise FsError("path not found", "NOT_FOUND")
            node_uuid = self._repo.ensure_node(owner_id, canon_rel, "dir" if disk_path.is_dir() else "file", False)
            # Самогрант и существующие — skipped; новые — INSERT (§20.6)
            existing = self._repo.grant_keys(node_uuid)
            skipped: list[dict[str, str]] = []
            fresh: list[dict[str, str]] = []
            for grantee in clean:
                key = (grantee["type"], grantee["id"])
                if grantee["type"] == "user" and grantee["id"] == owner_id:
                    skipped.append({**grantee, "reason": "self_grant"})
                elif key in existing:
                    skipped.append({**grantee, "reason": "already_granted"})
                else:
                    fresh.append(grantee)
            if fresh and self._repo.quota_count(owner_id) + len(fresh) > GRANT_QUOTA:
                raise FsError("grant quota exceeded", FS_QUOTA_EXCEEDED)
            added_keys = self._repo.insert_grants(node_uuid, fresh, level, owner_id)
            info = self._repo.grantees_info(added_keys + [dict(g) for g in skipped])
            added = [self._grantee_row(g, info, level) for g in added_keys]
            skipped_rows = [
                {
                    "grantee_type": g["type"],
                    "grantee_id": g["id"],
                    "name": info.get((g["type"], g["id"]), {}).get("name", ""),
                    "reason": g["reason"],
                }
                for g in skipped
            ]
            fs_share_grants_added.labels(outcome="added").inc(len(added_keys))
            fs_share_grants_added.labels(outcome="skipped").inc(len(skipped_rows))
        except Exception:
            fs_share_operations_total.labels(operation="share_add", outcome="error").inc()
            raise
        fs_share_operations_total.labels(operation="share_add", outcome="ok").inc()
        self._log.info(
            "fs_share_changed",
            extra={
                "operation": "share_add", "node_uuid": node_uuid,
                "added": len(added_keys), "skipped": len(skipped_rows), "actor": owner_name,
            },
        )
        # Уведомления — только по added[] (вердикт §20.6), graceful (§8.2 ADR-003)
        self._notify_share_grant(
            owner_id=owner_id,
            owner_name=owner_name,
            node_uuid=node_uuid,
            node_name=canon_rel.rsplit("/", 1)[-1],
            node_kind="dir" if disk_path.is_dir() else "file",
            level=level,
            added=added,
        )
        return {"added": added, "skipped": skipped_rows}

    @staticmethod
    def _grantee_row(grantee: dict[str, str], info: dict[Any, Any], level: str) -> dict[str, Any]:
        meta = info.get((grantee["type"], grantee["id"]), {})
        return {
            "grantee_type": grantee["type"],
            "grantee_id": grantee["id"],
            "name": meta.get("name", ""),
            "active": bool(meta.get("active", True)),
            "level": level,
        }

    def share_remove(self, user: str, path: str, grantee_type: str, grantee_id: str) -> dict[str, Any]:
        """Отозвать доступ (§8.1): по node_uuid+grantee, мгновенный эффект (§18)."""
        from .metrics import fs_share_operations_total

        owner_id, owner_name = self._identity(user)
        try:
            self._own_scope(user, owner_id)
            root, canon_rel = self._sandbox(user, None, path, need="editor")
            removed = self._repo.share_remove(owner_id, canon_rel, grantee_type, grantee_id)
        except Exception:
            fs_share_operations_total.labels(operation="share_remove", outcome="error").inc()
            raise
        fs_share_operations_total.labels(operation="share_remove", outcome="ok").inc()
        self._log.info(
            "fs_share_changed",
            extra={
                "operation": "share_remove", "path": canon_rel[:512],
                "grantee_type": grantee_type, "grantee_id": grantee_id, "actor": owner_name,
            },
        )
        return {"removed": removed}

    def share_list(self, user: str, path: str) -> dict[str, Any]:
        """ACL-таблица пути — только владелец (§8.1); active из auth."""
        from .metrics import fs_share_operations_total

        owner_id, _owner_name = self._identity(user)
        try:
            self._own_scope(user, owner_id)
            root, canon_rel = self._sandbox(user, None, path, need="viewer")
            items = self._repo.share_list(owner_id, canon_rel) if canon_rel else []
        except Exception:
            fs_share_operations_total.labels(operation="share_list", outcome="error").inc()
            raise
        fs_share_operations_total.labels(operation="share_list", outcome="ok").inc()
        return {
            "items": [
                {
                    "grantee_type": row["grantee_type"],
                    "grantee_id": row["grantee_id"],
                    "name": row["name"],
                    "active": bool(row["active"]),
                    "level": row["level"],
                    "created_at": row["created_at"].isoformat() if row.get("created_at") else None,
                }
                for row in items
            ],
        }

    def list_shared(self, user: str) -> dict[str, Any]:
        """Корни, расшаренные на меня (§9): fs.nodes × fs.acl, deleted_at фильтр."""
        from .metrics import fs_share_operations_total

        me, _me_name = self._identity(user)
        try:
            items = self._repo.list_shared(me)
        except Exception:
            fs_share_operations_total.labels(operation="list_shared", outcome="error").inc()
            raise
        fs_share_operations_total.labels(operation="list_shared", outcome="ok").inc()
        return {
            "items": [
                {
                    "owner_user_id": row["owner_user_id"],
                    "owner_username": row["owner_username"],
                    "path": row["path"],
                    "name": row["display_name"],
                    "level": row["level"],
                }
                for row in items
            ],
        }

    def resolve_entities(self, user: str, inputs: list[str]) -> dict[str, Any]:
        """AD-подобный batch-поиск (§8.2): resolved|unresolved|ambiguous.

        Не только владелец: диалог Add шаринга нужен обычному пользователю (§7)."""
        from .errors import FsError
        from .metrics import fs_share_operations_total

        self._identity(user)
        if len(inputs) > self._config.max_resolve_inputs:
            raise FsError("too many inputs", "VALIDATION")
        try:
            results = []
            for value in inputs[: self._config.max_resolve_inputs]:
                candidates = self._repo.resolve_one(str(value).strip())
                if not candidates:
                    status = "unresolved"
                elif len(candidates) == 1:
                    status = "resolved"
                else:
                    status = "ambiguous"
                results.append({"input": value, "status": status, "candidates": candidates})
        except Exception:
            fs_share_operations_total.labels(operation="resolve_entities", outcome="error").inc()
            raise
        fs_share_operations_total.labels(operation="resolve_entities", outcome="ok").inc()
        return {"results": results}

    def _own_scope(self, user: str, owner_id: str) -> None:
        """share_* — только владелец узла (§5.7); чужой → ACL_DENIED + событие."""
        requester_id, _name = self._identity(user)
        if requester_id != owner_id:
            raise FsError("only the owner manages access", "ACL_DENIED")

    def _notify_share_grant(
        self,
        *,
        owner_id: str,
        owner_name: str,
        node_uuid: str,
        node_name: str,
        node_kind: str,
        level: str,
        added: list[dict[str, Any]],
    ) -> None:
        """Хук ADR-003 §8.4: N ≤ 50 → send; > 50/Everyone → distribute; graceful."""
        if not added:
            return
        if self._notification is None:
            self._log.warning(
                "fs_notification_failed",
                extra={"node_uuid": node_uuid, "recipients": len(added), "error_type": "NoModule"},
            )
            return
        try:
            user_ids = [g["grantee_id"] for g in added if g["grantee_type"] == "user"]
            group_ids = [g["grantee_id"] for g in added if g["grantee_type"] == "group"]
            everyone = self._repo.everyone_group_id() if self._repo is not None else None
            scope: dict[str, Any]
            if everyone and everyone in group_ids:
                # Everyone — неявное membership: рассылка всем активным (§5.5, §6.1)
                scope = {"kind": "all_active"}
            else:
                members = self._repo.group_member_ids(group_ids) if self._repo is not None else []
                user_ids = list(dict.fromkeys(user_ids + members))
                scope = {"kind": "explicit", "user_ids": user_ids}
            payload = {
                "actor_id": owner_id,
                "actor_name": owner_name,
                "node_name": node_name,
                "node_uuid": node_uuid,
                "node_kind": node_kind,
                "level": level,
            }
            bucket = str(__import__("uuid").uuid4())
            threshold = int(getattr(self._notification, "distribute_threshold", 50) or 50)
            if scope["kind"] == "explicit" and len(user_ids) <= threshold:
                self._notification.send(
                    user_ids, "share_grant", payload, bucket=bucket, caller="fs",
                )
            else:
                self._notification.distribute(
                    "share_grant", payload, scope, bucket=bucket, caller="fs",
                )
        except Exception as exc:
            # Уведомление не валит share_add: WARN + метрика notification (§8.2)
            self._log.warning(
                "fs_notification_failed",
                extra={
                    "node_uuid": node_uuid,
                    "recipients": len(added),
                    "error_type": exc.__class__.__name__,
                },
            )


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

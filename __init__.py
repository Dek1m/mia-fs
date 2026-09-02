"""FS Module — диск пользователя, песочница и identity-based ACL (ADR-002).

Использование:
    app.load_module("fs")

    state.fs.ensure_home(user)
    state.fs.list(user, "projects", include_size=True)

Workspace — тонкий фасад над state.fs (§3.1).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from modules_system.module_base import ModuleBase, ModuleMeta

from .accessor import FsAccessor
from .config import FsConfig
from .errors import FsError
from .provider import FsProvider
from .schema import FS_DB_SCHEMA, FS_SCHEMA

__all__ = [
    "FsModule",
    "FsAccessor",
    "FsProvider",
    "FsConfig",
    "FsError",
    "FS_SCHEMA",
]

MODULE_VERSION = "0.1.0"


class FsModule(ModuleBase):
    """Домен fs: песочница /home/{username} as-is, state.fs, права fs:*."""

    @property
    def name(self) -> str:
        return "fs"

    @property
    def version(self) -> str:
        return MODULE_VERSION

    @property
    def meta(self) -> ModuleMeta:
        # notification — уведомления о share_add (ADR-003 §8); SQL-реестр fs.nodes/fs.acl
        # требует db+auth. Порядок загрузки выводится topo из зависимостей (§15).
        return ModuleMeta(
            permissions={
                "fs:read": "Чтение своего диска и расшаренного на меня",
                "fs:write": "Запись в свой диск и расшаренное с уровнем editor",
                "fs:share": "Управление доступом к своим папкам (share/resolve)",
            },
            cache_rules={},
            timeout_defaults={
                "ensure_home": 10.0,
                "list": 10.0,
                "stat": 5.0,
                "read": 30.0,
                "write": 30.0,
                "mkdir": 10.0,
                "touch": 10.0,
                "move": 30.0,
                "rename": 30.0,
                "trash": 30.0,
                "git_status": 15.0,
                "list_shared": 10.0,
                "share_list": 10.0,
                "share_add": 10.0,
                "share_remove": 10.0,
                "resolve_entities": 10.0,
            },
            dependencies=["db", "auth", "log", "notification"],
        )

    def __init__(self, config: FsConfig | None = None) -> None:
        self._config = config or FsConfig.from_env()
        self._log: Any | None = None
        self._accessor: FsAccessor | None = None
        self._provider: FsProvider | None = None

    def on_load(self, state: Any) -> None:
        """Вешает state.fs, регистрирует FS_SCHEMA в auth. Без DDL (belle ADR-004)."""
        self._log = state.log
        from modules.db.provider import DatabaseProvider

        database = state.services.resolve(DatabaseProvider)
        auth = None
        try:
            from modules.auth.provider import AuthProvider

            auth = state.services.resolve(AuthProvider)
        except Exception:
            auth = None
        self._accessor = FsAccessor(self._config, self._log, database, auth, getattr(state, "notification", None))
        state.fs = self._accessor
        self._provider = FsProvider(self._accessor, self._log)
        state.services.register(FsProvider, self._provider)
        self._register_auth_schema(state)
        self._log.info("fs_module_loaded", extra={"version": self.version})

    def apply_schema(self, state: Any) -> None:
        """DDL fs.nodes → fs.acl (порядок FK). Только migrate."""
        from modules.db.provider import DatabaseProvider

        database = state.services.resolve(DatabaseProvider)
        database.register_schema(
            "fs",
            dict(FS_DB_SCHEMA),
            schema_name="fs",
            ddl_dir=str(Path(__file__).resolve().parent / "ddl"),
        )

    def on_unload(self) -> None:
        if self._log is not None:
            self._log.info("fs_module_unloaded", extra={"version": self.version})
        self._provider = None
        self._accessor = None
        self._log = None

    def _register_auth_schema(self, state: Any) -> None:
        """Permissions fs:* живут в auth. Нет реестра — фасад всё равно работает."""
        try:
            from modules.auth.provider import AuthProvider

            auth = state.services.resolve(AuthProvider)
            if auth.registry is not None:
                auth.registry.register_sync("fs", FS_SCHEMA, is_builtin=False)
        except Exception as exc:
            if self._log is not None:
                self._log.debug("fs_auth_schema_skipped", extra={"error": str(exc)})

"""FsProvider — RPC fs.* (ADR-002 §4).

type="io" (диск — I/O). owner-only каркас: ACL-машина — шаг 5 (ревью Литы),
чужой owner уже сейчас fail closed (ACL_DENIED).
"""
from __future__ import annotations

from typing import Any

from core.task_decorator import task

from .accessor import FsAccessor
from .errors import FsError

__all__ = ["FsProvider"]


class FsProvider:
    """Дисковые RPC в песочнице владельца. SQL отсутствует (шаг 5 добавит реестр)."""

    def __init__(self, accessor: FsAccessor, log: Any = None) -> None:
        self._accessor = accessor
        self._log = log

    def _user(self, session_user_id: str | None) -> str:
        if not session_user_id:
            raise FsError("authentication required", "AUTH_ERROR")
        return session_user_id

    @task(
        type="io",
        api=True,
        permission="fs:read",
        name="ensure_home",
        description="Создать unix-пользователя и ~/ если ещё нет → {home, unix_name}",
        args={},
        return_type="dict",
    )
    def ensure_home(self, _session_user_id: str | None = None) -> dict[str, Any]:
        return self._accessor.ensure_home(self._user(_session_user_id))

    @task(
        type="io",
        api=True,
        permission="fs:read",
        name="list",
        description="Листинг каталога (своего или расшаренного, ACL — шаг 5)",
        args={"rel_path": "str", "owner": "str", "include_hidden": "bool", "include_size": "bool"},
        return_type="dict",
    )
    def list(
        self,
        rel_path: str = "",
        owner: str | None = None,
        include_hidden: bool = False,
        include_size: bool = False,
        _session_user_id: str | None = None,
    ) -> dict[str, Any]:
        user = self._user(_session_user_id)
        items = self._accessor.list(
            user, rel_path,
            include_hidden=include_hidden, include_size=include_size, owner=owner,
        )
        return {"home": self._accessor.home_for(owner or user), "items": items}

    @task(
        type="io",
        api=True,
        permission="fs:read",
        name="stat",
        description="kind + child_count/size пути",
        args={"rel_path": "str", "owner": "str"},
        return_type="dict",
    )
    def stat(
        self,
        rel_path: str,
        owner: str | None = None,
        _session_user_id: str | None = None,
    ) -> dict[str, Any]:
        return self._accessor.stat(self._user(_session_user_id), rel_path, owner=owner)

    @task(
        type="io",
        api=True,
        permission="fs:read",
        name="read",
        description="Содержимое файла b64, лимит FS_MAX_WRITE_BYTES",
        args={"rel_path": "str", "owner": "str"},
        return_type="dict",
    )
    def read(
        self,
        rel_path: str,
        owner: str | None = None,
        _session_user_id: str | None = None,
    ) -> dict[str, Any]:
        return self._accessor.read(self._user(_session_user_id), rel_path, owner=owner)

    @task(
        type="io",
        api=True,
        permission="fs:write",
        name="write",
        description="Запись/перезапись файла",
        args={"rel_path": "str", "content_b64": "str", "owner": "str"},
        return_type="dict",
    )
    def write(
        self,
        rel_path: str,
        content_b64: str,
        owner: str | None = None,
        _session_user_id: str | None = None,
    ) -> dict[str, Any]:
        return self._accessor.write(self._user(_session_user_id), rel_path, content_b64, owner=owner)

    @task(
        type="io",
        api=True,
        permission="fs:write",
        name="mkdir",
        description="Создать папку (ensure_nested kind=folder)",
        args={"rel_path": "str", "owner": "str"},
        return_type="dict",
    )
    def mkdir(
        self,
        rel_path: str,
        owner: str | None = None,
        _session_user_id: str | None = None,
    ) -> dict[str, Any]:
        return self._accessor.ensure_nested(self._user(_session_user_id), rel_path, "folder", owner=owner)

    @task(
        type="io",
        api=True,
        permission="fs:write",
        name="touch",
        description="Создать файл (ensure_nested kind=file)",
        args={"rel_path": "str", "owner": "str"},
        return_type="dict",
    )
    def touch(
        self,
        rel_path: str,
        owner: str | None = None,
        _session_user_id: str | None = None,
    ) -> dict[str, Any]:
        return self._accessor.ensure_nested(self._user(_session_user_id), rel_path, "file", owner=owner)

    @task(
        type="io",
        api=True,
        permission="fs:write",
        name="move",
        description="Перемещение внутри home; обновление fs.nodes — шаг 5",
        args={"src": "str", "dest_dir": "str", "owner": "str"},
        return_type="dict",
    )
    def move(
        self,
        src: str,
        dest_dir: str,
        owner: str | None = None,
        _session_user_id: str | None = None,
    ) -> dict[str, Any]:
        user = self._user(_session_user_id)
        new_rel = self._accessor.move(user, src, dest_dir, owner=owner)
        return {"rel_path": new_rel}

    @task(
        type="io",
        api=True,
        permission="fs:write",
        name="rename",
        description="Переименование; обновление fs.nodes — шаг 5",
        args={"src": "str", "new_name": "str", "owner": "str"},
        return_type="dict",
    )
    def rename(
        self,
        src: str,
        new_name: str,
        owner: str | None = None,
        _session_user_id: str | None = None,
    ) -> dict[str, Any]:
        user = self._user(_session_user_id)
        new_rel = self._accessor.rename(user, src, new_name, owner=owner)
        return {"rel_path": new_rel}

    @task(
        type="io",
        api=True,
        permission="fs:write",
        name="trash",
        description="Перенос в ~/Trash/belle/{utc}/{rel}; fs.nodes.deleted_at — шаг 5",
        args={"rel_path": "str", "owner": "str"},
        return_type="dict",
    )
    def trash(
        self,
        rel_path: str,
        owner: str | None = None,
        _session_user_id: str | None = None,
    ) -> dict[str, Any]:
        user = self._user(_session_user_id)
        trashed_rel = self._accessor.trash(user, rel_path, owner=owner)
        return {"rel_path": trashed_rel}

    @task(
        type="io",
        api=True,
        permission="fs:read",
        name="git_status",
        description="Git overlay по путям внутри своей песочницы",
        args={"rel_paths": "list"},
        return_type="dict",
    )
    def git_status(
        self,
        rel_paths: list[str],
        owner: str | None = None,
        _session_user_id: str | None = None,
    ) -> dict[str, Any]:
        user = self._user(_session_user_id)
        return {"items": self._accessor.git_repos(user, rel_paths, owner=owner)}

    @task(
        type="io",
        api=True,
        permission="fs:read",
        name="list_shared",
        description="Корни, расшаренные на меня (fs.nodes × fs.acl)",
        args={},
        return_type="dict",
    )
    def list_shared(self, _session_user_id: str | None = None) -> dict[str, Any]:
        self._user(_session_user_id)
        # TODO(ADR-002 шаг 5): SELECT по fs.nodes × fs.acl с membership + Everyone (§9);
        # до ACL-машины грантов не существует — честный пустой список.
        #
        # Ленивая регистрация узла — один CTE, не INSERT+SELECT двумя стейтментами.
        # Предикат deleted_at IS NULL в conflict_target ОБЯЗАТЕЛЕН: без него PG
        # не найдёт арбитра частичного индекса nodes_owner_path_live_idx (§5.0):
        #   WITH ins AS (
        #       INSERT INTO fs.nodes (owner_user_id, path, node_type, display_name)
        #       VALUES (:owner, :path, :type, basename(:path))
        #       ON CONFLICT (owner_user_id, path) WHERE deleted_at IS NULL
        #       DO NOTHING RETURNING node_uuid)
        #   SELECT node_uuid FROM ins
        #   UNION ALL
        #   SELECT node_uuid FROM fs.nodes
        #   WHERE owner_user_id = :owner AND path = :path AND deleted_at IS NULL
        #   LIMIT 1;
        #
        # Арбитраж повторных грантов ДОСЛОВНО повторяет выражение
        # acl_unique_grant_idx (§5.1), иначе ON CONFLICT не найдёт арбитр:
        #   ON CONFLICT (node_uuid, grantee_type, COALESCE(grantee_user_id, grantee_group_id))
        #   DO NOTHING;
        return {"items": []}

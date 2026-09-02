"""FsProvider — RPC fs.* (ADR-002 §4).

type="io" (диск — I/O). ACL-машина §5.4 на каждом затрагиваемом пути;
share_* — только владелец (§5.7).
"""
from __future__ import annotations

from typing import Any

from core.task_decorator import task

from .accessor import FsAccessor
from .errors import FsError

__all__ = ["FsProvider"]


class FsProvider:
    """Дисковые RPC в песочнице владельца + identity-based ACL."""

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
        description="Создать unix-аккаунт и ~/ если ещё нет → {home, username, unix_uid, login}",
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
        description="Листинг каталога (своего или расшаренного)",
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
        description="Перемещение внутри home + обновление fs.nodes.path",
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
        description="Переименование + обновление fs.nodes.path/display_name",
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
        description="Перенос в ~/Trash/belle/{utc}/{rel} + fs.nodes.deleted_at",
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
        return self._accessor.list_shared(self._user(_session_user_id))

    @task(
        type="io",
        api=True,
        permission="fs:share",
        name="share_list",
        description="ACL-таблица пути (только владелец)",
        args={"path": "str"},
        return_type="dict",
    )
    def share_list(self, path: str, _session_user_id: str | None = None) -> dict[str, Any]:
        return self._accessor.share_list(self._user(_session_user_id), path)

    @task(
        type="io",
        api=True,
        permission="fs:share",
        name="share_add",
        description="Выдать доступ; идемпотентно → added[]/skipped[] + уведомления",
        args={"path": "str", "grantees": "list", "level": "str"},
        return_type="dict",
    )
    def share_add(
        self,
        path: str,
        grantees: list[dict[str, str]],
        level: str,
        _session_user_id: str | None = None,
    ) -> dict[str, Any]:
        return self._accessor.share_add(self._user(_session_user_id), path, grantees, level)

    @task(
        type="io",
        api=True,
        permission="fs:share",
        name="share_remove",
        description="Отозвать доступ",
        args={"path": "str", "grantee_type": "str", "grantee_id": "str"},
        return_type="dict",
    )
    def share_remove(
        self,
        path: str,
        grantee_type: str,
        grantee_id: str,
        _session_user_id: str | None = None,
    ) -> dict[str, Any]:
        user = self._user(_session_user_id)
        return self._accessor.share_remove(user, path, grantee_type, grantee_id)

    @task(
        type="io",
        api=True,
        permission="fs:share",
        name="resolve_entities",
        description="Batch-проверка существования: uuid/email/phone/username/groupname",
        args={"inputs": "list"},
        return_type="dict",
    )
    def resolve_entities(
        self,
        inputs: list[str],
        _session_user_id: str | None = None,
    ) -> dict[str, Any]:
        return self._accessor.resolve_entities(self._user(_session_user_id), inputs)

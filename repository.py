"""FsRepository — SQL реестра fs.nodes, грантов fs.acl и машины ACL (ADR-002 §5).

Только воркер (шаблон модулей), параметризованный psycopg, никаких f-string.
Вся машина оперирует user_id (uuid); unix-аккаунт (fs.unix_accounts) ей не
виден — ревизия 6, §5.4. Lookup выполняется ТОЛЬКО на каноническом rel,
полученном из resolved.relative_to(root).as_posix() — аксиома §5.4.
"""
from __future__ import annotations

import re
from typing import Any

__all__ = ["FsRepository", "LEVELS", "GRANT_QUOTA"]

LEVELS = {"viewer": 1, "editor": 2}
GRANT_QUOTA = 1000  # живых грантов на владельца (§10 п.2)

# Ленивая регистрация узла — один CTE (ревью Норы); предикат deleted_at IS NULL
# в conflict_target обязателен: без него PG не найдёт арбитр частичного индекса.
# DO UPDATE делает вызов идемпотентным и возвращает флаг в TRUE при повторной
# линковке (§5.0); as_shareable_root=FALSE — чистое «подтверди узел».
_ENSURE_NODE_SQL = """
WITH ins AS (
    INSERT INTO fs.nodes (owner_user_id, path, node_type, display_name, is_shareable_root)
    VALUES (%s::uuid, %s, %s, %s, %s)
    ON CONFLICT (owner_user_id, path) WHERE deleted_at IS NULL
    DO UPDATE SET is_shareable_root = fs.nodes.is_shareable_root OR %s,
                  updated_at = NOW()
    RETURNING node_uuid)
SELECT node_uuid FROM ins
UNION ALL
SELECT node_uuid FROM fs.nodes
WHERE owner_user_id = %s::uuid AND path = %s AND deleted_at IS NULL
LIMIT 1
"""

_FIND_NODE_SQL = (
    "SELECT node_uuid, path, node_type, display_name, is_shareable_root "
    "FROM fs.nodes WHERE owner_user_id = %s::uuid AND path = %s AND deleted_at IS NULL"
)

# Машина §5.4 шаг 3a: кандидаты-узлы — предки целевого пути (точный матч включён).
# Предки собираются в Python: LIKE path||'/%' трактует %/_ в имени как wildcard.
# Дизъюнкта OR n.path = '' нет: гранта на '' не существует как класс (ревизия 5).
_ANCESTORS_SQL = (
    "SELECT node_uuid, path FROM fs.nodes "
    "WHERE owner_user_id = %s::uuid AND deleted_at IS NULL "
    "AND path = ANY(%s::text[])"
)

# Машина §5.4 шаг 3b: самый специфичный грант. Семантика auth повторяется
# дословно: явное membership UNION Everyone-builtin (§5.5).
_BEST_GRANT_SQL = (
    "SELECT n.path, a.level FROM fs.acl a "
    "JOIN fs.nodes n ON n.node_uuid = a.node_uuid "
    "WHERE a.node_uuid = ANY(%s::uuid[]) "
    "AND (a.grantee_user_id = %s::uuid "
    "OR a.grantee_group_id IN ("
    "SELECT group_id FROM auth.user_group_membership WHERE user_id = %s::uuid "
    "UNION "
    "SELECT id FROM auth.groups WHERE name = 'Everyone' AND is_builtin)) "
    "ORDER BY length(n.path) DESC LIMIT 1"
)

# Проверка share_add §5.6.3: путь равен или лежит под живым корнем линковки
_SHAREABLE_ROOT_SQL = (
    "SELECT 1 FROM fs.nodes "
    "WHERE owner_user_id = %s::uuid AND deleted_at IS NULL AND is_shareable_root "
    "AND path = ANY(%s::text[]) LIMIT 1"
)

_MARK_ROOT_SQL = (
    "UPDATE fs.nodes SET is_shareable_root = TRUE, updated_at = NOW() "
    "WHERE owner_user_id = %s::uuid AND path = %s AND deleted_at IS NULL "
    "AND NOT is_shareable_root RETURNING node_uuid"
)

_CLEAR_ROOT_SQL = (
    "UPDATE fs.nodes SET is_shareable_root = FALSE, updated_at = NOW() "
    "WHERE owner_user_id = %s::uuid AND path = %s AND deleted_at IS NULL "
    "AND is_shareable_root RETURNING node_uuid"
)

# rename/move (§5.2): узел живой → обновить путь и имя; гранты не трогаются
_UPDATE_PATH_SQL = (
    "UPDATE fs.nodes SET path = %s, display_name = %s, updated_at = NOW() "
    "WHERE owner_user_id = %s::uuid AND path = %s AND deleted_at IS NULL "
    "RETURNING node_uuid"
)

# restore (движение из Trash на обычный путь): спящий узел оживает
_RESTORE_SQL = (
    "UPDATE fs.nodes SET deleted_at = NULL, path = %s, display_name = %s, "
    "updated_at = NOW() WHERE owner_user_id = %s::uuid AND deleted_at IS NOT NULL "
    "AND path = %s RETURNING node_uuid"
)

_MARK_DELETED_SQL = (
    "UPDATE fs.nodes SET deleted_at = NOW(), updated_at = NOW() "
    "WHERE owner_user_id = %s::uuid AND path = %s AND deleted_at IS NULL "
    "RETURNING node_uuid"
)

# Квота живых грантов владельца (§10 п.2): fs.acl × живые узлы владельца
_QUOTA_SQL = (
    "SELECT count(*) AS grants FROM fs.acl a "
    "JOIN fs.nodes n ON n.node_uuid = a.node_uuid "
    "WHERE n.owner_user_id = %s::uuid AND n.deleted_at IS NULL"
)

_EXISTING_GRANTS_SQL = (
    "SELECT grantee_type, COALESCE(grantee_user_id::text, grantee_group_id::text) AS grantee_id "
    "FROM fs.acl WHERE node_uuid = %s::uuid"
)

# Арбитраж ДОСЛОВНО повторяет выражение acl_unique_grant_idx (§5.1),
# иначе ON CONFLICT не найдёт арбитр. Идемпотентность повторного share_add.
_INSERT_GRANTS_SQL = """
INSERT INTO fs.acl (node_uuid, grantee_type, grantee_user_id, grantee_group_id, level, created_by)
SELECT %s::uuid, g.gtype,
       CASE WHEN g.gtype = 'user' THEN g.gid::uuid END,
       CASE WHEN g.gtype = 'group' THEN g.gid::uuid END,
       %s, %s::uuid
FROM unnest(%s::text[], %s::text[]) AS g(gtype, gid)
ON CONFLICT (node_uuid, grantee_type, COALESCE(grantee_user_id, grantee_group_id)) DO NOTHING
RETURNING grantee_type, COALESCE(grantee_user_id::text, grantee_group_id::text) AS grantee_id
"""

_USERS_INFO_SQL = (
    "SELECT id::text, username AS name, (is_active = TRUE AND NOT is_disabled) AS active "
    "FROM auth.users WHERE id = ANY(%s::uuid[])"
)
_GROUPS_INFO_SQL = (
    "SELECT id::text, name, TRUE AS active FROM auth.groups WHERE id = ANY(%s::uuid[])"
)

_SHARE_LIST_SQL = (
    "SELECT a.grantee_type, COALESCE(a.grantee_user_id::text, a.grantee_group_id::text) AS grantee_id, "
    "COALESCE(u.username, g.name) AS name, "
    "COALESCE(u.is_active = TRUE AND NOT u.is_disabled, TRUE) AS active, "
    "a.level, a.created_at "
    "FROM fs.acl a "
    "JOIN fs.nodes n ON n.node_uuid = a.node_uuid "
    "LEFT JOIN auth.users u ON u.id = a.grantee_user_id "
    "LEFT JOIN auth.groups g ON g.id = a.grantee_group_id "
    "WHERE n.owner_user_id = %s::uuid AND n.path = %s AND n.deleted_at IS NULL "
    "ORDER BY a.created_at"
)

_SHARE_REMOVE_SQL = (
    "DELETE FROM fs.acl a USING fs.nodes n "
    "WHERE a.node_uuid = n.node_uuid "
    "AND n.owner_user_id = %s::uuid AND n.path = %s AND n.deleted_at IS NULL "
    "AND a.grantee_type = %s "
    "AND COALESCE(a.grantee_user_id::text, a.grantee_group_id::text) = %s "
    "RETURNING a.id"
)

# list_shared §9 — дословно по ADR (удалённый узел исчезает: deleted_at IS NULL)
_LIST_SHARED_SQL = (
    "SELECT DISTINCT n.owner_user_id::text AS owner_user_id, u.username AS owner_username, "
    "n.path, n.display_name, a.level "
    "FROM fs.nodes n "
    "JOIN fs.acl a ON a.node_uuid = n.node_uuid "
    "JOIN auth.users u ON u.id = n.owner_user_id "
    "WHERE n.deleted_at IS NULL "
    "AND (a.grantee_user_id = %s::uuid "
    "OR a.grantee_group_id IN ("
    "SELECT group_id FROM auth.user_group_membership WHERE user_id = %s::uuid "
    "UNION "
    "SELECT id FROM auth.groups WHERE name = 'Everyone' AND is_builtin)) "
    "ORDER BY u.username, n.path"
)

# resolve_entities §8.2 — всё exact, без ILIKE-сканов на v1
_RESOLVE_BY_ID_USER_SQL = (
    "SELECT id::text, username AS name, email FROM auth.users WHERE id = %s::uuid"
)
_RESOLVE_BY_ID_GROUP_SQL = (
    "SELECT id::text, name, NULL::varchar AS email FROM auth.groups WHERE id = %s::uuid"
)
_RESOLVE_BY_EMAIL_SQL = (
    "SELECT id::text, username AS name, email FROM auth.users WHERE email = %s"
)
_RESOLVE_BY_PHONE_SQL = (
    "SELECT id::text, username AS name, email FROM auth.users WHERE phone = %s"
)
_RESOLVE_BY_USERNAME_SQL = (
    "SELECT id::text, username AS name, email FROM auth.users WHERE username = %s"
)
_RESOLVE_BY_GROUPNAME_SQL = (
    "SELECT id::text, name, NULL::varchar AS email FROM auth.groups WHERE name = %s"
)

_MEMBERS_SQL = (
    "SELECT user_id::text FROM auth.user_group_membership WHERE group_id = ANY(%s::uuid[])"
)

_EVERYONE_SQL = (
    "SELECT id::text FROM auth.groups WHERE name = 'Everyone' AND is_builtin"
)

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_PHONE_RE = re.compile(r"^[0-9+]{5,}$")

_TRASH_PARTS = 3  # Trash/belle/{stamp}/


class FsRepository:
    """Реестр fs.nodes + гранты fs.acl + машина ACL. SQL только на воркере."""

    def __init__(self, database: Any, log: Any | None = None) -> None:
        self._database = database
        self._log = log

    def fetch(self, sql: str, *params: Any) -> list[dict[str, Any]]:
        return self._database.fetch(sql, *params)

    # ── Реестр fs.nodes ─────────────────────────────────────

    def ensure_node(self, owner: str, path: str, node_type: str, as_shareable_root: bool) -> str:
        rows = self.fetch(
            _ENSURE_NODE_SQL,
            owner, path, node_type, path.rsplit("/", 1)[-1], as_shareable_root,
            as_shareable_root, owner, path,
        )
        return str(rows[0]["node_uuid"])

    def find_node(self, owner: str, path: str) -> dict[str, Any] | None:
        rows = self.fetch(_FIND_NODE_SQL, owner, path)
        return rows[0] if rows else None

    def shareable_root_exists(self, owner: str, rel: str) -> bool:
        prefixes = _self_and_ancestors(rel)
        return bool(prefixes) and bool(self.fetch(_SHAREABLE_ROOT_SQL, owner, prefixes))

    def mark_shareable_root(self, owner: str, rel: str) -> bool:
        """Повторная линковка того же пути → флаг в TRUE (§5.6.1)."""
        return bool(self.fetch(_MARK_ROOT_SQL, owner, rel))

    def clear_shareable_root(self, owner: str, rel: str) -> bool:
        return bool(self.fetch(_CLEAR_ROOT_SQL, owner, rel))

    def update_path(self, owner: str, old_rel: str, new_rel: str) -> bool:
        """rename/move → UPDATE path/display_name; Trash-движение → restore (§5.2)."""
        name = new_rel.rsplit("/", 1)[-1]
        if old_rel == "Trash" or old_rel.startswith("Trash/"):
            candidate = _restore_candidate(old_rel)
            if candidate is None:
                return False
            rows = self.fetch(_RESTORE_SQL, new_rel, name, owner, candidate)
            return bool(rows)
        rows = self.fetch(_UPDATE_PATH_SQL, new_rel, name, owner, old_rel)
        return bool(rows)

    def mark_deleted(self, owner: str, rel: str) -> bool:
        rows = self.fetch(_MARK_DELETED_SQL, owner, rel)
        return bool(rows)

    # ── Машина ACL §5.4 ─────────────────────────────────────

    def effective_level(self, owner: str, canon_rel: str, requester: str) -> str | None:
        """Самый специфичный грант requester'а на канонический rel, или None.

        Кеша нет — отзыв мгновенный (§18); один-два indexed lookup на запрос."""
        prefixes = _self_and_ancestors(canon_rel)
        if not prefixes:
            return None
        uuids = [str(row["node_uuid"]) for row in self.fetch(_ANCESTORS_SQL, owner, prefixes)]
        if not uuids:
            return None
        rows = self.fetch(_BEST_GRANT_SQL, uuids, requester, requester)
        if not rows:
            return None
        return str(rows[0]["level"])

    # ── Шаринг: share_add / share_remove / share_list ───────

    def quota_count(self, owner: str) -> int:
        rows = self.fetch(_QUOTA_SQL, owner)
        return int(rows[0]["grants"]) if rows else 0

    def grant_keys(self, node_uuid: str) -> set[tuple[str, str]]:
        rows = self.fetch(_EXISTING_GRANTS_SQL, node_uuid)
        return {(str(row["grantee_type"]), str(row["grantee_id"])) for row in rows}

    def insert_grants(
        self, node_uuid: str, grantees: list[dict[str, str]], level: str, created_by: str,
    ) -> list[dict[str, str]]:
        """Multi-row INSERT; ON CONFLICT DO NOTHING → вернулись только новые."""
        if not grantees:
            return []
        rows = self.fetch(
            _INSERT_GRANTS_SQL,
            node_uuid, level, created_by,
            [g["type"] for g in grantees], [g["id"] for g in grantees],
        )
        return [{"type": str(r["grantee_type"]), "id": str(r["grantee_id"])} for r in rows]

    def grantees_info(self, keys: list[dict[str, str]]) -> dict[tuple[str, str], dict[str, Any]]:
        """Имена и active для ответов (username|groupname; disabled → active: false)."""
        info: dict[tuple[str, str], dict[str, Any]] = {}
        user_ids = [g["id"] for g in keys if g["type"] == "user"]
        group_ids = [g["id"] for g in keys if g["type"] == "group"]
        for row in self._fetch_many(_USERS_INFO_SQL, user_ids):
            info[("user", str(row["id"]))] = {
                "name": row["name"], "active": bool(row["active"]),
            }
        for row in self._fetch_many(_GROUPS_INFO_SQL, group_ids):
            info[("group", str(row["id"]))] = {
                "name": row["name"], "active": bool(row["active"]),
            }
        return info

    def _fetch_many(self, sql: str, ids: list[str]) -> list[dict[str, Any]]:
        if not ids:
            return []
        return self.fetch(sql, ids)

    def share_list(self, owner: str, rel: str) -> list[dict[str, Any]]:
        return self.fetch(_SHARE_LIST_SQL, owner, rel)

    def share_remove(self, owner: str, rel: str, grantee_type: str, grantee_id: str) -> bool:
        rows = self.fetch(_SHARE_REMOVE_SQL, owner, rel, grantee_type, grantee_id)
        return bool(rows)

    def list_shared(self, me: str) -> list[dict[str, Any]]:
        return self.fetch(_LIST_SHARED_SQL, me, me)

    # ── resolve_entities §8.2 ───────────────────────────────

    def resolve_one(self, value: str) -> list[dict[str, Any]]:
        """Классификация input → кандидаты; >1 совпадения → ambiguous (§8.2)."""
        candidates: list[dict[str, Any]] = []
        if _UUID_RE.match(value):
            candidates += self._as_candidates(self.fetch(_RESOLVE_BY_ID_USER_SQL, value), "user")
            candidates += self._as_candidates(self.fetch(_RESOLVE_BY_ID_GROUP_SQL, value), "group")
        elif "@" in value:
            candidates += self._as_candidates(self.fetch(_RESOLVE_BY_EMAIL_SQL, value), "user")
        elif _PHONE_RE.match(value):
            phone = re.sub(r"\D", "", value)
            candidates += self._as_candidates(self.fetch(_RESOLVE_BY_PHONE_SQL, phone), "user")
        else:
            candidates += self._as_candidates(self.fetch(_RESOLVE_BY_USERNAME_SQL, value), "user")
            candidates += self._as_candidates(self.fetch(_RESOLVE_BY_GROUPNAME_SQL, value), "group")
        return candidates

    @staticmethod
    def _as_candidates(rows: list[dict[str, Any]], entity_type: str) -> list[dict[str, Any]]:
        return [
            {
                "type": entity_type,
                "uuid": str(row["id"]),
                "name": row["name"],
                "email": row["email"],
            }
            for row in rows
        ]

    # ── Уведомления: резолв получателей (§6.1 ADR-003) ──────

    def everyone_group_id(self) -> str | None:
        rows = self.fetch(_EVERYONE_SQL)
        return str(rows[0]["id"]) if rows else None

    def group_member_ids(self, group_ids: list[str]) -> list[str]:
        """Прямое membership (nested-группы в v1 не разворачиваются, §5.4)."""
        if not group_ids:
            return []
        return [str(row["user_id"]) for row in self.fetch(_MEMBERS_SQL, group_ids)]


def _self_and_ancestors(rel: str) -> list[str]:
    """Канонический rel и предки. Пустой rel → [] (гранта на '' нет, NOT_SHAREABLE)."""
    if not rel:
        return []
    parts = rel.split("/")
    return ["/".join(parts[:i]) for i in range(len(parts), 0, -1)]


def _restore_candidate(trashed_rel: str) -> str | None:
    """Trash/belle/{stamp}/{rel} → исходный rel (path спящего узла)."""
    parts = trashed_rel.strip("/").split("/")
    if len(parts) <= _TRASH_PARTS or parts[0] != "Trash" or parts[1] != "belle":
        return None
    return "/".join(parts[_TRASH_PARTS:])

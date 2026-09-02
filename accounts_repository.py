"""UnixAccountsRepository — SQL таблицы fs.unix_accounts (ADR-002 §3.1).

Только воркер (шаблон модулей), параметризованный psycopg, никаких f-string.
Локи в ФИКСИРОВАННОМ ПОРЯДКЕ fs_uid → per-user против дедлоков. Запросы
внутри транзакции провижининга обязаны идти на её соединении (conn=...):
xact-лок виден только на своей сессии.
"""
from __future__ import annotations

from typing import Any

__all__ = ["UnixAccountsRepository"]

# Серийность выдачи UID (стиль belle ADR-004); xact-локи отпускаются на commit
_LOCK_FS_UID_SQL = "SELECT pg_advisory_xact_lock(hashtext('mia.schema.fs_uid'))"
_LOCK_PER_USER_SQL = "SELECT pg_advisory_xact_lock(hashtext('mia.fs.user:' || %s))"

_FIND_SQL = (
    "SELECT user_id, unix_uid, login, home_path, created_at "
    "FROM fs.unix_accounts WHERE user_id = %s::uuid"
)

# Первый пользователь → uid_min (COALESCE(MAX, uid_min - 1) + 1)
_NEXT_UID_SQL = "SELECT COALESCE(MAX(unix_uid), %s - 1) + 1 AS uid FROM fs.unix_accounts"

_INSERT_SQL = (
    "INSERT INTO fs.unix_accounts (user_id, unix_uid, login, home_path) "
    "VALUES (%s::uuid, %s, %s, %s) "
    "ON CONFLICT (user_id) DO NOTHING RETURNING user_id"
)


class UnixAccountsRepository:
    """CRUD привязки user_id → (unix_uid, login, home_path)."""

    def __init__(self, database: Any) -> None:
        self._database = database

    @staticmethod
    def _rows(conn: Any, database: Any, sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        """conn задан → выполнение на его сессии (транзакция провижининга)."""
        if conn is not None:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                if cur.description is None:
                    return []
                columns = [desc[0] for desc in cur.description]
                return [dict(zip(columns, row)) for row in cur.fetchall()]
        return database.fetch(sql, *params)

    def find_by_user_id(self, user_id: str, conn: Any = None) -> dict[str, Any] | None:
        rows = self._rows(conn, self._database, _FIND_SQL, (user_id,))
        return rows[0] if rows else None

    def acquire_provision_locks(self, user_id: str, conn: Any = None) -> None:
        """Оба xact-лока в фиксированном порядке fs_uid → per-user (§3.1).

        Вызывать ВНУТРИ database.transaction(): локи живут до commit/rollback."""
        self._rows(conn, self._database, _LOCK_FS_UID_SQL, ())
        self._rows(conn, self._database, _LOCK_PER_USER_SQL, (user_id,))

    def next_uid(self, uid_min: int, uid_max: int, conn: Any = None) -> int:
        """MAX(unix_uid)+1 под локом; вне [uid_min, uid_max] → UID_EXHAUSTED.

        Самоконсистентен с данными (restore из бэкапа не рассинхронизирует,
        в отличие от sequence — §18); UNIQUE(unix_uid) — последний рубеж."""
        rows = self._rows(conn, self._database, _NEXT_UID_SQL, (uid_min,))
        uid = int(rows[0]["uid"])
        if uid < uid_min or uid > uid_max:
            from .errors import FsError, UID_EXHAUSTED

            raise FsError(f"unix uid pool exhausted [{uid_min}..{uid_max}]", UID_EXHAUSTED)
        return uid

    def insert(self, user_id: str, unix_uid: int, login: str, home_path: str, conn: Any = None) -> bool:
        """INSERT привязки; ON CONFLICT(user_id) DO NOTHING — идемпотентный retry.

        UNIQUE(login/unix_uid/home_path) при гонке в обход лока ловится выше —
        вызывающий делает повторный lookup и возвращает существующую строку."""
        rows = self._rows(conn, self._database, _INSERT_SQL, (user_id, unix_uid, login, home_path))
        return bool(rows)

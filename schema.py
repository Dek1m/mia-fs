"""FS AUTH_SCHEMA — permissions и roles (ADR-002 §7) + DB schema dict.

FS_SCHEMA регистрируется через AuthSchemaRegistry.register_sync("fs", FS_SCHEMA).
fs:manage не вводится окончательно (вердикт Мастера 02.09.2026, §5.7).
DDL fs.nodes/fs.acl — ddl/001_nodes.sql → ddl/002_acl.sql: составные CHECK/UNIQUE
и частичные индексы dict-формат не выражает.
"""
from __future__ import annotations

from typing import Any

__all__ = ["FS_SCHEMA", "FS_DB_SCHEMA"]

FS_SCHEMA: dict[str, list[dict[str, Any]]] = {
    "permissions": [
        {"name": "fs:read", "description": "Чтение своего диска и расшаренного на меня"},
        {"name": "fs:write", "description": "Запись в свой диск и расшаренное с уровнем editor"},
        {"name": "fs:share", "description": "Управление доступом к своим папкам (share/resolve)"},
    ],
    "roles": [
        {
            "name": "fs_user",
            "description": "Обычный пользователь диска",
            "permissions": ["fs:read", "fs:write", "fs:share"],
        },
        {
            "name": "fs_viewer",
            "description": "Только чтение",
            "permissions": ["fs:read"],
        },
    ],
}

# Только имя PG-схемы; таблицы — ddl/001_nodes.sql, ddl/002_acl.sql.
FS_DB_SCHEMA: dict[str, Any] = {
    "schema": "fs",
}

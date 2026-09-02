-- fs.nodes — реестр расшаренных узлов (ADR-002 §5.0, ревизия 5). Порядок: nodes до acl (FK).
CREATE TABLE IF NOT EXISTS fs.nodes (
    node_uuid     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    path          TEXT NOT NULL,               -- относительный путь от ~ владельца
    node_type     VARCHAR(4) NOT NULL CHECK (node_type IN ('dir', 'file')),
    display_name  TEXT NOT NULL,               -- basename(path); переименование обновляет
    is_shareable_root BOOLEAN NOT NULL DEFAULT FALSE,  -- ревизия 5: узел = корень линковки workspace
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at    TIMESTAMPTZ                  -- NOT NULL = живой; заполнено = «удалён» (trash)
);
-- один живой узел на путь владельца (ленивая регистрация идемпотентна)
CREATE UNIQUE INDEX IF NOT EXISTS nodes_owner_path_live_idx
    ON fs.nodes (owner_user_id, path) WHERE deleted_at IS NULL;
-- (owner_user_id, path): list по владельцу (префикс), restore из trash
-- (owner+path при deleted_at IS NOT NULL), ACL-prefix-матч
CREATE INDEX IF NOT EXISTS nodes_owner_path_idx ON fs.nodes (owner_user_id, path);
-- проверка share_add: живые корни линковки владельца (ревизия 5, §5.6)
CREATE INDEX IF NOT EXISTS nodes_shareable_roots_idx
    ON fs.nodes (owner_user_id, path) WHERE deleted_at IS NULL AND is_shareable_root;

-- Догонка сред, накатывавших ревизию 4 (колонки/индекса не было — CREATE TABLE
-- IF NOT EXISTS их не добавляет): идемпотентно, идентично объявлению выше.
ALTER TABLE fs.nodes ADD COLUMN IF NOT EXISTS is_shareable_root BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS nodes_shareable_roots_idx
    ON fs.nodes (owner_user_id, path) WHERE deleted_at IS NULL AND is_shareable_root;

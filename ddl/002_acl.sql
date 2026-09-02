-- fs.acl — гранты по node_uuid (ADR-002 §5.1). Таблица регистрируется уже сейчас:
-- без кода ACL-машины (шаг 5) она не опасна, порядок DDL nodes → acl соблюдён.
CREATE TABLE IF NOT EXISTS fs.acl (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_uuid        UUID NOT NULL REFERENCES fs.nodes(node_uuid) ON DELETE CASCADE,
    grantee_type     VARCHAR(8) NOT NULL CHECK (grantee_type IN ('user', 'group')),
    grantee_user_id  UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    grantee_group_id UUID REFERENCES auth.groups(id) ON DELETE CASCADE,
    level            VARCHAR(8) NOT NULL CHECK (level IN ('viewer', 'editor')),
    created_by       UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT acl_grantee_exclusive CHECK (
        (grantee_user_id IS NULL) <> (grantee_group_id IS NULL)
    )
);
-- одна гранта на пару «узел+получатель» (COALESCE — только уникальным индексом:
-- CONSTRAINT UNIQUE в PostgreSQL не принимает выражения; в ревизии 1 это был дефект DDL)
CREATE UNIQUE INDEX IF NOT EXISTS acl_unique_grant_idx
    ON fs.acl (node_uuid, grantee_type, COALESCE(grantee_user_id, grantee_group_id));
CREATE INDEX IF NOT EXISTS acl_grantee_user_idx  ON fs.acl (grantee_user_id);
CREATE INDEX IF NOT EXISTS acl_grantee_group_idx ON fs.acl (grantee_group_id);

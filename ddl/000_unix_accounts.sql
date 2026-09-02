-- fs.unix_accounts — системная привязка домашней папки к real system UID
-- (ADR-002 ревизия 6, §3.1). Порядок файлов: 000 до 001/002 — читаемость;
-- FK между схемами fs.* нет, но unix_accounts ссылается на auth.users.
CREATE TABLE IF NOT EXISTS fs.unix_accounts (
    user_id    UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    unix_uid   INTEGER UNIQUE NOT NULL,      -- real system UID, диапазон fs.uid_min..fs.uid_max
    login      TEXT   UNIQUE NOT NULL,       -- mia-{8 hex user_id}
    home_path  TEXT   NOT NULL,              -- /home/{username} as-is (регистр/кириллица)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

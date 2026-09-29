-- Phase 6: application settings such as the server's TLS identity.
-- Values flagged secret are stored as references into the secrets table.

CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      BLOB,
    secret_id  TEXT REFERENCES secrets(id) ON DELETE SET NULL,
    updated_at INTEGER NOT NULL
);

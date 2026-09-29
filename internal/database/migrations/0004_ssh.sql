-- Phase 5: SSH key inventory. Private keys are stored as the original file
-- (still encrypted with its passphrase when it had one) inside a sealed secret.

CREATE TABLE ssh_keys (
    id                  TEXT PRIMARY KEY,
    name                TEXT UNIQUE,
    type                TEXT NOT NULL,        -- ssh-ed25519, ecdsa-sha2-nistp256, ssh-rsa, ...
    bits                INTEGER NOT NULL,
    fingerprint_sha256  TEXT NOT NULL UNIQUE,
    public_key          TEXT NOT NULL,        -- authorized_keys line without comment
    comment             TEXT NOT NULL DEFAULT '',
    passphrase_protected INTEGER NOT NULL DEFAULT 0,
    secret_id           TEXT REFERENCES secrets(id) ON DELETE SET NULL,
    source              TEXT NOT NULL,
    imported_at         INTEGER NOT NULL
);

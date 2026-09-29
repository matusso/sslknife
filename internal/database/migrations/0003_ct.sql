-- Phase 4: Certificate Transparency watches and observed issuances.
-- Only issuances for watched names are stored; CT logs are never mirrored.

CREATE TABLE ct_watches (
    id                  TEXT PRIMARY KEY,
    domain              TEXT NOT NULL,
    include_subdomains  INTEGER NOT NULL,
    source              TEXT NOT NULL,     -- manual or stored-san
    created_at          INTEGER NOT NULL,
    last_checked_at     INTEGER,
    cursor              TEXT NOT NULL DEFAULT '',
    UNIQUE (domain, include_subdomains)
);

CREATE TABLE ct_observations (
    id              TEXT PRIMARY KEY,
    watch_id        TEXT NOT NULL REFERENCES ct_watches(id) ON DELETE CASCADE,
    provider        TEXT NOT NULL,
    external_id     TEXT NOT NULL,
    identity        TEXT NOT NULL,          -- provider-independent de-duplication key
    cert_sha256     TEXT NOT NULL DEFAULT '',
    pubkey_sha256   TEXT NOT NULL DEFAULT '',
    serial          TEXT NOT NULL DEFAULT '',
    issuer          TEXT NOT NULL,
    issuer_name     TEXT NOT NULL DEFAULT '',
    dns_names       TEXT NOT NULL,          -- newline separated
    not_before      INTEGER NOT NULL,
    not_after       INTEGER NOT NULL,
    revoked         INTEGER,
    status          TEXT NOT NULL,          -- known, new, changed, unexpected, expired
    reason          TEXT NOT NULL DEFAULT '',
    known_cert_id   TEXT,
    acknowledged    INTEGER NOT NULL DEFAULT 0,
    first_seen      INTEGER NOT NULL,
    UNIQUE (watch_id, identity)
);
CREATE INDEX ct_observations_status ON ct_observations(status, first_seen);
CREATE INDEX ct_observations_watch ON ct_observations(watch_id, first_seen);

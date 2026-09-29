-- Phase 2: remote TLS endpoints and their observation history.

CREATE TABLE tls_endpoints (
    id          TEXT PRIMARY KEY,
    host        TEXT NOT NULL,
    port        INTEGER NOT NULL,
    sni         TEXT NOT NULL DEFAULT '',
    protocol    TEXT NOT NULL,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    UNIQUE (host, port, sni)
);

CREATE TABLE tls_scans (
    id           TEXT PRIMARY KEY,
    endpoint_id  TEXT NOT NULL REFERENCES tls_endpoints(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,            -- inspect or scan
    scanned_at   INTEGER NOT NULL,
    leaf_sha256  TEXT NOT NULL,
    snapshot     TEXT NOT NULL,            -- JSON summary used for history and diff
    result       BLOB NOT NULL             -- full JSON result
);
CREATE INDEX tls_scans_endpoint ON tls_scans(endpoint_id, scanned_at);
CREATE INDEX tls_scans_leaf ON tls_scans(leaf_sha256);

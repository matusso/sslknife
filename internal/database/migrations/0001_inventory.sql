-- Phase 1: certificate and key inventory.

CREATE TABLE secrets (
    id          TEXT PRIMARY KEY,
    nonce       BLOB NOT NULL,
    ciphertext  BLOB NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE keys (
    id           TEXT PRIMARY KEY,
    name         TEXT UNIQUE,
    algorithm    TEXT NOT NULL,          -- RSA, ECDSA, Ed25519, ML-DSA, ...
    bits         INTEGER NOT NULL,
    description  TEXT NOT NULL,          -- e.g. "ECDSA P-256"
    spki_sha256  TEXT NOT NULL UNIQUE,
    public_der   BLOB NOT NULL,          -- SubjectPublicKeyInfo
    secret_id    TEXT REFERENCES secrets(id) ON DELETE SET NULL,
    source       TEXT NOT NULL,
    comment      TEXT NOT NULL DEFAULT '',
    imported_at  INTEGER NOT NULL
);

CREATE TABLE certificates (
    id                   TEXT PRIMARY KEY,
    name                 TEXT UNIQUE,
    sha256               TEXT NOT NULL UNIQUE,
    sha1                 TEXT NOT NULL,
    spki_sha256          TEXT NOT NULL,
    serial               TEXT NOT NULL,
    subject              TEXT NOT NULL,
    subject_cn           TEXT NOT NULL,
    issuer               TEXT NOT NULL,
    issuer_cn            TEXT NOT NULL,
    not_before           INTEGER NOT NULL,
    not_after            INTEGER NOT NULL,
    key_algorithm        TEXT NOT NULL,
    key_bits             INTEGER NOT NULL,
    key_description      TEXT NOT NULL,
    signature_algorithm  TEXT NOT NULL,
    is_ca                INTEGER NOT NULL,
    self_signed          INTEGER NOT NULL,
    subject_key_id       TEXT NOT NULL,
    authority_key_id     TEXT NOT NULL,
    der                  BLOB NOT NULL,
    source               TEXT NOT NULL,
    comment              TEXT NOT NULL DEFAULT '',
    issuer_id            TEXT REFERENCES certificates(id) ON DELETE SET NULL,
    key_id               TEXT REFERENCES keys(id) ON DELETE SET NULL,
    ct_monitored         INTEGER NOT NULL DEFAULT 0,
    imported_at          INTEGER NOT NULL
);

CREATE INDEX certificates_not_after ON certificates(not_after);
CREATE INDEX certificates_spki ON certificates(spki_sha256);
CREATE INDEX certificates_ski ON certificates(subject_key_id);
CREATE INDEX certificates_subject_cn ON certificates(subject_cn);
CREATE INDEX certificates_issuer_id ON certificates(issuer_id);

CREATE TABLE certificate_sans (
    cert_id  TEXT NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    type     TEXT NOT NULL,              -- dns, ip, email, uri
    value    TEXT NOT NULL,
    PRIMARY KEY (cert_id, type, value)
);
CREATE INDEX certificate_sans_value ON certificate_sans(value);

CREATE TABLE tags (
    object_type  TEXT NOT NULL,          -- cert, key
    object_id    TEXT NOT NULL,
    tag          TEXT NOT NULL,
    PRIMARY KEY (object_type, object_id, tag)
);
CREATE INDEX tags_tag ON tags(tag);

CREATE TABLE notes (
    id           TEXT PRIMARY KEY,
    object_type  TEXT NOT NULL,
    object_id    TEXT NOT NULL,
    body         TEXT NOT NULL,
    created_at   INTEGER NOT NULL
);
CREATE INDEX notes_object ON notes(object_type, object_id);

-- Remote inventory sync (HashiCorp Vault). One row per object as it was when
-- this device last agreed with the remote; the digest covers the synced
-- fields, so a mismatch on either side means that side changed since.

CREATE TABLE remote_sync (
    remote  TEXT NOT NULL,    -- remote identity: address, namespace, mount and path
    kind    TEXT NOT NULL,    -- cert, key, ssh
    ident   TEXT NOT NULL,    -- certificate SHA-256, key SPKI SHA-256, SSH fingerprint (hex)
    digest  TEXT NOT NULL,
    PRIMARY KEY (remote, kind, ident)
);

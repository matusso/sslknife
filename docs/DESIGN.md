# SSLKnife design

This document is the first deliverable from `Roadmap.md` §62. It records the
architecture and the decisions behind it. When the code and this document
disagree, the code is authoritative and this document should be fixed.

## 1. Architecture

SSLKnife is a single Go binary. The CLI (`cmd/`) is a thin layer: it parses
flags, resolves configuration, opens the vault when a command needs it, calls
into a domain package and renders the result with `internal/output`.

```text
             ┌──────────────┐        ┌──────────────┐
  terminal → │  cmd (cobra) │        │ server + api │ ← browser (Phase 6)
             └──────┬───────┘        └──────┬───────┘
                    │  view models (stable JSON schema)
        ┌───────────┴───────────┬───────────┴─────────────┐
        ▼                       ▼                         ▼
 ┌─────────────┐        ┌──────────────┐          ┌──────────────┐
 │ certificate │        │  inventory   │          │ tls/scanner  │
 │ keys, ssh   │        │ (use cases)  │          │ ct, converter│
 │ (pure)      │        └──────┬───────┘          └──────────────┘
 └─────────────┘               ▼
                        ┌──────────────┐    ┌──────────────┐
                        │  database    │ ←─ │   secrets    │ keyslots,
                        │ (encrypted)  │    │  (unlock)    │ keyring, env
                        └──────────────┘    └──────────────┘
```

Rules:

* Parsing and analysis packages (`certificate`, `keys`, `ssh`, `converter`)
  are pure: bytes in, values out, no database, no terminal.
* `inventory` owns use cases that combine parsing with storage (import,
  link chains, search, expiry).
* `database` knows SQL and nothing about the CLI.
* `output` knows rendering and nothing about domains.
* No package-level mutable state. The CLI builds an `app` value per
  invocation and passes it down.

## 2. Technology choices

| Concern | Choice | Reason |
|---|---|---|
| Language | Go | Strong stdlib for X.509, TLS and crypto (including ML-DSA since Go 1.26), easy cross-compilation, single static binary. |
| CLI | `spf13/cobra` | Mature, native completion for bash/zsh/fish/PowerShell, doc generation. |
| SQLite | `ncruces/go-sqlite3` | SQLite compiled to Go (no cgo), so cross-compiling stays trivial. Ships an encrypting VFS. |
| DB encryption | Adiantum VFS + SQLite page checksums, keyed by HKDF from a random root key | See §5. SQLCipher needs cgo and a C crypto library. |
| Secret blobs | AES-256-GCM (stdlib) | Authenticated encryption for private keys on top of page encryption. |
| KDF | Argon2id (`x/crypto/argon2`) | Memory-hard, current best practice for passwords. |
| OS keychain | `zalando/go-keyring` | macOS Keychain, Windows Credential Manager, Secret Service. On macOS it writes secrets through `security -i` stdin, never argv. |
| PKCS#12 | `software.sslmate.com/src/go-pkcs12` | Maintained, supports modern AES/PBKDF2 and legacy RC2/3DES decoding. |
| JKS | `pavlo-v-chernykh/keystore-go` | Pure Go JKS/JCEKS reader/writer (Phase 3). |
| SSH | `golang.org/x/crypto/ssh` | Reference Go implementation of the SSH wire formats. |
| YAML | `gopkg.in/yaml.v3` | Config files and `--yaml` output. |
| Logging | `log/slog` with a redacting handler | Stdlib, structured. |
| Frontend | Plain ES modules + CSS embedded with `embed` | No Node toolchain needed to build the binary (Phase 6). |

SSLKnife never shells out to OpenSSL. The one external binary is macOS
`/usr/bin/security`, which the keyring library calls.

## 3. Package layout

```text
main.go                      entry point, calls cmd.Execute
cmd/                         cobra commands, one file per command group
internal/
  buildinfo/                 version, commit, date (ldflags)
  config/                    config file, platform paths, durations
  output/                    text/table/tree/JSON/YAML rendering, colours
  exitcode/                  typed errors → deterministic exit codes
  logging/                   slog setup with secret redaction
  prompt/                    TTY prompts: confirm, password, choice
  crypto/                    AEAD helpers, KDF, zeroize, random IDs
  secrets/                   keyslot file, unlock providers (env, keyring, Touch ID, TTY)
  keycache/                  background unlock cache (vault unlock / lock)
  database/                  encrypted SQLite open, migrations, repositories
  certificate/               parse, describe, fingerprints, create, lint, diff, chains
  keys/                      private/public key parse, generate, match, PKCS#8 (PBES2)
  inventory/                 import/link/list/show/search/expiry use cases
  search/                    query language → parameterised SQL
  views/                     public JSON schema shared by the CLI and the API
  netdial/                   direct, HTTP CONNECT and SOCKS5 dialing
  protocol/                  STARTTLS adapters and protocol detection
  scanner/                   raw ClientHello probes: versions, suites, groups, behaviour
  tlsinspect/                handshake inspection, validation, OCSP, full scan, history snapshots
  converter/                 format detection, Bundle decode/encode, PKCS#12, JKS
  ct/                        CT providers (Cert Spotter, crt.sh), classification, polling
  sshkeys/                   SSH keys, authorized_keys, OpenSSH certificates
  vaultkv/                   minimal HashiCorp Vault client: KV v2, Transit, token/AppRole/userpass
  remotesync/                three-way sync of the inventory with a shared remote (Vault)
  server/                    HTTP server, auth/CSRF/host checks, REST API, jobs, OpenAPI
web/                         embedded UI (static/) and its jsdom smoke test (test/)
docs/                        this design, generated command reference (docs/commands)
```

Keystore support lives in `converter` because JKS and PKCS#12 are just
two more container formats for the same objects. SQL migrations live in
`internal/database/migrations`, because `go:embed` cannot reach parent
directories.

## 4. Threat model

**Assets:** private keys (X.509 and SSH), keystore passwords, the vault root
key, and inventory metadata. Metadata such as internal hostnames, SANs and
scan history is reconnaissance value on its own.

**Adversaries and what SSLKnife defends against:**

| Threat | Mitigation |
|---|---|
| Stolen laptop, backup, or copied DB file | Whole-file encryption; root key only in keyslots protected by Argon2id or the OS keychain. |
| Tampering with the DB file | Page checksums inside a wide-block cipher detect modified pages (see §5). Private keys also carry a GCM tag bound to their row. |
| Secrets in shell history or process list | Passwords come from TTY, `SSLKNIFE_PASSWORD`, or `SSLKNIFE_PASSWORD_FILE`. Never from flags. |
| Secrets in logs | Redacting slog handler. Secret types implement `LogValue`. |
| Accidental disclosure on screen | Private material is never printed without `--stdout --show-secret`. Exports are written to files with mode 0600. |
| Other local users | Files and directories are created 0600/0700. |
| Malicious certificates, banners, TLS servers | Parsers must not panic; fuzz tests (Phase 7). Network reads are size- and time-bounded. |
| Web UI CSRF / DNS rebinding (Phase 6) | Loopback bind by default, Host header allow-list, CSRF tokens, token auth when not on loopback. |

**Out of scope:** a compromised account or OS (it can read process memory or
keylog the password), and rollback of the whole DB file to an older copy.
Rollback of individual pages is also not detected; see §5.

## 5. Encrypted database

Files in the data directory:

```text
sslknife.db        SQLite database, every page encrypted
sslknife.db.keys   keyslot file (JSON, 0600): wrapped root key
```

**Key hierarchy**

```text
root key RK (32 random bytes, generated at `sslknife init`)
 ├─ HKDF-SHA256(RK, info="sslknife/v1/db-page")  → Adiantum page key
 └─ HKDF-SHA256(RK, info="sslknife/v1/secrets")  → AES-256-GCM secret key
```

The RK is never stored in plaintext. Keyslots wrap it, the same way LUKS does:

* `password` slot: KEK = Argon2id(password, salt, t=3, m=64 MiB, p=4);
  wrapped = AES-256-GCM(KEK, RK, aad="sslknife-keyslot-v1|<db-id>|<slot-id>").
* `keyring` slot: a random 32-byte KEK stored in the OS keychain under
  service `sslknife`, account `<db-id>`. Wrapping is the same as above.
  With `touch_id: true` (macOS) the slot is used only after
  LocalAuthentication's `LAPolicyDeviceOwnerAuthentication` succeeds (Touch
  ID, Apple Watch, or the login password), called through purego so builds
  stay `CGO_ENABLED=0`. It is a presence check enforced by sslknife: the
  keychain item is written by `/usr/bin/security` and stays readable by any
  process of the same user, exactly like a plain keyring slot. Plain slots
  are tried first, so adding one bypasses Touch ID.

Unlock order: `SSLKNIFE_PASSWORD` / `SSLKNIFE_PASSWORD_FILE` → unlock cache →
keyring slot (plain, then Touch ID) → TTY password prompt. The Touch ID sheet
and the prompt only appear with a terminal attached, so shell completion
never blocks on them.

**Unlock cache** (`internal/keycache`, not on Windows). `vault unlock`, or a
password / Touch ID unlock with `vault.unlock_cache` set, starts a detached
`sslknife vault cache-daemon` that receives the RK over a pipe, `mlock`s it
and serves it on `$XDG_RUNTIME_DIR` or `$TMPDIR` `/sslknife-<uid>/<hash of
db-id>.sock`. The directory must be 0700 and owned by the user; the socket is
0600, and on macOS and Linux the peer's uid is checked (`LOCAL_PEERCRED`,
`SO_PEERCRED`). Every `get` extends the idle timer; when it fires, or on
`vault lock`, the process zeroes the key and exits. Anyone who can run code
as the user can read the RK while the cache is running, the same exposure as
a plain keyring slot. A failed GCM open means a wrong password; no separate
verifier is stored.

**Page encryption and integrity.** The Adiantum VFS encrypts each 4 KiB page
with a tweakable wide-block cipher (HBSH: XChaCha12, AES and NH/Poly1305),
using the page offset as the tweak. SQLite page checksums (8 reserved bytes
per page) are computed on the plaintext before encryption. Changing any
ciphertext bit makes the whole page decrypt to pseudorandom data, so the
checksum then fails with probability 1 − 2⁻⁶⁴. This is the encode-then-encipher
construction (Bellare & Rogaway, 2000). It gives per-page authenticity. Swapping
pages between offsets is also caught, because the offset is the tweak.
Replaying an older version of the same page is not caught. The journal mode is
`DELETE` rather than WAL, so there is no unchecksummed side file.

**Secret blobs.** Private keys are sealed again with AES-256-GCM before they
reach SQL, with a fresh 96-bit nonce and aad="sslknife-secret-v1|<secret-id>".
This keeps secrets out of plaintext in SQLite's page cache and in any future
export or backup of the database contents.

**Locking.** SQLite file locking plus `busy_timeout`. Transactions that write
use `BEGIN IMMEDIATE`, which serialises writers across the CLI and the server.

## 6. Database schema

The schema is in `internal/database/migrations/*.sql`. The versions applied
are tracked in `schema_migrations`, and migrations run automatically when the
vault is opened.

| Migration | Tables |
|---|---|
| 0001 inventory | `certificates`, `certificate_sans`, `keys`, `secrets`, `tags`, `notes` |
| 0002 tls_history | `tls_endpoints`, `tls_scans` (compact snapshot plus the full JSON result) |
| 0003 ct | `ct_watches` (with a provider cursor), `ct_observations` |
| 0004 ssh | `ssh_keys` (the private key file sealed in `secrets`, unchanged) |
| 0005 settings | `settings` (for example the server TLS identity, with the key sealed) |
| 0006 remote_sync | `remote_sync` (per remote: the digest of each object as last agreed with it, §13) |

* `certificates` holds the identity (id, name) and the fingerprints
  (`sha256` unique, `sha1`, `spki_sha256`). It also holds the serial, the
  subject and issuer (DN and CN), the validity window (unix seconds), key and
  signature algorithms, `is_ca`, `self_signed`, SKI/AKI, the DER, the source,
  a comment and the import time. `issuer_id` links the chain, `key_id` links
  the matching private key, and `ct_monitored` records whether CT watches
  the certificate's names.
* `keys` holds the public DER and `spki_sha256`; `secret_id` points to the
  sealed PKCS#8 and is NULL for public-only keys.
* `tags` and `notes` are polymorphic over object type (`cert`, `key`, `ssh`).

Indexes cover SAN values, fingerprints, SPKI, tags, `not_after`, endpoints
and observation status (§49).

## 7. CLI command hierarchy

See `sslknife --help` and `docs/commands/` (generated by `make docs`).
The tree follows Roadmap §52. Global flags: `--config --database --json --yaml
--format --quiet --verbose --debug --timeout --proxy --no-color`.

**Exit codes**

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | runtime error |
| 2 | invalid usage or arguments |
| 3 | object or file not found |
| 4 | vault locked, authentication failed |
| 5 | check failed: lint errors, key mismatch, certificate expired or expiring, scan finding |
| 6 | network or connection error |
| 7 | unsupported or impossible conversion |
| 130 | interrupted |

## 8. TLS protocol autodetection (Phase 2)

A `protocol.Adapter` interface:

```go
type Adapter interface {
    Name() string
    DefaultPorts() []int
    // Upgrade speaks the plaintext protocol until the socket is ready
    // for a TLS ClientHello. Direct-TLS adapters return immediately.
    Upgrade(ctx context.Context, conn net.Conn, host string) (Transcript, error)
}
```

Resolution order: explicit `--protocol`, then the port map (25/587 → SMTP,
143 → IMAP, 110 → POP3, 389 → LDAP, 21 → FTP, 5222 → XMPP, 5432 → Postgres,
3306 → MySQL, 993/995/465/636/8883/6380/443 → direct TLS), then banner
sniffing (`220 ` SMTP/FTP, `* OK` IMAP, `+OK` POP3, MySQL handshake packet),
then direct TLS. The result reports how TLS was reached, e.g.
`smtp (port) → STARTTLS`.

The version and cipher scanners use their own ClientHello encoder
(`internal/scanner`) and read only the ServerHello, so results do not depend
on what Go's `crypto/tls` (or OpenSSL) implements. SSLv2 and SSLv3 are
probed with their own record formats. Probes run concurrently
(`--concurrency`), and each probe opens one connection.

## 9. Conversion architecture (Phase 3)

`converter.Detect(bytes) → Container` normalises any input into a bag of
typed objects: certificates, private keys, public keys, CSRs, SSH keys, each
with an alias and origin. Writers take a bag and a target format. Each writer
checks whether it can represent the bag. For example, DER holds exactly one
object, and an authorized_keys file cannot hold a private key. When it
cannot, it fails with exit code 7 and explains why. It never drops objects
silently.

## 10. REST API (Phase 6)

The API lives under `/api/v1`. Its JSON bodies reuse the `views` schemas and
the `tlsinspect` results, and it is described by `/api/v1/openapi.json`
(`internal/server/openapi.json`). Main routes:

```text
GET  /session  /dashboard  /search?q=  /keys  /ssh/keys  /openapi.json
GET  /certificates?q=        POST /certificates (PEM; private keys are ignored)
GET  /certificates/{id}      DELETE /certificates/{id}   GET /certificates/{id}/pem
POST /certificates/{id}/tags DELETE /certificates/{id}/tags/{tag}
POST /tls/inspect  POST /tls/scan  GET /tls/endpoints  GET /tls/scans  GET /tls/scans/{id}
GET  /ct/watches  POST /ct/watches  DELETE /ct/watches/{id}
GET  /ct/observations  POST /ct/observations/{id}/ack  POST /ct/check
```

**Server security.**

* The server binds to loopback by default. Binding elsewhere prints warnings,
  and plain HTTP is refused off loopback unless explicitly allowed.
* A random access token is printed at startup; `--token-file` or
  `SSLKNIFE_SERVER_TOKEN` can supply it instead. API clients send it as a
  bearer token. Browsers exchange it once for an `HttpOnly`,
  `SameSite=Strict` session cookie (`Secure` over HTTPS). The token is then
  stripped from the URL by a redirect.
* Cookie sessions must send a CSRF token and pass a same-origin check on
  unsafe methods.
* A Host header allow-list defeats DNS rebinding.
* CSP (`default-src 'none'`, scripts from `self` only), `nosniff`, `DENY`
  framing, `no-referrer` and COOP are applied to every response.
* The self-signed HTTPS identity is created once and stored in `settings`,
  with its key sealed.
* No handler returns private key material.

## 11. Frontend architecture (Phase 6)

The UI is plain ES modules (`web/static/app.js`) and one stylesheet,
embedded with `//go:embed`, and needs no build step. A hash router calls
`fetch` against `/api/v1`. All DOM is built with `textContent`, never with
`innerHTML` from data, so certificate and server contents cannot inject
markup. Views:

* dashboard
* certificate list and detail, with Overview, SANs, Chain, Extensions,
  Findings, Raw, PEM, CT and History tabs
* keys
* TLS analyzer, with expandable result sections
* CT watches and observations
* import and search

`web/test/smoke.mjs` runs the UI in jsdom against a live server.

## 12. Implementation notes

* **CT.** Cert Spotter is the default provider. It de-duplicates
  precertificates, returns certificate and public-key hashes, and supports an
  incremental `after` cursor. crt.sh is the alternative, de-duplicated by
  issuer and serial. CAs are compared by organisation, because issuers rotate
  intermediates.
* **Incomplete chains.** Platform verifiers (macOS, Windows) fetch missing
  intermediates over AIA. SSLKnife compares the verified chain with the
  presented one and reports intermediates the server did not send.
* **Cipher strength.** A suite's strength comes from its IANA name, and is
  downgraded when the server's parameters are weak (DH groups below 2048
  bits, curves below 256 bits).

## 13. Shared inventory through HashiCorp Vault

Several devices share one inventory through a Vault KV version 2 mount
(`sslknife remote`, `remote:` in the config). The local encrypted database
stays the working copy. Search compiles to SQL, and TLS history and CT
monitoring are per-device, so replacing SQLite with Vault would lose them.
Only the inventory is synced: certificates, keys and SSH keys with their
names, comments, tags and notes.

**Layout** below `<mount>/<path>`: `manifest`, `certificates/<sha256>`,
`keys/<spki-sha256>`, `ssh/<fingerprint-hex>`. Each value is plain JSON with
PEM (or authorized_keys) encodings. Private keys go into `private_key`, or
into `private_key_transit` plus `transit_key` when a Transit key is
configured. The manifest maps every object to the digest of its metadata
and its KV version, so a sync reads one document and then fetches only the
objects that changed.

**Merge.** Objects are identified by content, never by local ID. For each
object the sync compares the local digest L, the manifest digest R and the
digest S recorded in `remote_sync` when both sides last agreed:

| State | Action |
|---|---|
| L = R | in sync |
| R = S, L changed | push |
| L = S, R changed | pull |
| both changed | merge: tags and notes united, remote name/comment preferred, push the result |
| only L, no S | push (new here) |
| only L, L = S | delete locally (deleted on another device) |
| only R, no S | pull (new there) |
| only R, R = S | delete remotely (deleted here) |
| one side deleted, the other changed | the change wins and is restored |

**Concurrency.** Object writes check-and-set on the version in the manifest.
The manifest itself is written with check-and-set last, and removed objects
are destroyed only after that. A device that loses the race gets a conflict
and runs the whole sync again from the new manifest (up to 5 attempts). The
`remote_sync` state is saved only after the manifest write succeeds.

**Triggers.** With `auto_sync`, `requireVault` syncs after unlocking, and
`Execute` syncs again when SQLite's `total_changes()` shows the command
wrote something. Failures in automatic syncs only warn. `sslknife server`
syncs every `remote.interval`.

**Trust.** Vault is trusted with the synced private keys (encryption at rest,
ACLs, audit log), optionally behind Transit. Tokens come from
`$VAULT_TOKEN`, AppRole, the OS keychain (`remote login`) or
`~/.vault-token`, never from flags or the config file. Remote content is
parsed with the same parsers as imported files. An object whose content does
not match its path is rejected.

## 14. Phased roadmap

| Phase | Scope | Status |
|---|---|---|
| 1. Foundation | CLI, config, encrypted SQLite, certificate and key parsing, inventory, search, lint, diff, create | done |
| 2. TLS | inspection, chain validation, STARTTLS adapters, version and cipher scanning, full scan, history | done |
| 3. Conversion | format detection, PEM/DER/PKCS#1/PKCS#8/PKCS#7/PKCS#12/JKS/OpenSSH | done (JCEKS read-only detection) |
| 4. CT | watches, stored-SAN watches, Cert Spotter / crt.sh polling, classification, history | done |
| 5. SSH | key inventory, inspect/convert, OpenSSH certificates | done |
| 6. Web | API, dashboard, certificate browser, TLS analyzer, CT views | done |
| 7. Hardening | fuzzing (all parsers), race tests, staticcheck/golangci-lint/gosec, govulncheck, permission and secret-leak review | first pass done; ongoing |

Beyond the roadmap's first version (§51), these are future work:

* DNS inspection (`sslknife dns`: CAA, TLSA/DANE, DNSSEC)
* ACME
* further secret backends (cloud KMS, PKCS#11)
* notifications and Prometheus metrics

The interfaces they would plug into already exist: `protocol.Adapter`,
`ct.Provider`, the `secrets.Keyring` and unlock providers, and
`converter.Encode` targets.

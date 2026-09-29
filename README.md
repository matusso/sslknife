# SSLKnife

One tool for everyday TLS, X.509, PKI and SSH work: inspect and lint
certificates, create a private CA, convert between every common key and
keystore format (including Java JKS without `keytool`), scan TLS servers
(including STARTTLS protocols), watch Certificate Transparency for your
domains, and keep it all in a local, encrypted inventory with an optional web
interface.

It is a single static Go binary with no OpenSSL dependency.

```console
$ sslknife tls scan example.com
$ sslknife cert inspect certificate.pem
$ sslknife convert old-keystore.jks --to pkcs12
```

- [Installation](#installation)
- [Quick start](#quick-start)
- [Command overview](#command-overview)
- [Certificate inventory](#certificate-inventory)
- [TLS scanner](#tls-scanner)
- [Conversion and keystores](#conversion-and-keystores)
- [CT monitoring](#certificate-transparency)
- [SSH](#ssh)
- [Server mode](#server-mode)
- [Security model](#security-model)
- [Configuration](#configuration)
- [Shell completion](#shell-completion)
- [Exit codes](#exit-codes)
- [Development](#development)

## Installation

```sh
# From source (Go 1.27+)
go install github.com/matusso/sslknife@latest

# Homebrew (after the first tagged release)
brew install matusso/tap/sslknife

# Docker (server mode)
docker run --rm -it -v sslknife-data:/data ghcr.io/matusso/sslknife init
docker run -p 127.0.0.1:8443:8443 -v sslknife-data:/data -it ghcr.io/matusso/sslknife
```

Release binaries for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64 and
windows/amd64 are attached to GitHub releases, together with SBOMs and a
Sigstore-signed checksum file.

## Quick start

Commands that work on files or remote hosts need no setup. The inventory
needs a vault:

```sh
sslknife init                  # asks for a vault password (Argon2id-protected)
sslknife init --keychain       # also store an unlock key in the OS keychain
```

Inspect a certificate, a whole chain, or what a server presents:

```console
$ sslknife cert inspect fullchain.pem
$ cat cert.pem | sslknife cert inspect -
$ sslknife cert inspect github.com:443 --json | jq '.certificates[0].sans'
$ sslknife cert sans cert.pem
$ sslknife cert expires cert.pem --check 30d || echo "renew soon"
$ sslknife fingerprint cert.pem
Kind:        certificate
Subject:     CN=api.example.com
SHA256:      49:F4:C8:30:...:00:03
SHA1:        6B:55:3B:09:...:14:01  (legacy)
SPKI SHA256: D0:DE:D5:25:...:46:31
```

Build a small private PKI and keep it in the vault:

```console
$ sslknife cert create --type root-ca --cn "Example Root CA" --algorithm ecdsa-p384 --store --name root
$ sslknife cert create --type intermediate-ca --cn "Example Issuing CA" --ca root --path-len 0 --store --name issuing
$ sslknife cert create --cn api.example.com --san www.api.example.com --ca issuing --validity 90d
Created TLS Server certificate for api.example.com (signed by Example Issuing CA)
  key ECDSA P-256, valid until 2026-12-28
  SANs api.example.com, www.api.example.com
  certificate api.example.com.crt
  private key api.example.com.key (mode 0600)
$ sslknife key match api.example.com.key api.example.com.crt
MATCH  api.example.com.key (private key) and api.example.com.crt (certificate) share the same public key
```

`sslknife cert create` without flags starts an interactive wizard.

## Command overview

```text
sslknife
├── cert        inspect create csr import export list show delete lint diff chain
│               sans subject issuer expires pem tag untag note rename expiring
├── key         generate inspect import export list show public match delete tag rename
├── tls         inspect scan versions ciphers groups chain alpn ocsp history diff
├── ct          watch unwatch list check history ack
├── ssh         generate inspect import export list show fingerprint public convert tag
│   └── cert    inspect sign create
├── jks         inspect list extract convert
├── convert     any supported format → any other (with explanations when impossible)
├── inspect     detect a file's format and list its contents
├── fingerprint SHA-256, SHA-1 (legacy) and SPKI fingerprints
├── search      query the inventory
├── server      local web UI and REST API
├── vault       status add-password add-keychain remove-slot change-password
├── init        create the vault
├── config      show path init
├── completion  bash zsh fish powershell
└── version
```

Every command documents its arguments, flags and examples in `--help`. The
full reference is generated into [`docs/commands`](docs/commands) with
`make docs`.

Global flags: `--json`, `--yaml`, `--format text|json|yaml|raw`, `--quiet`,
`--verbose`, `--debug`, `--log-level`, `--timeout`, `--proxy`
(`http://` or `socks5://`), `--no-color`, `--config`, `--database`.

## Certificate inventory

```console
$ sslknife cert import fullchain.pem --name api-prod --tag production
$ sslknife cert import api.example.com:443 --chain      # fetch and store what the server sends
$ sslknife key import server.key --name api-prod-key    # asks before storing private keys
$ sslknife cert list
ID        NAME      CN                  EXPIRES     DAYS  ALGORITHM    STATUS
d33d5147  api-prod  api.example.com     2026-10-19  19    ECDSA P-256  WARNING
9f2aeb63  vpn       vpn.example.com     2026-12-28  89    RSA 2048     OK
d74168f9  issuing   Example Issuing CA  2031-09-28  1824  ECDSA P-256  CA
$ sslknife cert show api-prod           # details, chain tree, linked key, notes
$ sslknife cert expiring --within 90d   # exit status 5 when something is found
```

Issuers and private keys are linked automatically in both directions, however
the objects are imported. Objects are addressed by ID, ID prefix, name or
fingerprint prefix.

Search uses a small query language:

```console
$ sslknife search 'expires:<30d'
$ sslknife search 'issuer:DigiCert -tag:staging'
$ sslknife search 'type:key algorithm:rsa'
$ sslknife search 'type:ssh tag:servers'
```

Fields: `name cn subject issuer san serial fingerprint spki algorithm tag type
status expires source id`. `expires` accepts `<30d`, `>1y`, `<=2027-01-01`.
Prefix a term with `-` to negate it.

**Lint** checks certificates and chains against RFC 5280, RFC 6125 and the
CA/Browser Forum Baseline Requirements. Each finding states what is wrong, why
it matters, the evidence, and the rule it comes from:

```console
$ sslknife cert lint fullchain.pem --hostname api.example.com --trust
WARNING  missing_intermediate  api.example.com
  WHAT     chain is incomplete
  WHY      clients without the missing issuer cached cannot build a path to a trusted root
  EVIDENCE no certificate for issuer CN=R11,O=Let's Encrypt,C=US (AIA caIssuers: http://r11.i.lencr.org/)
  REF      RFC 5280 §6
```

**Diff** compares any two certificates (files, stored or remote):

```console
$ sslknife cert diff old.pem new.pem --changed
SAN:
+ new.example.com
Expiration:
- 2026-10-01T00:00:00Z
+ 2027-10-01T00:00:00Z
```

Supported key algorithms: Ed25519, ECDSA P-256/P-384/P-521, RSA
2048/3072/4096, and ML-DSA-44/65/87 (FIPS 204). SSLKnife refuses to generate
RSA keys below 2048 bits.

## TLS scanner

```console
$ sslknife tls inspect example.com
$ sslknife tls inspect mail.example.com:25          # SMTP STARTTLS, detected from the port
$ sslknife tls inspect ldap.corp:389 --truststore corp-root.pem
$ sslknife tls versions example.com
SSLv2     NOT SUPPORTED
SSLv3     NOT SUPPORTED
TLS 1.0   NOT SUPPORTED
TLS 1.1   NOT SUPPORTED
TLS 1.2   SUPPORTED
TLS 1.3   SUPPORTED
$ sslknife tls ciphers example.com
$ sslknife tls scan example.com --fail-on high       # CI: exit 5 on high/critical findings
```

A full scan reports the certificate, chain trust (including chains that only
validate because the OS fetched a missing intermediate), hostname, expiry,
every protocol version from SSLv2 to TLS 1.3, every accepted cipher suite per
version with server/client order, DH group sizes and ECDHE curves, TLS 1.3 key
exchange groups (including X25519MLKEM768), secure renegotiation,
TLS_FALLBACK_SCSV, compression, OCSP stapling and session resumption.
Findings carry a severity grounded in RFCs and CVEs. There is no made-up
aggregate score.

Versions, suites and groups are probed with SSLKnife's own ClientHello, which
reads only the ServerHello. Results therefore do not depend on what the local
TLS library supports.

**Protocols.** Direct TLS (HTTPS, SMTPS, IMAPS, POP3S, LDAPS, FTPS, XMPPS,
MQTT, Redis, DoT) and STARTTLS-style upgrades for SMTP, IMAP, POP3, LDAP, FTP
(AUTH TLS), XMPP (client and server), PostgreSQL and MySQL. The protocol comes
from `--protocol`, then the URL scheme (`smtp://host`), then the port, then
the server's banner, and finally direct TLS. The report says which rule
applied. `--transcript` shows the plaintext negotiation.

**History.** Add `--save` to record an observation. `tls history` and
`tls diff` then show certificate, issuer, SAN, version and cipher changes over
time.

Only scan systems you are authorised to test. Probes are non-destructive.

## Conversion and keystores

The input format is detected from content, never from the file name:

```console
$ sslknife inspect mycert
File:               mycert
Detected format:    PKCS#12
Contains:           1 private key
                    1 leaf certificate
                    2 intermediate certificates
Password protected: yes

$ sslknife convert server.der --to pem --stdout
$ sslknife convert server.p12 --to pem -o server.pem
$ sslknife convert cert.pem key.pem chain.pem --to pkcs12 -o bundle.p12
$ sslknife convert keystore.jks --to pkcs12
$ sslknife convert truststore.jks --to pem --certs-only --stdout
$ sslknife jks list keystore.jks
$ sslknife jks extract keystore.jks --dir extracted/
```

| Format | Read | Write |
|---|---|---|
| PEM (certificates, keys, CSRs, public keys) | ✓ | ✓ |
| DER certificate / key / CSR / SPKI | ✓ | ✓ (one object) |
| PKCS#7 / .p7b | ✓ | ✓ (certificates only) |
| PKCS#8 (plain, and encrypted PBES2 incl. scrypt) | ✓ | ✓ (PBKDF2-SHA256 + AES-256-CBC) |
| PKCS#1 RSA / SEC1 EC | ✓ | ✓ |
| Legacy encrypted PEM (`Proc-Type: 4,ENCRYPTED`) | ✓ | — (use PKCS#8) |
| PKCS#12 / PFX, keystores and truststores | ✓ | ✓ |
| Java JKS | ✓ | ✓ |
| Java JCEKS | detected, explained | — |
| OpenSSH private key (plain / encrypted) | ✓ | ✓ |
| authorized_keys, RFC 4716 | ✓ | ✓ |

When a conversion would lose or misrepresent data, SSLKnife refuses with exit
status 7 and explains why. Examples: several objects to DER, a private key
into a .p7b, an EC key as PKCS#1, a certificate as an SSH key.

## Certificate Transparency

```console
$ sslknife ct watch '*.example.com'
$ sslknife ct check
*.example.com      12 fetched, 2 new
ID        STATUS      NAMES               ISSUER         NOT BEFORE  NOT AFTER
e57190b2  unexpected  shop.example.com    Surprise CA    2026-09-28  2026-12-27
a0e20cbc  known       www.example.com     Let's Encrypt  2026-09-01  2026-11-30
$ sslknife ct history example.com --status unexpected
$ sslknife ct ack e57190b2
```

SSLKnife queries a CT search service (Cert Spotter by default, or crt.sh with
`--provider crtsh`) for watched names only. It never mirrors CT logs. Each
issuance is classified against the inventory:

- **known**: the certificate, its key or its serial is stored
- **changed**: same names as a stored certificate, but a different certificate
- **new**: not stored, from a CA already used for these names
- **unexpected**: not stored, from a CA not seen before for these names
- **expired**: no longer valid

"Unexpected" is a prompt to look, not an accusation. With
`ct.auto_watch_stored_sans` (on by default), the DNS names of stored
certificates are watched automatically. `ct check --strict` exits with status
5 on unexpected or changed issuances. Set `SSLKNIFE_CERTSPOTTER_TOKEN` for a
higher Cert Spotter rate limit.

## SSH

```console
$ sslknife ssh generate -o ~/.ssh/id_ed25519 -C alice@laptop
$ sslknife ssh inspect ~/.ssh/id_ed25519.pub
Kind:               public
Format:             authorized_keys
Type:               ssh-ed25519
Bits:               256
Fingerprint SHA256: SHA256:5p9n...
Comment:            alice@laptop
$ sslknife ssh inspect ~/.ssh/authorized_keys          # every line, with options
$ sslknife ssh import ~/.ssh/id_ed25519                # stored as-is, still passphrase-protected
$ sslknife ssh convert id_rsa --to pkcs8 -o id_rsa.pem
$ sslknife ssh cert sign --ca ssh_ca --key id_ed25519.pub --principal alice --id alice@corp --validity 8h
$ sslknife ssh cert inspect id_ed25519-cert.pub
```

Encrypted private keys are inspected and fingerprinted without the passphrase
when the format allows it. Imported private keys are stored exactly as the
file, so a passphrase-protected key stays protected inside the vault. RSA SSH
CAs sign with `rsa-sha2-512`, never SHA-1.

## Server mode

```console
$ sslknife server
SSLKnife server started
https://127.0.0.1:8443/?token=3f1c…
TLS: self-signed certificate SHA-256 D6:EE:9A:…
```

The web UI (dashboard, certificate browser with chain, SANs, extensions,
findings, PEM, CT and history tabs, TLS analyzer, CT monitor, keys) runs on the
same inventory as the CLI. The REST API lives under `/api/v1` and is described
by `/api/v1/openapi.json`:

```sh
TOKEN=...   # printed at startup, or set with --token-file / $SSLKNIFE_SERVER_TOKEN
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:8443/api/v1/certificates
curl -sk -H "Authorization: Bearer $TOKEN" -X POST -d '{"target":"example.com","save":true}' \
     https://127.0.0.1:8443/api/v1/tls/scan
```

- It listens on loopback only unless `--listen` says otherwise, and prints
  warnings when exposed. Plain HTTP is refused off loopback.
- There is no default password. A random access token is printed at startup
  and exchanged for an `HttpOnly`, `SameSite=Strict` session cookie. Unsafe
  requests need a CSRF token and a same-origin `Origin`.
- A Host header allow-list blocks DNS rebinding. CSP, `nosniff`,
  frame-denial and a no-referrer policy are applied to every response.
- The HTTPS identity is self-signed, generated once and stored encrypted in
  the vault, so its fingerprint is stable. `--cert`/`--key` use your own.
- The API never returns private key material.
- Background jobs poll CT (`ct.interval`), re-inspect recorded endpoints
  (`server.refresh_interval`) and log certificates about to expire.
  `--no-jobs` disables them.

## Security model

The full threat model is in [docs/DESIGN.md](docs/DESIGN.md). In short:

- **Encrypted at rest.** The SQLite database is encrypted page by page
  (Adiantum wide-block cipher) with per-page checksums inside the encryption,
  so tampered pages are detected. Private keys are additionally sealed with
  AES-256-GCM, bound to their row.
- **Key hierarchy.** A random 256-bit root key is wrapped in keyslots:
  password (Argon2id, 64 MiB), and optionally the OS keychain. For automation,
  `SSLKNIFE_PASSWORD` or `SSLKNIFE_PASSWORD_FILE` supply the password. It is
  never accepted as a flag, never stored in the config, never logged.
  `sslknife vault` manages keyslots.
- **No accidental disclosure.** Private keys are exported to 0600 files;
  printing one needs `--stdout --show-secret`. Storing private keys asks first
  (`--yes` for automation). Logs redact passwords, keys, tokens and blobs.
- **Safe defaults.** No keys below RSA 2048 are generated, 128-bit random
  serials are used, PKCS#8 encryption uses PBKDF2-SHA256 with 600,000
  iterations, and SHA-1 appears only as a legacy fingerprint.
- **No custom cryptography.** Everything comes from the Go standard library
  or `golang.org/x/crypto`, and SSLKnife does not shell out to OpenSSL.

Back up `sslknife.db` together with `sslknife.db.keys`. Neither is useful
without the other.

## Configuration

Default locations (`sslknife config path` prints them):

| | Config | Data |
|---|---|---|
| Linux | `~/.config/sslknife/config.yaml` | `~/.local/share/sslknife/` |
| macOS | `~/Library/Application Support/sslknife/config.yaml` | `~/Library/Application Support/sslknife/` |
| Windows | `%AppData%\sslknife\config.yaml` | `%LocalAppData%\sslknife\` |

```yaml
database:
  path: ~/.local/share/sslknife/sslknife.db
tls:
  timeout: 10s
  concurrency: 8
  proxy: ""                # http://proxy:3128 or socks5://127.0.0.1:1080
ct:
  enabled: true
  provider: certspotter    # or crtsh
  interval: 15m
  auto_watch_stored_sans: true
server:
  listen: 127.0.0.1:8443
  refresh_interval: 6h
expiry:
  warning_days: 30
  critical_days: 7
```

Environment variables: `SSLKNIFE_CONFIG`, `SSLKNIFE_DATABASE`,
`SSLKNIFE_DATA_DIR`, `SSLKNIFE_PASSWORD`, `SSLKNIFE_PASSWORD_FILE`,
`SSLKNIFE_KEY_PASSWORD` (encrypted input files), `SSLKNIFE_OUT_PASSWORD`
(protected outputs), `SSLKNIFE_SSH_PASSPHRASE`, `SSLKNIFE_SERVER_TOKEN`,
`SSLKNIFE_CERTSPOTTER_TOKEN`, `SSLKNIFE_NO_KEYRING`, `NO_COLOR`.

## Shell completion

```sh
sslknife completion bash > /etc/bash_completion.d/sslknife
sslknife completion zsh > "${fpath[1]}/_sslknife"
sslknife completion fish > ~/.config/fish/completions/sslknife.fish
sslknife completion powershell | Out-String | Invoke-Expression
```

Stored certificate and key names are completed when the vault can be
unlocked without a prompt (keychain or environment).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | runtime error |
| 2 | invalid usage or arguments |
| 3 | object or file not found |
| 4 | vault locked or wrong password |
| 5 | check failed: lint errors, key mismatch, expiring certificates, scan findings, certificate diff |
| 6 | network or connection error |
| 7 | unsupported or impossible conversion |
| 130 | interrupted |

## Development

```sh
make build          # ./sslknife with version information
make test           # unit and integration tests (local servers only, no Internet)
make test-race
make vet lint vuln  # go vet + gofmt, golangci-lint, govulncheck
make fuzz           # short fuzzing pass over all parsers (FUZZTIME=30s)
make docs           # regenerate docs/commands
make cross          # binaries for all release platforms in dist/
```

The web UI is plain ES modules in [`web/static`](web/static), embedded in the
binary, with no build step. `web/test/smoke.mjs` runs it in jsdom against a
live server; CI does this automatically.

Architecture, the encrypted database design, the schema and the roadmap are
in [docs/DESIGN.md](docs/DESIGN.md).

## License

MIT, see [LICENSE](LICENSE).

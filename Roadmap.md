# SSLKnife — Swiss-Army Knife for TLS, Certificates, PKI and SSH

You are a senior systems programmer, security engineer, PKI specialist, cryptography engineer, CLI designer, and full-stack developer.

Your task is to design and implement **`sslknife`**, a production-quality Swiss-army knife for working with:

- SSL/TLS
- X.509 certificates
- Certificate chains
- Private/public keys
- PKI
- Certificate Transparency
- Cipher suites
- TLS protocol analysis
- Certificate conversion
- Keystores / truststores
- SSH keys

The target users are:

- software developers
- DevOps / DevSecOps engineers
- security engineers
- penetration testers
- PKI administrators
- SREs
- infrastructure engineers
- hackers and technical power users

The application must primarily be a **fast, powerful CLI tool**, while also supporting an optional **local server mode with a modern web interface**.

The project should feel like a combination of:

- `openssl`
- `ssh-keygen`
- `keytool`
- `testssl.sh`
- `sslyze`
- `step-cli`
- certificate inventory software

but with a much cleaner UX and a unified local database.

---

# 1. Core Philosophy

SSLKnife must follow these principles:

1. One tool for most everyday TLS, certificate, PKI and SSH operations.
2. Human-friendly output by default.
3. Machine-readable JSON/YAML output when requested.
4. Safe defaults.
5. Never silently weaken cryptographic security.
6. Never print private keys or secrets unless explicitly requested.
7. Work both interactively and in automation/CI.
8. Cross-platform where practical:
   - Linux
   - macOS
   - Windows
9. Minimize external dependencies.
10. Prefer a single distributable executable.
11. Operations should be composable and scriptable.
12. All potentially intrusive TLS scanning must be non-destructive.
13. Make network scanning suitable only for systems the user is authorized to test.

---

# 2. Recommended Architecture

Prefer implementing the core application in **Go** unless a strong technical reason exists to use Rust.

Suggested structure:

```text
sslknife/
├── cmd/
├── internal/
│   ├── certificate/
│   ├── pki/
│   ├── tls/
│   ├── scanner/
│   ├── ct/
│   ├── ssh/
│   ├── keystore/
│   ├── converter/
│   ├── database/
│   ├── crypto/
│   ├── secrets/
│   ├── server/
│   ├── api/
│   └── config/
├── web/
├── migrations/
├── docs/
├── tests/
└── main.go
```

Use clean interfaces so individual components are testable independently.

Avoid one giant package.

---

# 3. CLI

Primary binary:

```bash
sslknife
```

The CLI must have discoverable subcommands.

Example:

```bash
sslknife cert inspect example.pem
sslknife cert create
sslknife cert import certificate.pem
sslknife cert list
sslknife cert show <id>

sslknife key create
sslknife key import
sslknife key list

sslknife tls inspect example.com
sslknife tls inspect example.com:443
sslknife tls scan example.com
sslknife tls ciphers example.com
sslknife tls versions example.com

sslknife convert input.p12 --to pem

sslknife ct watch example.com
sslknife ct list

sslknife ssh generate
sslknife ssh inspect ~/.ssh/id_ed25519.pub
sslknife ssh list

sslknife server
```

Support aliases where sensible.

---

# 4. CLI UX

Use a mature CLI framework such as Cobra.

Implement:

- colored terminal output
- tables
- tree representations for certificate chains
- quiet mode
- verbose mode
- debug mode
- JSON output
- YAML output
- raw output where appropriate

Examples:

```bash
sslknife tls inspect example.com --json

sslknife cert list --format table

sslknife cert show abc123 --yaml

sslknife tls scan smtp.example.com:25 --protocol smtp
```

Global options should include:

```text
--config
--database
--json
--yaml
--quiet
--verbose
--debug
--timeout
--proxy
--no-color
```

Exit codes must be deterministic and documented.

---

# 5. Shell Completion

Implement native autocompletion generation for:

- bash
- zsh
- fish
- PowerShell

Example:

```bash
sslknife completion bash
sslknife completion zsh
sslknife completion fish
sslknife completion powershell
```

Also support context-aware completion where practical, for example certificate names stored in the local database.

---

# 6. Local Encrypted Database

Use **SQLite** as the embedded database.

The database MUST be encrypted at rest.

Evaluate:

- SQLCipher
- encrypted SQLite VFS
- another mature SQLite encryption implementation

Do not invent proprietary cryptography.

The database should contain metadata for:

- certificates
- certificate chains
- private keys
- public keys
- SSH keys
- CT watches
- CT observations
- remote TLS endpoints
- scan history
- tags
- notes
- keystores
- truststores

Sensitive key material must receive additional protection where appropriate.

Use authenticated encryption.

Master-key handling should support:

1. OS keychain/keyring
2. user-supplied password
3. environment variable for automation
4. external secret provider in future

Never store the database encryption password in plaintext configuration.

Support database locking.

---

# 7. Certificate Inventory

SSLKnife should operate as a local certificate inventory.

Each certificate entry should support:

- ID
- friendly name
- tags
- comments
- fingerprint
- SHA-256 fingerprint
- serial
- subject
- issuer
- SANs
- validity
- key algorithm
- key size
- signature algorithm
- associated private key
- chain
- source
- import date
- expiry status
- CT monitoring state

Example:

```bash
sslknife cert list
```

Possible output:

```text
NAME             CN                  EXPIRES      DAYS  ALGORITHM   STATUS
api-prod         api.example.com     2027-01-03   96    ECDSA P256  OK
legacy-vpn       vpn.example.com     2026-10-04   5     RSA 2048    WARNING
internal-ca      Company Root CA     2035-01-01   ...   RSA 4096    CA
```

---

# 8. Certificate Inspection

Implement:

```bash
sslknife cert inspect cert.pem
```

Show as much meaningful X.509 information as possible:

- version
- serial number
- fingerprint
- Subject
- Issuer
- Subject Alternative Names
- DNS SAN
- IP SAN
- URI SAN
- email SAN
- validity
- remaining lifetime
- public-key algorithm
- public-key parameters
- signature algorithm
- basic constraints
- CA status
- path length
- key usage
- extended key usage
- SKI
- AKI
- CRL distribution points
- AIA
- OCSP responder
- CA issuer URL
- certificate policies
- name constraints
- SCT information
- unknown extensions
- DER size
- PEM encoding

Identify unusual or deprecated cryptographic characteristics.

---

# 9. Certificate Creation

Support creation of:

- self-signed certificates
- certificate signing requests
- root CA
- intermediate CA
- leaf certificates
- server certificates
- client certificates
- code-signing certificates

Example:

```bash
sslknife cert create
```

Interactive wizard:

```text
Certificate type:
> TLS Server

Common Name:
> api.example.com

SANs:
> api.example.com
> www.api.example.com

Algorithm:
> Ed25519
  ECDSA P-256
  RSA 3072
  RSA 4096

Validity:
> 365d
```

Also support fully non-interactive operation.

---

# 10. Key Management

Support:

- RSA
- ECDSA
- Ed25519
- other widely supported modern algorithms when practical

Operations:

```bash
sslknife key generate
sslknife key inspect
sslknife key import
sslknife key export
sslknife key list
sslknife key delete
sslknife key public
sslknife key match
```

`key match` should determine whether a private key belongs to a certificate.

Example:

```bash
sslknife key match server.key server.crt
```

---

# 11. Remote TLS Inspection

One of the most important features.

Example:

```bash
sslknife tls inspect example.com
```

Equivalent:

```bash
sslknife tls inspect example.com:443
```

Gather:

- resolved IP addresses
- hostname
- SNI
- negotiated TLS version
- negotiated cipher
- ALPN
- protocol
- leaf certificate
- intermediate certificates
- chain
- trust status
- SANs
- expiration
- issuer
- OCSP information
- OCSP stapling
- SCTs
- certificate fingerprints
- public-key details
- signature algorithms
- session resumption capability where practical
- TLS extensions
- ALPN protocols
- server certificate chain order
- chain validation errors

Validate against the host operating system's trust store.

Optionally allow another trust store:

```bash
sslknife tls inspect example.com \
    --truststore company-ca.pem
```

---

# 12. Protocol Autodetection

SSLKnife must not assume TLS always runs over HTTPS.

Support generic TLS endpoints.

Example:

```bash
sslknife tls inspect host:636
```

Implement protocol autodetection where possible.

Support at minimum:

- HTTPS / generic TLS
- SMTP STARTTLS
- SMTPS
- IMAP STARTTLS
- IMAPS
- POP3 STARTTLS
- POP3S
- LDAP STARTTLS
- LDAPS
- FTP AUTH TLS
- XMPP STARTTLS
- PostgreSQL SSL negotiation
- MySQL TLS negotiation
- MQTT TLS
- Redis TLS

Architecture should allow additional protocol adapters.

Autodetection strategy:

1. use explicitly supplied `--protocol` if present
2. infer likely protocol from port
3. inspect banner/protocol response
4. try protocol-specific TLS upgrade
5. optionally attempt direct TLS
6. report exactly how TLS was reached

Example:

```bash
sslknife tls inspect mail.example.com:25
```

Output:

```text
Detected protocol: SMTP
STARTTLS: supported
TLS negotiated: TLS 1.3
Cipher: TLS_AES_256_GCM_SHA384
```

Allow overriding:

```bash
sslknife tls inspect host:12345 --protocol tls
```

---

# 13. TLS Cipher Scanner

Implement:

```bash
sslknife tls ciphers example.com
```

Determine which cipher suites the server accepts.

Categorize results:

```text
TLS 1.3
  TLS_AES_256_GCM_SHA384
  TLS_CHACHA20_POLY1305_SHA256
  TLS_AES_128_GCM_SHA256

TLS 1.2
  ECDHE_RSA_WITH_AES_256_GCM_SHA384
  ECDHE_RSA_WITH_AES_128_GCM_SHA256
```

Identify:

- modern ciphers
- deprecated ciphers
- weak ciphers
- insecure ciphers
- null encryption
- export-grade crypto
- RC4
- DES
- 3DES
- CBC-only legacy configurations
- static RSA where relevant
- anonymous DH
- insufficient DH parameters

Do not simply trust the locally installed OpenSSL cipher list.

---

# 14. TLS Version Scanner

Example:

```bash
sslknife tls versions example.com
```

Test:

- SSLv2
- SSLv3
- TLS 1.0
- TLS 1.1
- TLS 1.2
- TLS 1.3

Output:

```text
SSLv2     NOT SUPPORTED
SSLv3     NOT SUPPORTED
TLS 1.0   NOT SUPPORTED
TLS 1.1   NOT SUPPORTED
TLS 1.2   SUPPORTED
TLS 1.3   SUPPORTED
```

Clearly identify insecure legacy versions.

---

# 15. Full TLS Scan

Implement:

```bash
sslknife tls scan example.com
```

Combine:

- certificate analysis
- chain validation
- TLS versions
- cipher enumeration
- key exchange
- weak crypto detection
- OCSP
- ALPN
- SNI behavior
- certificate expiry
- hostname validation
- certificate-chain quality

Example summary:

```text
TLS Security Summary

Certificate          PASS
Certificate Chain    PASS
Hostname             PASS
Expiration           PASS
TLS 1.3              ENABLED
TLS 1.2              ENABLED
TLS 1.1              DISABLED
TLS 1.0              DISABLED
SSLv3                 DISABLED
Weak Ciphers          NONE
OCSP Stapling         ENABLED
```

Avoid fake "security scores".

Present factual findings and severity classifications based on documented cryptographic weaknesses.

---

# 16. Certificate Transparency

Implement Certificate Transparency monitoring.

Commands:

```bash
sslknife ct watch example.com
sslknife ct unwatch example.com
sslknife ct list
sslknife ct check
```

The CT subsystem must NOT attempt to mirror entire CT logs.

Only retain entries related to:

1. explicitly watched domains
2. SANs belonging to certificates already stored in SSLKnife
3. explicitly configured domain patterns

For a stored certificate containing:

```text
example.com
www.example.com
api.example.com
```

SSLKnife may automatically monitor those names.

Allow:

```bash
sslknife ct watch "*.example.com"
```

Store discovered certificates and metadata locally.

Mark certificates as:

- known
- new
- changed
- unexpected
- expired

Do not automatically label a certificate malicious simply because it is unknown.

---

# 17. CT Monitoring Server Mode

When server mode is running, periodically poll configured CT sources.

Configuration:

```yaml
ct:
  enabled: true
  interval: 15m
  auto_watch_stored_sans: true
```

Dashboard should show:

```text
New CT certificates: 3
Watched domains: 17
Unexpected SANs: 2
Certificates expiring soon: 4
```

---

# 18. Certificate and Keystore Conversion

One of the primary features must be universal certificate/key conversion.

Command:

```bash
sslknife convert input-file --to <format>
```

Automatically detect input format whenever practical.

Supported formats should include at least:

- PEM
- DER
- PKCS#1
- PKCS#8
- PKCS#12 / PFX
- X.509 certificate
- CSR
- Java JKS
- Java PKCS12 keystore
- Java truststore
- OpenSSH public key
- OpenSSH private key where technically applicable
- authorized_keys format
- RFC4716 SSH public keys

Examples:

```bash
sslknife convert server.der --to pem

sslknife convert server.p12 --to pem

sslknife convert keystore.jks --to pkcs12

sslknife convert cert.pem key.pem --to pkcs12

sslknife convert truststore.jks --to pem
```

When conversion is not mathematically or semantically possible, explain why instead of silently producing incorrect data.

---

# 19. Format Detection

Implement:

```bash
sslknife inspect file
```

Example:

```text
File: mycert
Detected format: PKCS#12
Contains:
  1 private key
  1 leaf certificate
  2 intermediate certificates
Password protected: yes
```

The user should not normally need to know the source encoding.

---

# 20. Java Keystore Support

Provide strong support for Java environments.

Commands:

```bash
sslknife jks inspect keystore.jks
sslknife jks list keystore.jks
sslknife jks extract keystore.jks
sslknife jks convert keystore.jks
```

Show:

- aliases
- certificate entries
- key entries
- certificate chains
- expiration
- algorithms

Allow converting JKS into PKCS#12 or PEM structures.

---

# 21. SSH Key Management

SSLKnife must also provide useful SSH-key management.

Commands:

```bash
sslknife ssh generate
sslknife ssh import
sslknife ssh inspect
sslknife ssh list
sslknife ssh show
sslknife ssh export
sslknife ssh fingerprint
sslknife ssh public
sslknife ssh convert
```

Support:

- Ed25519
- ECDSA
- RSA

Inspect:

```bash
sslknife ssh inspect ~/.ssh/id_ed25519.pub
```

Output:

```text
Type: ssh-ed25519
Fingerprint SHA256: ...
Comment: user@host
Bits: 256
```

---

# 22. SSH Private Keys

Encrypted SSH private keys must remain encrypted whenever possible.

SSLKnife may store keys in its encrypted vault.

Support:

```bash
sslknife ssh import ~/.ssh/id_ed25519
```

Require explicit confirmation or option before storing private material.

Never expose private-key contents in normal CLI output.

---

# 23. SSH Certificate Support

Where practical, support OpenSSH certificates.

Commands:

```bash
sslknife ssh cert inspect
sslknife ssh cert create
sslknife ssh cert sign
```

Show:

- principals
- serial
- key ID
- validity
- extensions
- critical options
- CA fingerprint

---

# 24. Server Mode

Implement:

```bash
sslknife server
```

Example:

```text
SSLKnife server started
https://127.0.0.1:8443
```

Default behavior MUST listen only on loopback.

Do not expose the server to LAN/WAN by default.

Allow explicitly:

```bash
sslknife server --listen 0.0.0.0:8443
```

When exposed beyond loopback, require strong warnings and support authentication.

---

# 25. REST API

Server mode should expose an internal API.

Example endpoints:

```text
GET    /api/v1/certificates
GET    /api/v1/certificates/{id}
POST   /api/v1/certificates
DELETE /api/v1/certificates/{id}

GET    /api/v1/keys

POST   /api/v1/tls/inspect
POST   /api/v1/tls/scan

GET    /api/v1/ct/watches
POST   /api/v1/ct/watches
DELETE /api/v1/ct/watches/{id}

GET    /api/v1/ssh/keys
```

Keep API versioned from the beginning.

Generate OpenAPI documentation.

---

# 26. Web UI Design

The UI should be:

- dark
- simple
- clean
- modern
- technical
- fast
- dense without being cluttered

Avoid:

- giant cards
- excessive gradients
- unnecessary animations
- dashboard-template appearance
- oversized padding

Think:

```text
GitHub Dark
+
Linear
+
Grafana
+
modern developer tooling
```

Possible frontend:

- Svelte / SvelteKit
- Vue
- React

Prefer a lightweight build.

Compile and embed frontend assets into the SSLKnife executable if practical.

---

# 27. Dashboard

Main dashboard:

```text
SSLKnife

Certificates       32
Private Keys        9
SSH Keys           12
CT Watches          8
Expiring <30d       3
TLS Endpoints      17
```

Sections:

- expiring certificates
- recent TLS scans
- CT discoveries
- recently added certificates
- weak TLS configuration findings

---

# 28. Certificate UI

Certificate page should visually show chain relationships.

Example:

```text
DigiCert Global Root G2
        ↓
DigiCert TLS RSA SHA256 2020 CA1
        ↓
api.example.com
```

Tabs:

```text
Overview
SANs
Chain
Extensions
Raw
PEM
CT
History
```

Private keys must NEVER be exposed by default in browser responses.

---

# 29. TLS Analyzer UI

Input:

```text
Host:
api.example.com

Port:
443

Protocol:
Auto

[ Analyze ]
```

Results:

```text
TLS 1.3
TLS_AES_256_GCM_SHA384
ECDSA P-256

Certificate valid
Hostname valid
Chain trusted

Expires:
2027-03-02

SAN:
api.example.com
*.example.com
```

Expandable sections for full TLS data.

---

# 30. Search

Implement fast local search.

Examples:

```text
example.com
issuer:DigiCert
expires:<30d
algorithm:rsa
tag:production
type:ssh
```

CLI:

```bash
sslknife search 'expires:<30d'
```

---

# 31. Tags

Allow tagging:

```bash
sslknife cert tag abc123 production
sslknife cert tag abc123 kubernetes
```

Useful tags:

```text
production
development
kubernetes
vpn
internal
external
customer
root-ca
intermediate-ca
```

---

# 32. Expiry Monitoring

Implement:

```bash
sslknife cert expiring
```

Default:

```text
30 days
```

Allow:

```bash
sslknife cert expiring --within 90d
```

Server mode should periodically check stored certificates and known endpoints.

---

# 33. Configuration

Default locations:

Linux:

```text
~/.config/sslknife/config.yaml
~/.local/share/sslknife/sslknife.db
```

macOS should use appropriate application directories where possible.

Example configuration:

```yaml
database:
  path: ~/.local/share/sslknife/sslknife.db

tls:
  timeout: 10s

ct:
  enabled: true
  interval: 15m
  auto_watch_stored_sans: true

server:
  listen: 127.0.0.1:8443

expiry:
  warning_days: 30
  critical_days: 7
```

---

# 34. Security Model

Treat SSLKnife as software that handles extremely sensitive secrets.

Mandatory requirements:

- encrypted database
- authenticated encryption
- no secrets in logs
- no passwords in command history where avoidable
- password prompting from TTY
- secret environment-variable support for CI
- restrictive file permissions
- zero sensitive temporary files where possible
- memory cleanup where practical
- CSRF protection for UI
- secure HTTP headers
- API authentication when exposed remotely
- localhost-only web server by default
- no private key returned through ordinary API endpoints
- cryptographically secure random generation
- no custom crypto algorithms

When invoking external processes is unavoidable, never expose passwords through command-line arguments.

---

# 35. Import Protection

Before importing a private key display something similar to:

```text
This file contains private key material.

Store it inside the encrypted SSLKnife vault?

[Y/n]
```

Provide:

```bash
--yes
```

for automation.

---

# 36. Sensitive Output Controls

Commands displaying sensitive information must require explicit flags.

For example:

```bash
sslknife key export abc123
```

should export securely to a file rather than dump it to stdout.

To print:

```bash
sslknife key export abc123 --stdout --show-secret
```

Require clear intentional action.

---

# 37. History

Store useful historical observations.

For endpoints:

```text
api.example.com:443

2026-09-20
TLS 1.2 + TLS 1.3
Certificate ABC

2026-09-28
TLS 1.2 + TLS 1.3
Certificate DEF
```

Allow detecting:

- certificate changes
- issuer changes
- SAN changes
- TLS version changes
- cipher changes

---

# 38. Diff

Implement:

```bash
sslknife cert diff cert1.pem cert2.pem
```

Example:

```text
Subject:
  unchanged

SAN:
+ new.example.com

Expiration:
- 2026-10-01
+ 2027-10-01

Public Key:
  unchanged
```

Also:

```bash
sslknife tls diff scan1 scan2
```

---

# 39. Import from Remote Host

Example:

```bash
sslknife cert import example.com:443
```

SSLKnife should:

1. connect to server
2. obtain chain
3. show discovered certificates
4. ask which ones to store

Option:

```bash
sslknife cert import example.com:443 --chain
```

---

# 40. Fingerprints

Support convenient fingerprints:

```bash
sslknife fingerprint cert.pem
```

Return at least:

```text
SHA256
SHA1
SPKI SHA256
```

Clearly mark SHA-1 as a legacy fingerprint mechanism rather than a recommended signature/hash algorithm.

---

# 41. DNS and TLS

Optionally inspect relevant DNS information.

Future-compatible support should include:

- CAA
- TLSA/DANE
- DNSSEC status

Command:

```bash
sslknife dns example.com
```

Architecture should allow these features even if implemented after MVP.

---

# 42. Certificate Linting

Implement:

```bash
sslknife cert lint cert.pem
```

Detect issues such as:

- expired certificate
- not-yet-valid certificate
- hostname mismatch when hostname supplied
- malformed chain
- missing intermediate
- deprecated signature algorithm
- weak RSA key size
- invalid basic constraints
- problematic key usage
- CA without appropriate CA constraints
- excessive lifetime
- suspicious SAN structure

Prefer established standards and libraries over arbitrary rules.

Every finding should explain:

```text
WHAT
WHY
EVIDENCE
```

---

# 43. Useful Convenience Commands

Examples:

```bash
sslknife cert expires cert.pem

sslknife cert sans cert.pem

sslknife cert issuer cert.pem

sslknife cert subject cert.pem

sslknife cert chain example.com

sslknife cert pem cert.der

sslknife key public private.key

sslknife key match server.key server.crt

sslknife tls alpn example.com

sslknife tls ocsp example.com
```

Make simple tasks simple.

---

# 44. Pipeline Support

Commands should behave correctly in shell pipelines.

Example:

```bash
sslknife tls inspect example.com --json |
jq '.certificate.sans'
```

Allow stdin:

```bash
cat certificate.pem | sslknife cert inspect -
```

Allow stdout for non-secret conversions:

```bash
sslknife convert cert.der --to pem --stdout
```

---

# 45. Output Schema Stability

JSON fields should be intentionally designed.

Example:

```json
{
  "target": "example.com:443",
  "protocol": "https",
  "tls": {
    "version": "TLS1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "alpn": "h2"
  },
  "certificate": {
    "subject": "...",
    "issuer": "...",
    "sans": [],
    "not_before": "...",
    "not_after": "...",
    "fingerprints": {}
  }
}
```

Do not expose internal Go structures directly as the public API schema.

---

# 46. Logging

Structured logging.

Levels:

```text
error
warn
info
debug
trace
```

Debug logging must still redact:

- passwords
- private keys
- encrypted blobs
- API tokens

---

# 47. Tests

Require extensive automated tests.

Include:

### Unit tests

- certificate parsing
- certificate creation
- key parsing
- encryption
- format detection
- conversion
- SAN extraction
- chain construction

### Integration tests

Run disposable TLS servers supporting:

- TLS 1.2
- TLS 1.3
- expired certificate
- self-signed certificate
- incomplete chain
- weak ciphers where the runtime allows them
- SMTP STARTTLS
- IMAP STARTTLS

Do not make the test suite dependent on public Internet services.

---

# 48. Fuzzing

Use fuzz tests for parsers processing attacker-controlled data:

- certificates
- PEM
- DER
- PKCS#12
- SSH public keys
- protocol banners
- TLS metadata

Parsing malformed input must never panic the program.

---

# 49. Performance

Requirements:

- startup should feel instantaneous
- certificate inspection should normally complete in milliseconds
- remote TLS connection should not perform unnecessary handshakes
- cipher scanning should support configurable concurrency
- SQLite indexes should be created for SANs, fingerprints, tags and expiry

Provide:

```bash
--concurrency
```

where appropriate.

---

# 50. Plugin-Friendly Architecture

Do not build a complex plugin system initially.

But interfaces should make future extensions possible for:

- protocols
- CT providers
- secret backends
- exporters
- certificate sources
- notification providers

---

# 51. Future Features

Design architecture so these can be added later without major redesign:

- ACME
- Let's Encrypt integration
- Vault
- AWS ACM
- Azure Key Vault
- GCP Certificate Manager
- Kubernetes secrets
- Kubernetes cert-manager
- HSM / PKCS#11
- YubiKey
- SCEP
- EST
- DANE
- certificate renewal
- webhook notifications
- Slack notifications
- Prometheus metrics
- CRL monitoring

Do NOT implement all of these in the first version.

---

# 52. Suggested Command Tree

Aim toward:

```text
sslknife
├── cert
│   ├── inspect
│   ├── create
│   ├── import
│   ├── export
│   ├── list
│   ├── show
│   ├── delete
│   ├── lint
│   ├── diff
│   ├── chain
│   ├── sans
│   └── expiring
│
├── key
│   ├── generate
│   ├── inspect
│   ├── import
│   ├── export
│   ├── list
│   ├── public
│   └── match
│
├── tls
│   ├── inspect
│   ├── scan
│   ├── versions
│   ├── ciphers
│   ├── chain
│   ├── alpn
│   └── ocsp
│
├── ct
│   ├── watch
│   ├── unwatch
│   ├── list
│   ├── check
│   └── history
│
├── ssh
│   ├── generate
│   ├── inspect
│   ├── import
│   ├── export
│   ├── list
│   ├── fingerprint
│   ├── public
│   └── cert
│
├── convert
├── inspect
├── search
├── server
├── completion
└── version
```

---

# 53. Example User Experience

A user should be able to install SSLKnife and immediately run:

```bash
sslknife tls scan google.com
```

or:

```bash
sslknife cert inspect certificate.pem
```

or:

```bash
sslknife convert old-keystore.jks --to pkcs12
```

without reading a manual.

Advanced users must still have enough control to override autodetection and cryptographic behavior where appropriate.

---

# 54. README

Create an excellent README containing:

- what SSLKnife is
- installation
- screenshots
- quick-start examples
- command overview
- server mode
- certificate inventory
- TLS scanner
- CT monitoring
- SSH support
- security model
- supported formats
- shell completion
- configuration
- development instructions

README should prioritize concrete commands over marketing language.

---

# 55. Documentation

Generate documentation for every command.

Example:

```bash
sslknife tls scan --help
```

must contain:

- description
- arguments
- options
- examples

Generate a command-reference document from CLI definitions if possible.

---

# 56. Versioning

Use semantic versioning.

Expose build information:

```bash
sslknife version
```

Example:

```text
SSLKnife 0.1.0
commit: 2fdd6ce
built: 2026-09-29
go: go1.xx
os/arch: darwin/arm64
```

---

# 57. Packaging

Prepare releases for:

```text
linux/amd64
linux/arm64
darwin/amd64
darwin/arm64
windows/amd64
```

Provide:

- GitHub Releases
- Homebrew
- Docker image for server mode

Potential future packages:

- deb
- rpm
- winget
- Chocolatey

---

# 58. Docker

Server mode should support:

```bash
docker run \
  -p 127.0.0.1:8443:8443 \
  -v sslknife-data:/data \
  sslknife/sslknife server
```

Never ship a default password.

---

# 59. CI/CD

Create CI pipelines for:

- build
- unit tests
- integration tests
- linting
- static analysis
- dependency vulnerability scanning
- frontend build
- cross-platform compilation
- release artifacts
- SBOM generation

Sign release artifacts where practical.

---

# 60. Development Method

Do not attempt to implement everything in one giant change.

Build the project incrementally.

## Phase 1 — Foundation

Implement:

- project structure
- CLI
- configuration
- encrypted SQLite
- certificate parsing
- key parsing
- local certificate inventory

## Phase 2 — TLS

Implement:

- remote inspection
- chain validation
- protocol autodetection
- TLS versions
- cipher enumeration

## Phase 3 — Conversion

Implement:

- PEM
- DER
- PKCS#1
- PKCS#8
- PKCS#12
- JKS

## Phase 4 — CT

Implement:

- domain watches
- stored-SAN watches
- CT polling
- change history

## Phase 5 — SSH

Implement SSH key inventory and operations.

## Phase 6 — Web

Implement:

- HTTP API
- dashboard
- certificate browser
- TLS scanner
- CT monitoring

## Phase 7 — Hardening

Perform:

- fuzzing
- security audit
- permission review
- secret leakage review
- performance improvements

---

# 61. Coding Requirements

Code must be:

- idiomatic
- modular
- testable
- documented where necessary
- free of unnecessary abstractions

Avoid:

- placeholder implementations
- giant files
- global mutable state
- hard-coded passwords
- hard-coded paths
- shelling out to OpenSSL for basic functionality
- parsing command output when native libraries can perform the operation
- storing plaintext private keys in SQLite
- insecure random-number generation

External binaries may be used only where there is a strong technical justification.

---

# 62. First Deliverable

Begin by producing:

1. architecture proposal
2. technology choices with reasoning
3. package/module layout
4. threat model
5. encrypted-database design
6. database schema
7. CLI command hierarchy
8. TLS protocol autodetection design
9. certificate-conversion architecture
10. REST API outline
11. frontend architecture
12. phased implementation roadmap

Then create the project skeleton.

After the skeleton exists, implement **Phase 1 completely**, including tests, before progressing further.

Do not create fake implementations merely to make commands appear to work.

---

# 63. Definition of Done

SSLKnife should eventually allow a user to perform workflows such as:

```bash
sslknife tls scan mail.example.com:25
```

and automatically understand SMTP STARTTLS;

```bash
sslknife cert import api.example.com:443 --chain
```

and store the retrieved certificate chain;

```bash
sslknife ct watch '*.example.com'
```

and detect newly issued certificates;

```bash
sslknife convert legacy.jks --to pkcs12
```

without requiring Java `keytool`;

```bash
sslknife key match private.key certificate.pem
```

and verify their relationship;

```bash
sslknife cert expiring --within 30d
```

and find certificates that require attention;

and:

```bash
sslknife server
```

to open a polished local web interface exposing the same underlying SSLKnife functionality.

The final product should feel like a tool an experienced security engineer would install on every workstation rather than another thin wrapper around OpenSSL.

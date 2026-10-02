# SSLKnife documentation

Guides:

- [Getting started](getting-started.md): vault setup, first inspections, a private PKI
- [Certificate inventory](inventory.md): import, list, search, lint and diff
- [TLS scanner](tls-scanner.md): versions, ciphers, STARTTLS, scan history
- [Conversion and keystores](conversion.md): PEM, DER, PKCS#7/8/12, JKS, OpenSSH
- [Certificate Transparency](certificate-transparency.md): watching your domains
- [SSH](ssh.md): keys, `authorized_keys` and SSH certificates
- [Server mode](server.md): web UI and REST API
- [Sharing between devices](remote-vault.md): HashiCorp Vault sync
- [Security model](security.md)
- [Configuration](configuration.md): config file, environment, shell completion, exit codes

Reference:

- [Command reference](commands/sslknife.md), generated with `make docs`

Project:

- [Development](development.md)
- [Releasing](releasing.md): versioning, GitHub Actions and the Homebrew tap
- [Design](DESIGN.md): architecture, database and threat model
- [Roadmap](ROADMAP.md)

## Command overview

```text
sslknife
├── cert        inspect create csr import export list show delete lint diff chain
│               sans subject issuer expires pem tag untag note rename expiring
├── key         generate inspect import export list show public match delete tag rename
├── tls         inspect scan versions ciphers groups chain alpn ocsp history diff
├── ct          watch unwatch list check history ack
├── ssh         generate inspect import export list show fingerprint public convert tag
│   ├── cert    inspect sign create
│   └── agent   add list remove serve
├── jks         inspect list extract convert
├── convert     any supported format → any other (with explanations when impossible)
├── inspect     detect a file's format and list its contents
├── fingerprint SHA-256, SHA-1 (legacy) and SPKI fingerprints
├── search      query the inventory
├── server      local web UI and REST API
├── vault       status unlock lock add-password add-keychain remove-slot change-password
├── remote      sync status login logout forget (share via HashiCorp Vault)
├── init        create the vault
├── config      show path init
├── completion  bash zsh fish powershell
└── version
```

Global flags: `--json`, `--yaml`, `--format text|json|yaml|raw`, `--quiet`,
`--verbose`, `--debug`, `--log-level`, `--timeout`, `--proxy`
(`http://` or `socks5://`), `--no-color`, `--config`, `--database`,
`--no-sync`.

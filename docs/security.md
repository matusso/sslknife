# Security model

The full threat model is in [DESIGN.md](DESIGN.md). In short:

- **Encrypted at rest.** The SQLite database is encrypted page by page
  (Adiantum wide-block cipher) with per-page checksums inside the encryption,
  so tampered pages are detected. Private keys are additionally sealed with
  AES-256-GCM, bound to their row.
- **Key hierarchy.** A random 256-bit root key is wrapped in keyslots:
  password (Argon2id, 64 MiB), and optionally the OS keychain (on macOS
  optionally gated by Touch ID or Apple Watch; that gate is a presence check
  by sslknife, the keychain item is readable by your account either way).
  `vault unlock` / `vault.unlock_cache` keep the root key in the memory of a
  background process, served only to your user over a private Unix socket,
  until it has been idle for the configured time. For automation,
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

# Getting started

Commands that work on files or remote hosts need no setup. The inventory
needs a vault:

```sh
sslknife init                  # asks for a vault password (Argon2id-protected)
sslknife init --keychain       # also store an unlock key in the OS keychain
sslknife init --touch-id       # macOS: keychain key that needs Touch ID or Apple Watch
```

To stop being asked for the password on every command, either add a Touch ID
keyslot to an existing vault, or keep the vault unlocked for a while:

```sh
sslknife vault add-keychain --touch-id   # confirm with Touch ID / Apple Watch instead of typing
sslknife vault unlock --for 30m          # no prompts until 30 minutes after the last use
sslknife vault lock                      # forget the cached key now
```

Setting `vault.unlock_cache: 15m` in the config starts that cache
automatically whenever a command had to ask for the password or Touch ID.

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

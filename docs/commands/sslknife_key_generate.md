## sslknife key generate

Generate a new private key

### Synopsis

Generate a private key with the operating system's CSPRNG.

The key is written as PKCS#8 PEM with mode 0600, optionally encrypted
(PBKDF2-HMAC-SHA256 + AES-256-CBC), and/or stored in the encrypted vault.

Algorithms: ecdsa-p256, ecdsa-p384, ecdsa-p521, ed25519, rsa-2048, rsa-3072, rsa-4096, ml-dsa-44, ml-dsa-65, ml-dsa-87

```
sslknife key generate [flags]
```

### Examples

```
  sslknife key generate -o server.key
  sslknife key generate --algorithm rsa-4096 -o legacy.key --encrypt
  sslknife key generate --algorithm ed25519 --store --name signing-key
```

### Options

```
  -a, --algorithm string       key algorithm (default "ecdsa-p256")
      --encrypt                encrypt the key file with a password
      --force                  overwrite the output file
  -h, --help                   help for generate
      --name string            friendly name in the vault
  -o, --out string             output file (default key.pem unless --store)
      --password-file string   read the encryption password from a file
      --store                  store the key in the vault
      --tag strings            tags in the vault (repeatable)
```

### Options inherited from parent commands

```
      --config string      config file (default: platform config dir, or $SSLKNIFE_CONFIG)
      --database string    database file (default from config, or $SSLKNIFE_DATABASE)
      --debug              debug logging (secrets are always redacted)
      --format string      output format: text|table|json|yaml|raw (default "text")
      --json               output JSON
      --log-level string   log level: error|warn|info|debug|trace
      --no-color           disable coloured output (also honours NO_COLOR)
      --no-sync            do not sync with the Vault remote for this command
      --proxy string       proxy for outbound connections (http://, socks5://)
  -q, --quiet              suppress non-essential output
      --timeout duration   network timeout (default from config, 10s)
  -v, --verbose            verbose logging
      --yaml               output YAML
```

### SEE ALSO

* [sslknife key](sslknife_key.md)	 - Generate, inspect and manage private and public keys


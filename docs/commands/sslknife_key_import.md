## sslknife key import

Store keys from a file in the encrypted vault

### Synopsis

Import private keys (or a public key) into the vault. Private keys are
converted to PKCS#8 and sealed with AES-256-GCM inside the encrypted database.
Certificates already stored that use the same key are linked automatically.

You are asked to confirm before private key material is stored; pass --yes in
automation.

```
sslknife key import <file|-> [flags]
```

### Examples

```
  sslknife key import server.key --name api-prod
  SSLKNIFE_KEY_PASSWORD=... sslknife key import encrypted.key --yes
```

### Options

```
      --comment string         free-text comment
  -h, --help                   help for import
      --name string            friendly name
      --password-file string   password for encrypted keys
      --tag strings            tags (repeatable)
  -y, --yes                    store private key material without asking
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


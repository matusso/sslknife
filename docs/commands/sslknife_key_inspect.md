## sslknife key inspect

Describe a private or public key (never prints key material)

### Synopsis

Detect the format of a key file and describe the key. Supported: PKCS#8
(plain and encrypted), PKCS#1, SEC1, legacy encrypted PEM, OpenSSH private
keys, PKIX and PKCS#1 public keys, authorized_keys and RFC 4716 SSH keys.

```
sslknife key inspect <file|-> [flags]
```

### Examples

```
  sslknife key inspect server.key
  sslknife key inspect ~/.ssh/id_ed25519.pub --json
```

### Options

```
  -h, --help                   help for inspect
      --password-file string   password for encrypted keys
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


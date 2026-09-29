## sslknife init

Create the encrypted SSLKnife vault

### Synopsis

Create the encrypted database and its key file.

A random 256-bit root key encrypts the database. The root key is stored only
in wrapped form, protected by your password (Argon2id) and optionally by the
OS keychain so that everyday commands do not prompt.

The password is read from the terminal, or from SSLKNIFE_PASSWORD /
SSLKNIFE_PASSWORD_FILE for automation. It is never accepted as a flag.

```
sslknife init [flags]
```

### Examples

```
  sslknife init
  sslknife init --keychain
  SSLKNIFE_PASSWORD_FILE=/run/secrets/sslknife sslknife init
```

### Options

```
  -h, --help            help for init
      --keychain        also store an unlock key in the OS keychain
      --keychain-only   protect the vault with the OS keychain only (no password)
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
      --proxy string       proxy for outbound connections (http://, socks5://)
  -q, --quiet              suppress non-essential output
      --timeout duration   network timeout (default from config, 10s)
  -v, --verbose            verbose logging
      --yaml               output YAML
```

### SEE ALSO

* [sslknife](sslknife.md)	 - Swiss-army knife for TLS, certificates, PKI and SSH keys


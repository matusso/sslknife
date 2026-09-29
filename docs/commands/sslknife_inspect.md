## sslknife inspect

Detect a file's format and list what it contains

### Synopsis

Identify any certificate, key or keystore file by its content and list the
objects inside, without printing key material. Password-protected containers
(PKCS#12, JKS, encrypted keys) are opened when a password is available;
otherwise only the format is reported.

```
sslknife inspect <file|-> [flags]
```

### Examples

```
  sslknife inspect mycert
  sslknife inspect keystore.jks --json
  SSLKNIFE_KEY_PASSWORD=changeit sslknife inspect bundle.p12
```

### Options

```
  -h, --help                   help for inspect
      --password-file string   password for protected files
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


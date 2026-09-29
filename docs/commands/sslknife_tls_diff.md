## sslknife tls diff

Compare two recorded observations

### Synopsis

Compare two recorded observations (IDs from 'tls history'), or the two most
recent observations of a target. Detects certificate, issuer, SAN, expiry,
key, version and cipher changes. Exit status is 5 when something changed.

```
sslknife tls diff <scan1> <scan2> | diff <target> [flags]
```

### Examples

```
  sslknife tls diff api.example.com:443
  sslknife tls diff 3f2a9c 81be02
```

### Options

```
  -h, --help   help for diff
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

* [sslknife tls](sslknife_tls.md)	 - Inspect and scan remote TLS endpoints (HTTPS, SMTP, IMAP, LDAP, databases, ...)


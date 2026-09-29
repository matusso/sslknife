## sslknife tls history

Show recorded observations of endpoints (from --save)

```
sslknife tls history [target] [flags]
```

### Examples

```
  sslknife tls history
  sslknife tls history api.example.com:443
```

### Options

```
  -h, --help        help for history
      --limit int   maximum number of observations (default 20)
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

* [sslknife tls](sslknife_tls.md)	 - Inspect and scan remote TLS endpoints (HTTPS, SMTP, IMAP, LDAP, databases, ...)


## sslknife cert list

List stored certificates

### Synopsis

List stored certificates, soonest expiry first. An optional query uses the
search language (see 'sslknife search --help').

```
sslknife cert list [query] [flags]
```

### Examples

```
  sslknife cert list
  sslknife cert list 'issuer:DigiCert expires:<90d'
  sslknife cert list --tag production --json
```

### Options

```
      --ca              only CA certificates
      --filter string   search query
  -h, --help            help for list
      --tag strings     only certificates with this tag
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

* [sslknife cert](sslknife_cert.md)	 - Inspect, create and manage X.509 certificates


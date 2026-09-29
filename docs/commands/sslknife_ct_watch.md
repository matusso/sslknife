## sslknife ct watch

Watch domains (use *.example.com to include subdomains)

```
sslknife ct watch <domain>... [flags]
```

### Examples

```
  sslknife ct watch example.com
  sslknife ct watch '*.example.com'
  sslknife ct watch example.com --subdomains
```

### Options

```
  -h, --help         help for watch
      --subdomains   include all subdomains
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

* [sslknife ct](sslknife_ct.md)	 - Monitor Certificate Transparency for your domains


## sslknife ct history

List recorded CT observations

```
sslknife ct history [domain] [flags]
```

### Examples

```
  sslknife ct history
  sslknife ct history example.com --status unexpected
```

### Options

```
  -h, --help            help for history
      --limit int       maximum number of observations (default 100)
      --status string   only this status: known, new, changed, unexpected, expired
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

* [sslknife ct](sslknife_ct.md)	 - Monitor Certificate Transparency for your domains


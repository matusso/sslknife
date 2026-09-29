## sslknife ct check

Poll CT now and record new certificates

### Synopsis

Query the CT provider for every watched domain (or one domain) and record
issuances not seen before. When ct.auto_watch_stored_sans is enabled in the
config, the DNS names of stored certificates are watched automatically.

With --strict the exit status is 5 when unexpected or changed certificates
were found (for cron jobs and CI).

Set SSLKNIFE_CERTSPOTTER_TOKEN to use a Cert Spotter API key.

```
sslknife ct check [domain] [flags]
```

### Examples

```
  sslknife ct check
  sslknife ct check example.com --provider crtsh
  sslknife ct check --strict --json
```

### Options

```
  -h, --help              help for check
      --no-auto-watch     do not add watches for stored certificate names
      --provider string   CT provider: certspotter or crtsh (default from config)
      --strict            exit 5 when unexpected or changed certificates are found
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


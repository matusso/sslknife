## sslknife cert export

Write a stored certificate (optionally with its chain) as PEM or DER

```
sslknife cert export <id|name> [flags]
```

### Examples

```
  sslknife cert export api-prod > api.pem
  sslknife cert export api-prod --chain -o fullchain.pem
```

### Options

```
      --chain        include stored issuer certificates
      --der          write DER instead of PEM
      --force        overwrite the output file
  -h, --help         help for export
  -o, --out string   output file (default stdout)
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

* [sslknife cert](sslknife_cert.md)	 - Inspect, create and manage X.509 certificates


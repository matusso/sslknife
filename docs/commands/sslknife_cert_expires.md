## sslknife cert expires

Print the expiry date and remaining days

### Synopsis

Print when the certificate expires. With --check, exit with status 5 when
the certificate expires within the given period (for monitoring scripts).

```
sslknife cert expires <file|-> [flags]
```

### Examples

```
  sslknife cert expires server.pem
  sslknife cert expires server.pem --check 30d || echo "renew soon"
```

### Options

```
      --check string   exit 5 if the certificate expires within this period (e.g. 30d)
  -h, --help           help for expires
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


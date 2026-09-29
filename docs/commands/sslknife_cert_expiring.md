## sslknife cert expiring

List stored certificates that expire soon

### Synopsis

List stored certificates expiring within a period (default: expiry.warning_days
from the config, 30 days). Exit status is 5 when any are found, so the
command can drive monitoring.

```
sslknife cert expiring [flags]
```

### Examples

```
  sslknife cert expiring
  sslknife cert expiring --within 90d --json
  sslknife cert expiring --expired
```

### Options

```
      --expired         include certificates that have already expired
  -h, --help            help for expiring
      --within string   period, e.g. 30d, 12w, 1y
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


## sslknife jks list

List keystore entries: aliases, types, chains and expiry

```
sslknife jks list <keystore> [flags]
```

### Examples

```
  sslknife jks list keystore.jks
  SSLKNIFE_KEY_PASSWORD=changeit sslknife jks list truststore.p12 --json
```

### Options

```
  -h, --help                   help for list
      --password-file string   keystore password file
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

* [sslknife jks](sslknife_jks.md)	 - Inspect, extract and convert Java keystores (JKS and PKCS#12) without keytool


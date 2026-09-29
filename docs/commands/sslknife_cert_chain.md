## sslknife cert chain

Show the certificate chain as a tree

### Synopsis

Order the certificates of a bundle (or a stored certificate and its stored
issuers) from leaf to root and display them as a tree.

```
sslknife cert chain <file|id|host:port> [flags]
```

### Examples

```
  sslknife cert chain fullchain.pem
  sslknife cert chain api-prod --verify
  sslknife cert chain fullchain.pem --verify --truststore company-root.pem
```

### Options

```
  -h, --help                help for chain
      --hostname string     also check the leaf is valid for this hostname
      --truststore string   validate against these roots instead of the system store
      --verify              validate against the system trust store
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


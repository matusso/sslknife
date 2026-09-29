## sslknife cert lint

Check a certificate or chain against RFC 5280 and CA/B Forum rules

### Synopsis

Check certificates for standards violations and risky properties. Each
finding explains WHAT is wrong, WHY it matters and the EVIDENCE found, with a
reference to the relevant RFC or CA/Browser Forum Baseline Requirement.

A bundle with several certificates is also checked as a chain (order,
missing intermediates, issuer constraints).

Exit status is 5 when an error-level finding exists (or any warning with --strict).

```
sslknife cert lint <file|-> [flags]
```

### Examples

```
  sslknife cert lint server.pem
  sslknife cert lint fullchain.pem --hostname api.example.com --trust
  sslknife cert lint chain.pem --truststore company-root.pem --json
```

### Options

```
  -h, --help                help for lint
      --hostname string     check that the certificate is valid for this hostname
      --strict              fail on warnings as well as errors
      --trust               validate the chain against the system trust store
      --truststore string   validate the chain against these root certificates (PEM/DER)
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


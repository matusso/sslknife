## sslknife ssh cert inspect

Describe an OpenSSH certificate (principals, validity, options, CA)

```
sslknife ssh cert inspect <cert-file> [flags]
```

### Examples

```
  sslknife ssh cert inspect ~/.ssh/id_ed25519-cert.pub
```

### Options

```
  -h, --help   help for inspect
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

* [sslknife ssh cert](sslknife_ssh_cert.md)	 - Inspect, sign and create OpenSSH certificates


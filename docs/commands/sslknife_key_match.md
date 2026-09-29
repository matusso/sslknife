## sslknife key match

Check whether a private key belongs to a certificate

### Synopsis

Compare the public keys of two objects: private keys, public keys,
certificates, CSRs, or stored keys/certificates, in any order.

Exit status is 0 when they match and 5 when they do not.

```
sslknife key match <key> <certificate|csr|key> [flags]
```

### Examples

```
  sslknife key match server.key server.crt
  sslknife key match api-prod-key api-prod
```

### Options

```
  -h, --help   help for match
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

* [sslknife key](sslknife_key.md)	 - Generate, inspect and manage private and public keys


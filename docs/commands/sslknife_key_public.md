## sslknife key public

Print the public key of a private key, certificate or stored key

```
sslknife key public <file|id> [flags]
```

### Examples

```
  sslknife key public server.key
  sslknife key public server.crt
  sslknife key public ~/.ssh/id_ed25519 --ssh
```

### Options

```
  -h, --help   help for public
      --ssh    print in OpenSSH authorized_keys format
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


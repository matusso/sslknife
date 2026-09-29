## sslknife ssh public

Print the public key (authorized_keys line) of a private key

```
sslknife ssh public <file|id> [flags]
```

### Examples

```
  sslknife ssh public ~/.ssh/id_ed25519
  sslknife ssh public server.key   # a PEM/PKCS#8 key works too
```

### Options

```
  -h, --help                     help for public
      --passphrase-file string   passphrase for legacy encrypted PEM keys
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

* [sslknife ssh](sslknife_ssh.md)	 - Generate, inspect, store and certify SSH keys


## sslknife ssh inspect

Describe SSH keys, authorized_keys files and certificates

### Synopsis

Describe public keys, private keys (without decrypting them when the
format includes the public key), every line of an authorized_keys file, and
OpenSSH certificates.

```
sslknife ssh inspect <file|id> [flags]
```

### Examples

```
  sslknife ssh inspect ~/.ssh/id_ed25519.pub
  sslknife ssh inspect ~/.ssh/authorized_keys
  sslknife ssh inspect id_ed25519-cert.pub --json
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

* [sslknife ssh](sslknife_ssh.md)	 - Generate, inspect, store and certify SSH keys


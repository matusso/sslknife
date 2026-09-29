## sslknife ssh import

Store SSH keys in the vault

### Synopsis

Store SSH public keys, or private keys after confirmation. Private keys are
stored exactly as the file (a passphrase-protected key stays protected by its
passphrase) inside the encrypted vault. --public-only stores just the public
key of a private key file.

```
sslknife ssh import <file>... [flags]
```

### Examples

```
  sslknife ssh import ~/.ssh/id_ed25519
  sslknife ssh import ~/.ssh/id_ed25519 --public-only
  sslknife ssh import ~/.ssh/authorized_keys --tag servers
```

### Options

```
      --comment string   override the key comment
  -h, --help             help for import
      --name string      friendly name
      --public-only      store only the public key
      --tag strings      tags
  -y, --yes              store private keys without asking
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


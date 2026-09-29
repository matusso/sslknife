## sslknife ssh export

Write a stored SSH key to a file

### Synopsis

Write the stored private key file exactly as imported (mode 0600, still
passphrase-protected if it was), or the public key with --public. Private
keys go to stdout only with --stdout --show-secret.

```
sslknife ssh export <id|name> [flags]
```

### Examples

```
  sslknife ssh export deploy-key -o ~/.ssh/deploy
  sslknife ssh export deploy-key --public >> ~/.ssh/authorized_keys
```

### Options

```
      --force         overwrite the output file
  -h, --help          help for export
  -o, --out string    output file
      --public        export the public key
      --show-secret   confirm that secret material may be printed
      --stdout        write the private key to stdout (requires --show-secret)
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


## sslknife ssh cert

Inspect, sign and create OpenSSH certificates

### Options

```
  -h, --help   help for cert
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
* [sslknife ssh cert create](sslknife_ssh_cert_create.md)	 - Generate a new key pair and certify it in one step
* [sslknife ssh cert inspect](sslknife_ssh_cert_inspect.md)	 - Describe an OpenSSH certificate (principals, validity, options, CA)
* [sslknife ssh cert sign](sslknife_ssh_cert_sign.md)	 - Sign a public key with an SSH CA


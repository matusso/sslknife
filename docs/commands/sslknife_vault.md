## sslknife vault

Manage the encrypted vault and its unlock methods

### Options

```
  -h, --help   help for vault
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

* [sslknife](sslknife.md)	 - Swiss-army knife for TLS, certificates, PKI and SSH keys
* [sslknife vault add-keychain](sslknife_vault_add-keychain.md)	 - Store an unlock key in the OS keychain
* [sslknife vault add-password](sslknife_vault_add-password.md)	 - Add a password keyslot
* [sslknife vault change-password](sslknife_vault_change-password.md)	 - Replace all password keyslots with a new password
* [sslknife vault remove-slot](sslknife_vault_remove-slot.md)	 - Remove a keyslot (the last slot cannot be removed)
* [sslknife vault status](sslknife_vault_status.md)	 - Show vault location, keyslots and contents


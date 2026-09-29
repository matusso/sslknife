## sslknife remote

Share the inventory between devices through HashiCorp Vault

### Synopsis

Share certificates, keys and SSH keys between devices through a HashiCorp
Vault KV version 2 secrets engine.

Every device keeps its own encrypted local vault (search, TLS history and CT
monitoring stay local) and syncs its inventory with Vault: certificates,
private and public keys, SSH keys, names, comments, tags and notes. Changes
merge in both directions, and deletions propagate. With remote.auto_sync
(the default) every command that opens the vault syncs before it runs and
pushes its changes afterwards; 'sslknife server' syncs every remote.interval.

Configure it in the config file ('sslknife config path'):

  remote:
    type: vault
    address: https://vault.example.com:8200
    mount: secret          # KV v2 mount
    path: sslknife         # prefix inside the mount
    auth_method: token     # token | userpass | ldap | approle
    transit_key: sslknife  # optional: encrypt private keys with Transit

Private keys are stored in Vault as PKCS#8 PEM (SSH keys as the original
file), protected by Vault's encryption at rest and ACL policies. Set
remote.transit_key to encrypt them with a Transit key first, so that reading
the KV path alone does not reveal them.

Tokens come from $VAULT_TOKEN, an AppRole login, the OS keychain ('sslknife
remote login') or ~/.vault-token, never from flags or the config file.

### Examples

```
  sslknife remote login
  sslknife remote login --method userpass --username alice
  sslknife remote status
  sslknife remote sync --dry-run
  sslknife remote sync
```

### Options

```
  -h, --help   help for remote
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

* [sslknife](sslknife.md)	 - Swiss-army knife for TLS, certificates, PKI and SSH keys
* [sslknife remote forget](sslknife_remote_forget.md)	 - Forget what was last synced, so the next sync merges both sides from scratch
* [sslknife remote login](sslknife_remote_login.md)	 - Log in to Vault and keep the token in the OS keychain
* [sslknife remote logout](sslknife_remote_logout.md)	 - Remove the stored Vault token from the OS keychain
* [sslknife remote status](sslknife_remote_status.md)	 - Show the remote configuration, token and pending changes
* [sslknife remote sync](sslknife_remote_sync.md)	 - Merge the local inventory with the Vault remote


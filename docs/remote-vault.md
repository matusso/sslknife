# Sharing between devices (HashiCorp Vault)

Several devices can share one inventory through a HashiCorp Vault KV
version 2 secrets engine. Each device keeps its own encrypted local vault and
syncs certificates, private and public keys, SSH keys, names, comments, tags
and notes with Vault. TLS scan history, CT watches and server settings stay
local to each device.

```yaml
# config.yaml on every device
remote:
  type: vault
  address: https://vault.example.com:8200   # or $VAULT_ADDR
  mount: secret                             # KV v2 mount
  path: sslknife                            # prefix inside the mount
  auth_method: token                        # token | userpass | ldap | approle
  transit_key: sslknife                     # optional, see below
```

```console
$ sslknife remote login --method userpass --username alice   # token kept in the OS keychain
$ sslknife remote status
$ sslknife cert import api.pem --name api                    # pushed to Vault straight away
Synced with Vault: 1 pushed
```

On the other device, `sslknife cert list` pulls it first.

- **Automatic sync.** With `remote.auto_sync: true` (the default), every
  command that opens the vault syncs before it runs and pushes its own changes
  afterwards. `sslknife server` syncs every `remote.interval` (5m). If Vault
  is unreachable you get a warning and the command runs on the local vault;
  the next sync catches up. `--no-sync` skips syncing for one command, and
  `sslknife remote sync [--dry-run]` syncs explicitly.
- **Merging.** Objects are matched by content (certificate SHA-256, key SPKI
  SHA-256, SSH fingerprint), so the same certificate imported on two devices
  is one object. A change on one side is copied to the other. If both sides
  changed an object, tags and notes are united and the remote name and comment
  win. Deleting an object deletes it on every device, unless another device
  changed it in the meantime. Writes use KV check-and-set on a manifest, so
  devices that sync at the same moment retry instead of overwriting each
  other.
- **Private keys** are stored as PKCS#8 PEM (SSH keys as the original file,
  still passphrase-protected if it was). Vault's encryption at rest and your
  ACL policies protect them. With `remote.transit_key` set, they are first
  encrypted with that Transit key, so reading the KV path alone reveals only
  ciphertext.
- **Authentication.** In this order: `$VAULT_TOKEN`, AppRole
  (`auth_method: approle`, `role_id`, and `$SSLKNIFE_VAULT_SECRET_ID` or
  `secret_id_file`), the token stored by `sslknife remote login` in the OS
  keychain, and `~/.vault-token`. Tokens are never taken from flags or the
  config file. `$VAULT_NAMESPACE` and `$VAULT_CACERT` are honoured as well.

A minimal policy (KV mount `secret`, path `sslknife`, Transit key `sslknife`):

```hcl
path "secret/data/sslknife/*"     { capabilities = ["create", "read", "update"] }
path "secret/metadata/sslknife/*" { capabilities = ["list", "delete"] }
path "transit/encrypt/sslknife"   { capabilities = ["update"] }
path "transit/decrypt/sslknife"   { capabilities = ["update"] }
```

Everything under the path is plain JSON, so other tools can read it too:
`vault kv get -field=certificate secret/sslknife/certificates/<sha256>`.

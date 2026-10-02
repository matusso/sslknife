# Configuration

Default locations (`sslknife config path` prints them):

| | Config | Data |
|---|---|---|
| Linux | `~/.config/sslknife/config.yaml` | `~/.local/share/sslknife/` |
| macOS | `~/Library/Application Support/sslknife/config.yaml` | `~/Library/Application Support/sslknife/` |
| Windows | `%AppData%\sslknife\config.yaml` | `%LocalAppData%\sslknife\` |

```yaml
database:
  path: ~/.local/share/sslknife/sslknife.db
vault:
  unlock_cache: 0s         # e.g. 15m: stay unlocked after a password/Touch ID unlock
tls:
  timeout: 10s
  concurrency: 8
  proxy: ""                # http://proxy:3128 or socks5://127.0.0.1:1080
ct:
  enabled: true
  provider: certspotter    # or crtsh
  interval: 15m
  auto_watch_stored_sans: true
server:
  listen: 127.0.0.1:8443
  refresh_interval: 6h
expiry:
  warning_days: 30
  critical_days: 7
remote:
  type: ""                 # "vault" to share the inventory, see remote-vault.md
  mount: secret
  path: sslknife
  auth_method: token
  auto_sync: true
  interval: 5m
```

Environment variables: `SSLKNIFE_CONFIG`, `SSLKNIFE_DATABASE`,
`SSLKNIFE_DATA_DIR`, `SSLKNIFE_PASSWORD`, `SSLKNIFE_PASSWORD_FILE`,
`SSLKNIFE_KEY_PASSWORD` (encrypted input files), `SSLKNIFE_OUT_PASSWORD`
(protected outputs), `SSLKNIFE_SSH_PASSPHRASE`, `SSLKNIFE_SERVER_TOKEN`,
`SSLKNIFE_CERTSPOTTER_TOKEN`, `SSLKNIFE_NO_KEYRING`, `SSLKNIFE_VAULT_ROLE_ID`,
`SSLKNIFE_VAULT_SECRET_ID`, `NO_COLOR`, and for the Vault remote `VAULT_ADDR`,
`VAULT_TOKEN`, `VAULT_NAMESPACE`, `VAULT_CACERT`.

## Shell completion

```sh
sslknife completion bash > /etc/bash_completion.d/sslknife
sslknife completion zsh > "${fpath[1]}/_sslknife"
sslknife completion fish > ~/.config/fish/completions/sslknife.fish
sslknife completion powershell | Out-String | Invoke-Expression
```

Stored certificate and key names are completed when the vault can be
unlocked without a prompt (keychain or environment).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | runtime error |
| 2 | invalid usage or arguments |
| 3 | object or file not found |
| 4 | vault locked or wrong password |
| 5 | check failed: lint errors, key mismatch, expiring certificates, scan findings, certificate diff |
| 6 | network or connection error |
| 7 | unsupported or impossible conversion |
| 130 | interrupted |

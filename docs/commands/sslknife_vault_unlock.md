## sslknife vault unlock

Keep the vault unlocked for a while, so commands do not ask again

### Synopsis

Unlock the vault once and keep it unlocked in a background process, like
sudo's timestamp. Every command that uses the cached key extends the time;
'sslknife vault lock' ends it at once.

The root key stays only in that process's memory (locked against swapping
where possible) and is handed out over a Unix socket in a private directory,
to processes running as your user.

Set vault.unlock_cache in the config to start the cache automatically
whenever a command asks for the password or Touch ID.

```
sslknife vault unlock [flags]
```

### Examples

```
  sslknife vault unlock
  sslknife vault unlock --for 1h
  sslknife vault lock
```

### Options

```
      --for string   idle time before locking again, e.g. 30m, 8h (default vault.unlock_cache or 15m)
  -h, --help         help for unlock
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

* [sslknife vault](sslknife_vault.md)	 - Manage the encrypted vault and its unlock methods


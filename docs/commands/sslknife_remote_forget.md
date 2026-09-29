## sslknife remote forget

Forget what was last synced, so the next sync merges both sides from scratch

### Synopsis

Forget the local record of what this device last synced with the remote.

The next sync then treats every object as new on both sides: nothing is
deleted, objects present on only one side are copied to the other, and
objects present on both are merged. Use it after restoring the local vault
from a backup, or when pointing it at a different remote.

```
sslknife remote forget [flags]
```

### Options

```
  -h, --help   help for forget
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

* [sslknife remote](sslknife_remote.md)	 - Share the inventory between devices through HashiCorp Vault


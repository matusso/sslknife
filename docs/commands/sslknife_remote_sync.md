## sslknife remote sync

Merge the local inventory with the Vault remote

### Synopsis

Merge the local inventory with the Vault remote.

Objects are matched by content (certificate SHA-256, key SPKI SHA-256, SSH
key fingerprint). An object changed on one side since the last sync is
copied to the other. When both sides changed it, tags and notes are united
and the remote name and comment win. An object deleted on one side is
deleted on the other, unless the other side changed it in the meantime.

```
sslknife remote sync [flags]
```

### Options

```
  -n, --dry-run   show what would change without changing anything
  -h, --help      help for sync
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


## sslknife ssh agent remove

Remove identities from the agent (like ssh-add -d / -D)

### Synopsis

Remove keys, and certificates of those keys, from the agent. A SHA256:
fingerprint is matched against the agent directly, without the vault.

```
sslknife ssh agent remove [<id|name|fingerprint|file>...] [flags]
```

### Examples

```
  sslknife ssh agent remove deploy-key
  sslknife ssh agent remove SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s
  sslknife ssh agent remove --all
```

### Options

```
      --all             remove every identity from the agent
  -h, --help            help for remove
      --socket string   agent socket (default $SSH_AUTH_SOCK)
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

* [sslknife ssh agent](sslknife_ssh_agent.md)	 - Load stored SSH keys into ssh-agent, or run a built-in agent


## sslknife ssh agent list

List the identities held by the agent (like ssh-add -l)

```
sslknife ssh agent list [flags]
```

### Options

```
  -h, --help            help for list
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


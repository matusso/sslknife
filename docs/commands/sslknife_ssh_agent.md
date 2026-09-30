## sslknife ssh agent

Load stored SSH keys into ssh-agent, or run a built-in agent

### Synopsis

Make SSH keys from the vault usable by ssh without writing them to disk.

'add', 'list' and 'remove' talk to the agent at $SSH_AUTH_SOCK (or --socket),
such as OpenSSH's ssh-agent. 'serve' runs an agent inside sslknife that holds
only the selected keys, for one command or until it is stopped.

Keys are chosen by vault ID, name or fingerprint, by --tag, or with --all;
private key files work too. Passphrase-protected keys are decrypted with
--passphrase-file, $SSLKNIFE_SSH_PASSPHRASE or a prompt, and a passphrase
that opened one key is tried on the next before asking again.

### Options

```
  -h, --help   help for agent
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
* [sslknife ssh agent add](sslknife_ssh_agent_add.md)	 - Load stored SSH keys into the running ssh-agent (like ssh-add)
* [sslknife ssh agent list](sslknife_ssh_agent_list.md)	 - List the identities held by the agent (like ssh-add -l)
* [sslknife ssh agent remove](sslknife_ssh_agent_remove.md)	 - Remove identities from the agent (like ssh-add -d / -D)
* [sslknife ssh agent serve](sslknife_ssh_agent_serve.md)	 - Run a built-in ssh-agent holding the selected keys


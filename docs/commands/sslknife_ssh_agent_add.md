## sslknife ssh agent add

Load stored SSH keys into the running ssh-agent (like ssh-add)

### Synopsis

Decrypt the selected keys and hand them to the agent at $SSH_AUTH_SOCK or
--socket. The keys stay in the agent's memory only. A certificate named
<file>-cert.pub next to a key file is loaded with it, as ssh-add does; use
--cert for stored keys.

```
sslknife ssh agent add [<id|name|fingerprint|file>...] [flags]
```

### Examples

```
  sslknife ssh agent add deploy-key
  sslknife ssh agent add --tag servers --lifetime 8h
  sslknife ssh agent add --all --confirm
  sslknife ssh agent add laptop --cert ~/.ssh/id_ed25519-cert.pub
```

### Options

```
      --all                      every stored SSH key that has a private key
      --cert strings             OpenSSH certificate to load with its key (repeatable)
  -c, --confirm                  require confirmation (ssh-askpass) each time a key is used
  -h, --help                     help for add
      --lifetime string          remove the keys from the agent after this long, e.g. 8h, 1d
      --passphrase-file string   read key passphrases from a file
      --socket string            agent socket (default $SSH_AUTH_SOCK)
      --tag strings              stored SSH keys with this tag (repeatable)
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


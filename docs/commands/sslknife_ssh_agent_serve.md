## sslknife ssh agent serve

Run a built-in ssh-agent holding the selected keys

### Synopsis

Start an SSH agent inside sslknife that holds the selected keys in memory.

With a command after --, the command runs with $SSH_AUTH_SOCK pointing at the
agent, and the agent stops when it exits (its exit status is returned).
Without one, the agent runs until interrupted (Ctrl-C or SIGTERM); point ssh at
it with SSH_AUTH_SOCK, or permanently in ~/.ssh/config with a fixed --socket:

  Host *.example.com
      IdentityAgent ~/.ssh/sslknife-agent.sock

The socket is created with mode 0600; by default it lives in a new private
temporary directory. Clients may add and remove keys while it runs; nothing
is written back to the vault.

```
sslknife ssh agent serve [<id|name|fingerprint|file>...] [-- <command> [args...]] [flags]
```

### Examples

```
  sslknife ssh agent serve deploy-key -- ssh deploy@web01
  sslknife ssh agent serve --tag prod -- ansible-playbook site.yml
  sslknife ssh agent serve --all --socket ~/.ssh/sslknife-agent.sock --lifetime 8h
```

### Options

```
      --all                      every stored SSH key that has a private key
      --cert strings             OpenSSH certificate to load with its key (repeatable)
  -h, --help                     help for serve
      --lifetime string          remove the keys from the agent after this long, e.g. 8h, 1d
      --passphrase-file string   read key passphrases from a file
      --socket string            socket path (default: a new private temporary directory)
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


## sslknife completion

Generate the autocompletion script for the specified shell

### Synopsis

Generate the autocompletion script for sslknife for the specified shell.
See each sub-command's help for details on how to use the generated script.


### Options

```
  -h, --help   help for completion
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
      --proxy string       proxy for outbound connections (http://, socks5://)
  -q, --quiet              suppress non-essential output
      --timeout duration   network timeout (default from config, 10s)
  -v, --verbose            verbose logging
      --yaml               output YAML
```

### SEE ALSO

* [sslknife](sslknife.md)	 - Swiss-army knife for TLS, certificates, PKI and SSH keys
* [sslknife completion bash](sslknife_completion_bash.md)	 - Generate the autocompletion script for bash
* [sslknife completion fish](sslknife_completion_fish.md)	 - Generate the autocompletion script for fish
* [sslknife completion powershell](sslknife_completion_powershell.md)	 - Generate the autocompletion script for powershell
* [sslknife completion zsh](sslknife_completion_zsh.md)	 - Generate the autocompletion script for zsh


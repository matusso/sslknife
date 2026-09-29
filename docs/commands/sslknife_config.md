## sslknife config

Show or create the configuration file

### Options

```
  -h, --help   help for config
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

* [sslknife](sslknife.md)	 - Swiss-army knife for TLS, certificates, PKI and SSH keys
* [sslknife config init](sslknife_config_init.md)	 - Write a config file with the default settings
* [sslknife config path](sslknife_config_path.md)	 - Print the config, database and key file locations
* [sslknife config show](sslknife_config_show.md)	 - Print the effective configuration


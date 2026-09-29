## sslknife remote login

Log in to Vault and keep the token in the OS keychain

### Synopsis

Log in to Vault and store the resulting token in the OS keychain, so later
commands on this device can sync without prompting.

With --method token (the default) you paste an existing token. With userpass
or ldap you enter your password and SSLKnife exchanges it for a token. The
password is read from the terminal only.

AppRole (remote.auth_method: approle) logs in on every run instead and needs
no 'login'.

```
sslknife remote login [flags]
```

### Options

```
  -h, --help              help for login
      --method string     auth method: token, userpass or ldap (default remote.auth_method)
      --username string   username for userpass/ldap (default remote.username)
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


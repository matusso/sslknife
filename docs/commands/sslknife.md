## sslknife

Swiss-army knife for TLS, certificates, PKI and SSH keys

### Synopsis

SSLKnife inspects, creates, converts and inventories X.509 certificates,
private keys and SSH keys, and analyses remote TLS endpoints.

Everything stored by SSLKnife lives in a local encrypted database, which
can be shared between devices through HashiCorp Vault ('sslknife remote').

### Options

```
      --config string      config file (default: platform config dir, or $SSLKNIFE_CONFIG)
      --database string    database file (default from config, or $SSLKNIFE_DATABASE)
      --debug              debug logging (secrets are always redacted)
      --format string      output format: text|table|json|yaml|raw (default "text")
  -h, --help               help for sslknife
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

* [sslknife cert](sslknife_cert.md)	 - Inspect, create and manage X.509 certificates
* [sslknife completion](sslknife_completion.md)	 - Generate the autocompletion script for the specified shell
* [sslknife config](sslknife_config.md)	 - Show or create the configuration file
* [sslknife convert](sslknife_convert.md)	 - Convert certificates, keys and keystores between formats
* [sslknife ct](sslknife_ct.md)	 - Monitor Certificate Transparency for your domains
* [sslknife fingerprint](sslknife_fingerprint.md)	 - Print SHA-256, SHA-1 and SPKI fingerprints
* [sslknife init](sslknife_init.md)	 - Create the encrypted SSLKnife vault
* [sslknife inspect](sslknife_inspect.md)	 - Detect a file's format and list what it contains
* [sslknife jks](sslknife_jks.md)	 - Inspect, extract and convert Java keystores (JKS and PKCS#12) without keytool
* [sslknife key](sslknife_key.md)	 - Generate, inspect and manage private and public keys
* [sslknife remote](sslknife_remote.md)	 - Share the inventory between devices through HashiCorp Vault
* [sslknife search](sslknife_search.md)	 - Search the inventory
* [sslknife server](sslknife_server.md)	 - Run the local web interface and REST API
* [sslknife ssh](sslknife_ssh.md)	 - Generate, inspect, store and certify SSH keys
* [sslknife tls](sslknife_tls.md)	 - Inspect and scan remote TLS endpoints (HTTPS, SMTP, IMAP, LDAP, databases, ...)
* [sslknife vault](sslknife_vault.md)	 - Manage the encrypted vault and its unlock methods
* [sslknife version](sslknife_version.md)	 - Print version and build information


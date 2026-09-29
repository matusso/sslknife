## sslknife jks

Inspect, extract and convert Java keystores (JKS and PKCS#12) without keytool

### Synopsis

Work with Java keystores without a JDK. JKS and PKCS#12 keystores and
truststores are supported. The store password comes from --password-file,
$SSLKNIFE_KEY_PASSWORD or a prompt (Java's default is often "changeit").

### Options

```
  -h, --help   help for jks
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
* [sslknife jks convert](sslknife_jks_convert.md)	 - Convert a keystore to PKCS#12 (default), JKS or PEM
* [sslknife jks extract](sslknife_jks_extract.md)	 - Write every entry as PEM files (<alias>.crt, <alias>.key)
* [sslknife jks inspect](sslknife_jks_inspect.md)	 - List keystore entries: aliases, types, chains and expiry
* [sslknife jks list](sslknife_jks_list.md)	 - List keystore entries: aliases, types, chains and expiry


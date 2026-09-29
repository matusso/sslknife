## sslknife tls chain

Show the certificate chain sent by the server and validate it

```
sslknife tls chain <target> [flags]
```

### Examples

```
  sslknife tls chain example.com
  sslknife tls chain mail.example.com:587 --truststore corp.pem
```

### Options

```
  -h, --help                help for chain
      --hostname string     hostname to validate (default: SNI or host)
      --ip string           connect to this IP address instead of resolving the host
  -p, --protocol string     protocol: dot, ftp, ftps, https, imap, imaps, ldap, ldaps, mqtts, mysql, pop3, pop3s, postgres, redis, sips, smtp, smtps, tls, xmpp, xmpp-server, xmpps (default: autodetect)
      --sni string          server name to send (default: the target host)
      --truststore string   validate against these roots instead of the system store
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

* [sslknife tls](sslknife_tls.md)	 - Inspect and scan remote TLS endpoints (HTTPS, SMTP, IMAP, LDAP, databases, ...)


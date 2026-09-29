## sslknife tls versions

Test which protocol versions (SSLv2–TLS 1.3) the server accepts

### Synopsis

Probe each protocol version with a dedicated ClientHello.

The target is host, host:port, [ipv6]:port or a URL such as smtp://mail.example.com.
The protocol is taken from --protocol, the URL scheme, the well-known port,
or the server's banner, in that order; otherwise direct TLS is assumed.

Only scan systems you are authorised to test. Probes are non-destructive:
raw probes stop after the server's first reply, and full handshakes send no
application data.

```
sslknife tls versions <target> [flags]
```

### Examples

```
  sslknife tls versions example.com
  sslknife tls versions imap.example.com:143
```

### Options

```
      --concurrency int   parallel probes
  -h, --help              help for versions
      --ip string         connect to this IP address instead of resolving the host
  -p, --protocol string   protocol: dot, ftp, ftps, https, imap, imaps, ldap, ldaps, mqtts, mysql, pop3, pop3s, postgres, redis, sips, smtp, smtps, tls, xmpp, xmpp-server, xmpps (default: autodetect)
      --sni string        server name to send (default: the target host)
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


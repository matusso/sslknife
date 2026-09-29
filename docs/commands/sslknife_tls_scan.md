## sslknife tls scan

Full TLS assessment: versions, ciphers, groups, certificate and behaviour

### Synopsis

Run a complete, non-destructive assessment of a TLS endpoint:

  - certificate, chain validation, hostname and expiry
  - protocol versions SSLv2 through TLS 1.3
  - every accepted cipher suite per version, with server order
  - key exchange groups and DH parameter sizes
  - secure renegotiation, TLS_FALLBACK_SCSV, compression, OCSP stapling

Findings carry a severity based on documented weaknesses (CVE, RFC) and
explain what, why and the evidence. There is no aggregate score.

With --fail-on, the exit status is 5 when a finding at or above that
severity exists (for CI pipelines).

The target is host, host:port, [ipv6]:port or a URL such as smtp://mail.example.com.
The protocol is taken from --protocol, the URL scheme, the well-known port,
or the server's banner, in that order; otherwise direct TLS is assumed.

Only scan systems you are authorised to test. Probes are non-destructive:
raw probes stop after the server's first reply, and full handshakes send no
application data.

```
sslknife tls scan <target> [flags]
```

### Examples

```
  sslknife tls scan example.com
  sslknife tls scan smtp.example.com:25 --protocol smtp
  sslknife tls scan internal.example.com:8443 --truststore corp-root.pem --fail-on high
  sslknife tls scan example.com --json > scan.json
```

### Options

```
      --concurrency int     parallel probes (default from config, 8)
      --fail-on string      exit 5 if a finding of this severity or worse exists: critical|high|medium|low|info
  -h, --help                help for scan
      --hostname string     hostname to validate (default: SNI or host)
      --ip string           connect to this IP address instead of resolving the host
      --no-ciphers          skip cipher suite enumeration
  -p, --protocol string     protocol: dot, ftp, ftps, https, imap, imaps, ldap, ldaps, mqtts, mysql, pop3, pop3s, postgres, redis, sips, smtp, smtps, tls, xmpp, xmpp-server, xmpps (default: autodetect)
      --save                record the scan in the vault history
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
      --proxy string       proxy for outbound connections (http://, socks5://)
  -q, --quiet              suppress non-essential output
      --timeout duration   network timeout (default from config, 10s)
  -v, --verbose            verbose logging
      --yaml               output YAML
```

### SEE ALSO

* [sslknife tls](sslknife_tls.md)	 - Inspect and scan remote TLS endpoints (HTTPS, SMTP, IMAP, LDAP, databases, ...)


## sslknife tls

Inspect and scan remote TLS endpoints (HTTPS, SMTP, IMAP, LDAP, databases, ...)

### Synopsis

Inspect and scan remote TLS endpoints.

The target is host, host:port, [ipv6]:port or a URL such as smtp://mail.example.com.
The protocol is taken from --protocol, the URL scheme, the well-known port,
or the server's banner, in that order; otherwise direct TLS is assumed.

Only scan systems you are authorised to test. Probes are non-destructive:
raw probes stop after the server's first reply, and full handshakes send no
application data.

### Options

```
  -h, --help   help for tls
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
* [sslknife tls alpn](sslknife_tls_alpn.md)	 - List ALPN protocols the server accepts
* [sslknife tls chain](sslknife_tls_chain.md)	 - Show the certificate chain sent by the server and validate it
* [sslknife tls ciphers](sslknife_tls_ciphers.md)	 - Enumerate accepted cipher suites per protocol version
* [sslknife tls diff](sslknife_tls_diff.md)	 - Compare two recorded observations
* [sslknife tls groups](sslknife_tls_groups.md)	 - List supported key exchange groups (including post-quantum hybrids)
* [sslknife tls history](sslknife_tls_history.md)	 - Show recorded observations of endpoints (from --save)
* [sslknife tls inspect](sslknife_tls_inspect.md)	 - Connect and show the negotiated session and certificate chain
* [sslknife tls ocsp](sslknife_tls_ocsp.md)	 - Check OCSP stapling and ask the CA's OCSP responder for the status
* [sslknife tls scan](sslknife_tls_scan.md)	 - Full TLS assessment: versions, ciphers, groups, certificate and behaviour
* [sslknife tls versions](sslknife_tls_versions.md)	 - Test which protocol versions (SSLv2–TLS 1.3) the server accepts


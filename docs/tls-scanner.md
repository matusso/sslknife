# TLS scanner

```console
$ sslknife tls inspect example.com
$ sslknife tls inspect mail.example.com:25          # SMTP STARTTLS, detected from the port
$ sslknife tls inspect ldap.corp:389 --truststore corp-root.pem
$ sslknife tls versions example.com
SSLv2     NOT SUPPORTED
SSLv3     NOT SUPPORTED
TLS 1.0   NOT SUPPORTED
TLS 1.1   NOT SUPPORTED
TLS 1.2   SUPPORTED
TLS 1.3   SUPPORTED
$ sslknife tls ciphers example.com
$ sslknife tls scan example.com --fail-on high       # CI: exit 5 on high/critical findings
```

A full scan reports the certificate, chain trust (including chains that only
validate because the OS fetched a missing intermediate), hostname, expiry,
every protocol version from SSLv2 to TLS 1.3, every accepted cipher suite per
version with server/client order, DH group sizes and ECDHE curves, TLS 1.3 key
exchange groups (including X25519MLKEM768), secure renegotiation,
TLS_FALLBACK_SCSV, compression, OCSP stapling and session resumption.
Findings carry a severity grounded in RFCs and CVEs. There is no made-up
aggregate score.

Versions, suites and groups are probed with SSLKnife's own ClientHello, which
reads only the ServerHello. Results therefore do not depend on what the local
TLS library supports.

**Protocols.** Direct TLS (HTTPS, SMTPS, IMAPS, POP3S, LDAPS, FTPS, XMPPS,
MQTT, Redis, DoT) and STARTTLS-style upgrades for SMTP, IMAP, POP3, LDAP, FTP
(AUTH TLS), XMPP (client and server), PostgreSQL and MySQL. The protocol comes
from `--protocol`, then the URL scheme (`smtp://host`), then the port, then
the server's banner, and finally direct TLS. The report says which rule
applied. `--transcript` shows the plaintext negotiation.

**History.** Add `--save` to record an observation. `tls history` and
`tls diff` then show certificate, issuer, SAN, version and cipher changes over
time.

Only scan systems you are authorised to test. Probes are non-destructive.

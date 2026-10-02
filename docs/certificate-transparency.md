# Certificate Transparency

```console
$ sslknife ct watch '*.example.com'
$ sslknife ct check
*.example.com      12 fetched, 2 new
ID        STATUS      NAMES               ISSUER         NOT BEFORE  NOT AFTER
e57190b2  unexpected  shop.example.com    Surprise CA    2026-09-28  2026-12-27
a0e20cbc  known       www.example.com     Let's Encrypt  2026-09-01  2026-11-30
$ sslknife ct history example.com --status unexpected
$ sslknife ct ack e57190b2
```

SSLKnife queries a CT search service (Cert Spotter by default, or crt.sh with
`--provider crtsh`) for watched names only. It never mirrors CT logs. Each
issuance is classified against the inventory:

- **known**: the certificate, its key or its serial is stored
- **changed**: same names as a stored certificate, but a different certificate
- **new**: not stored, from a CA already used for these names
- **unexpected**: not stored, from a CA not seen before for these names
- **expired**: no longer valid

"Unexpected" is a prompt to look, not an accusation. With
`ct.auto_watch_stored_sans` (on by default), the DNS names of stored
certificates are watched automatically. `ct check --strict` exits with status
5 on unexpected or changed issuances. Set `SSLKNIFE_CERTSPOTTER_TOKEN` for a
higher Cert Spotter rate limit.

# Server mode

```console
$ sslknife server
SSLKnife server started
https://127.0.0.1:8443/?token=3f1c…
TLS: self-signed certificate SHA-256 D6:EE:9A:…
```

The web UI (dashboard, certificate browser with chain, SANs, extensions,
findings, PEM, CT and history tabs, TLS analyzer, CT monitor, keys) runs on the
same inventory as the CLI. The REST API lives under `/api/v1` and is described
by `/api/v1/openapi.json`:

```sh
TOKEN=...   # printed at startup, or set with --token-file / $SSLKNIFE_SERVER_TOKEN
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:8443/api/v1/certificates
curl -sk -H "Authorization: Bearer $TOKEN" -X POST -d '{"target":"example.com","save":true}' \
     https://127.0.0.1:8443/api/v1/tls/scan
```

- It listens on loopback only unless `--listen` says otherwise, and prints
  warnings when exposed. Plain HTTP is refused off loopback.
- There is no default password. A random access token is printed at startup
  and exchanged for an `HttpOnly`, `SameSite=Strict` session cookie. Unsafe
  requests need a CSRF token and a same-origin `Origin`.
- A Host header allow-list blocks DNS rebinding. CSP, `nosniff`,
  frame-denial and a no-referrer policy are applied to every response.
- The HTTPS identity is self-signed, generated once and stored encrypted in
  the vault, so its fingerprint is stable. `--cert`/`--key` use your own.
- The API never returns private key material.
- Background jobs poll CT (`ct.interval`), re-inspect recorded endpoints
  (`server.refresh_interval`) and log certificates about to expire.
  `--no-jobs` disables them.

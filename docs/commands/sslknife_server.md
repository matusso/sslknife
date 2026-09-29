## sslknife server

Run the local web interface and REST API

### Synopsis

Start the SSLKnife web interface and REST API on https://127.0.0.1:8443.

The server listens on loopback by default. Open the printed URL: it contains
a one-time access token that is exchanged for a session cookie. API clients
send the token as "Authorization: Bearer <token>". The token is random for
every start unless --token-file or $SSLKNIFE_SERVER_TOKEN sets it; there is
no default password.

HTTPS uses a self-signed certificate that is generated once and stored
encrypted in the vault, so its fingerprint stays the same across restarts;
--cert/--key use your own certificate instead.

While running, the server polls Certificate Transparency (ct.interval),
re-inspects recorded TLS endpoints (server.refresh_interval) and logs
certificates entering the critical expiry window. --no-jobs disables this.

Exposing the server beyond loopback (--listen 0.0.0.0:8443) prints a warning;
plain HTTP is then refused unless --allow-insecure-http is given.

```
sslknife server [flags]
```

### Examples

```
  sslknife server
  sslknife server --listen 127.0.0.1:9443 --http
  sslknife server --listen 0.0.0.0:8443 --cert srv.pem --key srv.key --token-file /run/secrets/sslknife-token
```

### Options

```
      --allow-insecure-http    allow plain HTTP on a non-loopback address
      --allowed-host strings   additional Host header values to accept (DNS-rebinding protection)
      --cert string            TLS certificate file (PEM) instead of the self-signed one
  -h, --help                   help for server
      --http                   serve plain HTTP instead of HTTPS
      --key string             TLS private key file (PEM)
      --listen string          address to listen on (default from config, 127.0.0.1:8443)
      --no-jobs                disable background CT polling and endpoint refresh
      --token-file string      read the access token from a file
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


## sslknife cert import

Store certificates in the inventory, from files or remote servers

### Synopsis

Import every certificate in a file (PEM, DER or PKCS#7) into the vault.
Duplicates are detected by SHA-256 fingerprint. Issuers already stored are
linked automatically, as are private keys with the same public key.

If the file also contains private keys you are asked whether to store them
(or pass --with-keys --yes).

With host:port (or a URL) SSLKnife connects, shows the chain the server
presents and asks which certificates to store; --chain stores all of them,
otherwise non-interactive runs store the leaf only.

```
sslknife cert import <file|-|host:port> [flags]
```

### Examples

```
  sslknife cert import fullchain.pem --name api-prod --tag production
  sslknife cert import api.example.com:443 --chain
  sslknife cert import smtp://mail.example.com --tag mail
  sslknife cert import bundle.p7b --leaf
  cat cert.pem | sslknife cert import - --tag kubernetes
```

### Options

```
      --chain                  store the whole chain presented by a remote server
      --comment string         free-text comment
  -h, --help                   help for import
      --leaf                   import only the end-entity certificate
      --name string            friendly name for the leaf certificate
      --password-file string   password for encrypted keys in the file
      --tag strings            tags (repeatable)
      --with-keys              also store private keys found in the file
  -y, --yes                    do not ask for confirmation
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

* [sslknife cert](sslknife_cert.md)	 - Inspect, create and manage X.509 certificates


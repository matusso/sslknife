## sslknife cert csr

Create a certificate signing request (PKCS#10)

```
sslknife cert csr [flags]
```

### Examples

```
  sslknife cert csr --cn api.example.com --san www.api.example.com
  sslknife cert csr --cn api.example.com --key server.key -o api.csr
  sslknife cert csr --cn api.example.com --key api-prod-key --store
```

### Options

```
  -a, --algorithm string       algorithm for a new key (default "ecdsa-p256")
      --cn string              subject common name
      --country string         subject country (C), two letters
      --encrypt-key            encrypt the new key file
      --force                  overwrite output files
  -h, --help                   help for csr
      --key string             existing private key (file or stored key)
      --key-out string         new key output file (default <cn>.key unless --store)
      --locality string        subject locality (L)
      --org string             subject organization (O)
      --ou string              subject organizational unit (OU)
  -o, --out string             CSR output file (default <cn>.csr)
      --password-file string   password file
      --province string        subject state or province (ST)
      --san strings            subject alternative name (repeatable)
      --store                  store the new key in the vault
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


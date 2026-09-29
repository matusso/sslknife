## sslknife key export

Export a stored key to a file

### Synopsis

Write a stored private key as PKCS#8 PEM to a file with mode 0600.

Private keys are never written to the terminal unless both --stdout and
--show-secret are given. Use --public to export only the public key.

```
sslknife key export <id|name> [flags]
```

### Examples

```
  sslknife key export api-prod -o api.key
  sslknife key export api-prod -o api.key --encrypt
  sslknife key export api-prod --public
  sslknife key export api-prod --stdout --show-secret | kubectl create secret ...
```

### Options

```
      --encrypt                encrypt with a password (PBES2 AES-256)
      --force                  overwrite the output file
  -h, --help                   help for export
      --key-format string      private key format: pkcs8, pkcs1 (RSA), sec1 (EC), openssh (default "pkcs8")
  -o, --out string             output file (default <name>.key)
      --password-file string   read the encryption password from a file
      --public                 export the public key only
      --show-secret            confirm that secret material may be printed
      --stdout                 write to standard output (requires --show-secret)
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

* [sslknife key](sslknife_key.md)	 - Generate, inspect and manage private and public keys


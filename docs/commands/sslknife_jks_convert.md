## sslknife jks convert

Convert a keystore to PKCS#12 (default), JKS or PEM

```
sslknife jks convert <keystore> [flags]
```

### Examples

```
  sslknife jks convert legacy.jks                 # → legacy.p12
  sslknife jks convert legacy.jks --to pem -o legacy.pem
  sslknife jks convert truststore.jks --to pem --stdout
```

### Options

```
      --encrypt                    encrypt private keys in PEM output
      --force                      overwrite the output file
  -h, --help                       help for convert
  -o, --out string                 output file
      --out-password-file string   password for the output
      --password-file string       keystore password file
      --show-secret                allow private key material on standard output
      --stdout                     write to standard output
  -t, --to string                  target format: pkcs12, jks, pem (default "pkcs12")
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

* [sslknife jks](sslknife_jks.md)	 - Inspect, extract and convert Java keystores (JKS and PKCS#12) without keytool


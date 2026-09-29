## sslknife fingerprint

Print SHA-256, SHA-1 and SPKI fingerprints

### Synopsis

Print fingerprints of certificates, CSRs and keys.

SHA-256 identifies the certificate. SPKI SHA-256 identifies the public key
(stable across renewals with the same key, used for HPKP-style pinning).
SHA-1 is shown only as a legacy identifier for older tools; it is not a
recommended hash for any security purpose.

```
sslknife fingerprint <file|-> [flags]
```

### Examples

```
  sslknife fingerprint cert.pem
  sslknife fingerprint server.key --json
```

### Options

```
  -h, --help    help for fingerprint
      --plain   print lowercase hex without colons
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
      --no-sync            do not sync with the Vault remote for this command
      --proxy string       proxy for outbound connections (http://, socks5://)
  -q, --quiet              suppress non-essential output
      --timeout duration   network timeout (default from config, 10s)
  -v, --verbose            verbose logging
      --yaml               output YAML
```

### SEE ALSO

* [sslknife](sslknife.md)	 - Swiss-army knife for TLS, certificates, PKI and SSH keys


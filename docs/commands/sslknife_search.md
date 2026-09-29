## sslknife search

Search the inventory

### Synopsis

Search stored certificates and keys. All terms must match.

  example.com            substring of name, CN, subject, issuer or any SAN
  name:api cn:api        friendly name / subject common name
  subject:"Example Inc"  subject DN substring (quote values with spaces)
  issuer:DigiCert        issuer DN substring
  san:example.com        SAN substring
  serial:0a1b            serial number
  fingerprint:ab12cd     SHA-256 or SHA-1 fingerprint prefix
  spki:ab12              public key (SPKI SHA-256) prefix
  algorithm:rsa          key algorithm, e.g. rsa, rsa4096, p256, ed25519
  tag:production         tag
  type:cert|key|ssh|ca|leaf|root|private|public
  status:expired|expiring|valid|future
  expires:<30d           expires within 30 days (also >90d, <=2027-01-01, =2026-12-31)
  source:created         where the object came from
  -tag:legacy            prefix any term with - to negate it

```
sslknife search <query> [flags]
```

### Examples

```
  sslknife search 'expires:<30d'
  sslknife search 'issuer:"Let'"'"'s Encrypt" -tag:staging'
  sslknife search 'type:key algorithm:rsa' --json
```

### Options

```
  -h, --help   help for search
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


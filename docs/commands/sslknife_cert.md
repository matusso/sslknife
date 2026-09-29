## sslknife cert

Inspect, create and manage X.509 certificates

### Options

```
  -h, --help   help for cert
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
* [sslknife cert chain](sslknife_cert_chain.md)	 - Show the certificate chain as a tree
* [sslknife cert create](sslknife_cert_create.md)	 - Create a certificate: self-signed, CA-signed, root or intermediate CA
* [sslknife cert csr](sslknife_cert_csr.md)	 - Create a certificate signing request (PKCS#10)
* [sslknife cert delete](sslknife_cert_delete.md)	 - Delete stored certificates
* [sslknife cert diff](sslknife_cert_diff.md)	 - Compare two certificates field by field
* [sslknife cert expires](sslknife_cert_expires.md)	 - Print the expiry date and remaining days
* [sslknife cert expiring](sslknife_cert_expiring.md)	 - List stored certificates that expire soon
* [sslknife cert export](sslknife_cert_export.md)	 - Write a stored certificate (optionally with its chain) as PEM or DER
* [sslknife cert import](sslknife_cert_import.md)	 - Store certificates in the inventory, from files or remote servers
* [sslknife cert inspect](sslknife_cert_inspect.md)	 - Show everything about a certificate or bundle
* [sslknife cert issuer](sslknife_cert_issuer.md)	 - Print the issuer distinguished name
* [sslknife cert lint](sslknife_cert_lint.md)	 - Check a certificate or chain against RFC 5280 and CA/B Forum rules
* [sslknife cert list](sslknife_cert_list.md)	 - List stored certificates
* [sslknife cert note](sslknife_cert_note.md)	 - Attach a note to a stored certificate
* [sslknife cert pem](sslknife_cert_pem.md)	 - Convert certificates to PEM (or DER with --der)
* [sslknife cert rename](sslknife_cert_rename.md)	 - Set a stored certificate's friendly name (and optionally comment)
* [sslknife cert sans](sslknife_cert_sans.md)	 - Print Subject Alternative Names, one per line
* [sslknife cert show](sslknife_cert_show.md)	 - Show a stored certificate with its chain, key and notes
* [sslknife cert subject](sslknife_cert_subject.md)	 - Print the subject distinguished name
* [sslknife cert tag](sslknife_cert_tag.md)	 - Add tags to a stored certificate
* [sslknife cert untag](sslknife_cert_untag.md)	 - Remove tags from a stored certificate


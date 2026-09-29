## sslknife ct

Monitor Certificate Transparency for your domains

### Synopsis

Watch domains in Certificate Transparency and record every certificate
issued for them. SSLKnife queries CT search services (Cert Spotter by
default, or crt.sh) for watched names only; it never mirrors CT logs.

Observations are classified against the inventory:

  known       the certificate, its key or its serial is stored in SSLKnife
  changed     same names as a stored certificate, but a different certificate
  new         not stored, from a CA already used for these names
  unexpected  not stored, from a CA not seen before for these names
  expired     no longer valid

"unexpected" does not mean malicious; it means worth a look.

### Options

```
  -h, --help   help for ct
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
* [sslknife ct ack](sslknife_ct_ack.md)	 - Mark observations as expected (their issuer then counts as known)
* [sslknife ct check](sslknife_ct_check.md)	 - Poll CT now and record new certificates
* [sslknife ct history](sslknife_ct_history.md)	 - List recorded CT observations
* [sslknife ct list](sslknife_ct_list.md)	 - List watched domains and what has been seen for them
* [sslknife ct unwatch](sslknife_ct_unwatch.md)	 - Stop watching a domain and delete its observations
* [sslknife ct watch](sslknife_ct_watch.md)	 - Watch domains (use *.example.com to include subdomains)


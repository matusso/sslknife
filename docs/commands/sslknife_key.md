## sslknife key

Generate, inspect and manage private and public keys

### Options

```
  -h, --help   help for key
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
* [sslknife key delete](sslknife_key_delete.md)	 - Delete a stored key and its private material
* [sslknife key export](sslknife_key_export.md)	 - Export a stored key to a file
* [sslknife key generate](sslknife_key_generate.md)	 - Generate a new private key
* [sslknife key import](sslknife_key_import.md)	 - Store keys from a file in the encrypted vault
* [sslknife key inspect](sslknife_key_inspect.md)	 - Describe a private or public key (never prints key material)
* [sslknife key list](sslknife_key_list.md)	 - List stored keys
* [sslknife key match](sslknife_key_match.md)	 - Check whether a private key belongs to a certificate
* [sslknife key public](sslknife_key_public.md)	 - Print the public key of a private key, certificate or stored key
* [sslknife key rename](sslknife_key_rename.md)	 - Change a stored key's friendly name
* [sslknife key show](sslknife_key_show.md)	 - Show a stored key's metadata
* [sslknife key tag](sslknife_key_tag.md)	 - Add tags to a stored key
* [sslknife key untag](sslknife_key_untag.md)	 - Remove tags from a stored key


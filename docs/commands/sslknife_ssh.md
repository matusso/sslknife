## sslknife ssh

Generate, inspect, store and certify SSH keys

### Options

```
  -h, --help   help for ssh
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
* [sslknife ssh cert](sslknife_ssh_cert.md)	 - Inspect, sign and create OpenSSH certificates
* [sslknife ssh convert](sslknife_ssh_convert.md)	 - Convert SSH keys: openssh, pkcs8, pem, ssh (authorized_keys), rfc4716
* [sslknife ssh delete](sslknife_ssh_delete.md)	 - Delete a stored SSH key
* [sslknife ssh export](sslknife_ssh_export.md)	 - Write a stored SSH key to a file
* [sslknife ssh fingerprint](sslknife_ssh_fingerprint.md)	 - Print SSH key fingerprints (SHA256; MD5 with --md5)
* [sslknife ssh generate](sslknife_ssh_generate.md)	 - Generate an SSH key pair (like ssh-keygen)
* [sslknife ssh import](sslknife_ssh_import.md)	 - Store SSH keys in the vault
* [sslknife ssh inspect](sslknife_ssh_inspect.md)	 - Describe SSH keys, authorized_keys files and certificates
* [sslknife ssh list](sslknife_ssh_list.md)	 - List stored SSH keys
* [sslknife ssh public](sslknife_ssh_public.md)	 - Print the public key (authorized_keys line) of a private key
* [sslknife ssh show](sslknife_ssh_show.md)	 - Show a stored SSH key
* [sslknife ssh tag](sslknife_ssh_tag.md)	 - Tag a stored SSH key


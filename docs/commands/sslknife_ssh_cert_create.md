## sslknife ssh cert create

Generate a new key pair and certify it in one step

### Synopsis

Generate a new key pair and certify it in one step.

User certificates get OpenSSH's default permissions (pty, forwarding, user rc)
unless --extension is given; host certificates carry none. RSA CAs sign with
rsa-sha2-512. --option sets critical options such as force-command=/bin/true
or source-address=10.0.0.0/8.

```
sslknife ssh cert create [flags]
```

### Examples

```
  sslknife ssh cert sign --ca ca_key --key id_ed25519.pub --principal alice --id alice@corp --validity 8h
  sslknife ssh cert sign --ca ssh-ca --key host_key.pub --host --principal web01.example.com --validity 52w
  sslknife ssh cert create --ca ssh-ca --principal deploy --validity 1h -o deploy_key --no-passphrase
```

### Options

```
      --ca string                CA private key (file or stored SSH key)
      --extension strings        user certificate extensions (default OpenSSH set)
      --force                    overwrite output files
  -h, --help                     help for create
      --host                     issue a host certificate
  -I, --id string                certificate key ID (appears in server logs)
      --no-passphrase            do not protect the new private key
  -O, --option strings           critical options, e.g. force-command=/bin/ls
  -o, --out string               output file
      --passphrase-file string   passphrase for the CA key
  -n, --principal strings        user or host names (repeatable)
      --serial uint              serial number (default random)
  -t, --type string              type of the new key (default "ed25519")
  -V, --validity string          validity period, e.g. 8h, 30d, forever
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

* [sslknife ssh cert](sslknife_ssh_cert.md)	 - Inspect, sign and create OpenSSH certificates


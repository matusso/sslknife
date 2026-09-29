## sslknife ssh convert

Convert SSH keys: openssh, pkcs8, pem, ssh (authorized_keys), rfc4716

### Synopsis

Convert between SSH key formats. Private keys: openssh (new OpenSSH format),
pkcs8 and pem (PKCS#8 PEM). Public keys: ssh (authorized_keys) and rfc4716.
Encrypted keys are decrypted with --passphrase-file, $SSLKNIFE_SSH_PASSPHRASE
or a prompt; add --encrypt to protect the output.

```
sslknife ssh convert <file> [flags]
```

### Examples

```
  sslknife ssh convert id_rsa --to pkcs8 -o id_rsa.pem
  sslknife ssh convert id_ed25519.pub --to rfc4716 --stdout
  sslknife ssh convert key.pem --to openssh --encrypt -o id_new
```

### Options

```
      --encrypt                  protect the output private key with a passphrase
      --force                    overwrite the output file
  -h, --help                     help for convert
  -o, --out string               output file
      --passphrase-file string   passphrase for the input key
      --show-secret              allow private keys on standard output
      --stdout                   write to standard output
  -t, --to string                target format
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

* [sslknife ssh](sslknife_ssh.md)	 - Generate, inspect, store and certify SSH keys


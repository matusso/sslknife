## sslknife ssh generate

Generate an SSH key pair (like ssh-keygen)

### Synopsis

Generate an SSH key pair in OpenSSH format: <out> (private, mode 0600) and
<out>.pub. On a terminal you are asked for a passphrase (empty for none);
otherwise $SSLKNIFE_SSH_PASSPHRASE or --passphrase-file is used, or
--no-passphrase must be given.

```
sslknife ssh generate [flags]
```

### Examples

```
  sslknife ssh generate
  sslknife ssh generate --type ecdsa-p384 -o ~/.ssh/id_ecdsa -C alice@laptop
  sslknife ssh generate --no-passphrase --store --name deploy-key
```

### Options

```
  -C, --comment string           comment (default user@host)
      --force                    overwrite existing files
  -h, --help                     help for generate
      --name string              friendly name in the vault
      --no-passphrase            do not protect the private key
  -o, --out string               private key file (default ./id_<type>)
      --passphrase-file string   read the passphrase from a file
      --store                    also store the key in the vault
      --tag strings              tags in the vault
  -t, --type string              key type: ed25519, ecdsa-p256, ecdsa-p384, ecdsa-p521, rsa-3072, rsa-4096 (default "ed25519")
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


## sslknife convert

Convert certificates, keys and keystores between formats

### Synopsis

Convert between certificate, key and keystore formats. The input format is
detected from the content (PEM, DER, PKCS#7, PKCS#8, PKCS#1, SEC1, PKCS#12,
JKS, OpenSSH, authorized_keys, RFC 4716). Several inputs are merged, so a
certificate and a key can be combined into one PKCS#12 or JKS file.

Target formats:
  pem      PEM text: certificates, keys (PKCS#8), CSRs, public keys
  der      binary DER of exactly one object
  pkcs7    PKCS#7 / .p7b certificate bundle (certificates only)
  pkcs8    PKCS#8 private key (encrypted with --out-password)
  pkcs1    PKCS#1 RSA private or public key
  sec1     SEC1 EC private key
  spki     PKIX SubjectPublicKeyInfo public key
  pkcs12   PKCS#12 / PFX keystore or truststore
  jks      Java KeyStore
  openssh  OpenSSH private key
  ssh      OpenSSH authorized_keys public key line(s)
  rfc4716  RFC 4716 SSH2 public key

When the target cannot represent the input (DER with several objects, a
private key in a certificate bundle, an EC key as PKCS#1, ...) the command
fails with exit status 7 and explains why; nothing is dropped silently.

Output goes to a file (default: input name with a new extension; mode 0600
when it contains private keys). --stdout prints non-secret results; secret
results also need --show-secret.

Passwords: input passwords come from --password-file, $SSLKNIFE_KEY_PASSWORD
or a prompt; output passwords from --out-password-file, $SSLKNIFE_OUT_PASSWORD
or a prompt. They are never accepted as command-line values.

```
sslknife convert <input>... --to <format> [flags]
```

### Examples

```
  sslknife convert server.der --to pem --stdout
  sslknife convert server.p12 --to pem -o server.pem
  sslknife convert cert.pem key.pem chain.pem --to pkcs12 -o bundle.p12
  sslknife convert keystore.jks --to pkcs12
  sslknife convert truststore.jks --to pem --certs-only --stdout
  sslknife convert id_ed25519 --to ssh --stdout
```

### Options

```
      --alias string               alias for the key entry in a JKS output
      --certs-only                 convert only the certificates
      --der                        binary DER output for pkcs1/pkcs8/sec1/spki/pkcs7
      --encrypt                    encrypt private keys in pem/pkcs8/openssh output
      --force                      overwrite the output file
  -h, --help                       help for convert
      --keys-only                  convert only the keys
  -o, --out string                 output file
      --out-password-file string   password for the output
      --password-file string       password for encrypted inputs
      --show-secret                allow private key material on standard output
      --stdout                     write to standard output
  -t, --to string                  target format
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


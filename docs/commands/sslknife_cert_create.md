## sslknife cert create

Create a certificate: self-signed, CA-signed, root or intermediate CA

### Synopsis

Create certificates for TLS servers and clients, code signing, S/MIME, and
root or intermediate CAs.

Without flags on a terminal, an interactive wizard asks for the details.
With --ca the certificate is signed by an existing CA (a stored certificate
with a linked private key, or files given with --ca and --ca-key); otherwise
it is self-signed. --csr signs an existing certificate request.

Serial numbers carry 128 random bits. Key usages follow the profile:
servers get digitalSignature (+keyEncipherment for RSA) and serverAuth;
CAs get keyCertSign/cRLSign with a critical basicConstraints.

Types: server, client, server-client, code-signing, email, root-ca, intermediate-ca

```
sslknife cert create [flags]
```

### Examples

```
  sslknife cert create                                   # wizard
  sslknife cert create --type root-ca --cn "Example Root CA" --algorithm ecdsa-p384 --store --name root
  sslknife cert create --type intermediate-ca --cn "Example Issuing CA" --ca root --path-len 0 --store --name issuing
  sslknife cert create --cn api.example.com --san www.api.example.com --ca issuing --validity 90d
  sslknife cert create --type client --cn alice --san alice@example.com --ca issuing -o alice.crt --key-out alice.key
  sslknife cert create --csr request.csr --ca issuing -o signed.crt
```

### Options

```
  -a, --algorithm string       algorithm for a new key (default "ecdsa-p256")
      --ca string              issuer certificate (stored certificate or file)
      --ca-key string          issuer private key (file or stored key; default: key linked to --ca)
      --cn string              subject common name
      --country string         subject country (C), two letters
      --csr string             sign this certificate request instead of generating a key
      --encrypt-key            encrypt the private key file with a password
      --force                  overwrite output files
  -h, --help                   help for create
  -i, --interactive            run the interactive wizard
      --key string             use an existing private key (file or stored key)
      --key-out string         private key output file (default <cn>.key unless --store)
      --locality string        subject locality (L)
      --name string            friendly name in the vault
      --org string             subject organization (O)
      --ou string              subject organizational unit (OU)
  -o, --out string             certificate output file (default <cn>.crt unless --store)
      --password-file string   password file for --encrypt-key or encrypted input keys
      --path-len int           CA path length constraint (-1: none) (default -1)
      --province string        subject state or province (ST)
      --san strings            subject alternative name: DNS, IP, e-mail or URI (repeatable)
      --store                  store the certificate and new key in the vault
      --tag strings            tags in the vault (repeatable)
  -t, --type string            certificate type (default "server")
      --validity string        validity period (default 365d; 1825d intermediate; 3650d root)
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

* [sslknife cert](sslknife_cert.md)	 - Inspect, create and manage X.509 certificates


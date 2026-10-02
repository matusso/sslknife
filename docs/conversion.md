# Conversion and keystores

The input format is detected from content, never from the file name:

```console
$ sslknife inspect mycert
File:               mycert
Detected format:    PKCS#12
Contains:           1 private key
                    1 leaf certificate
                    2 intermediate certificates
Password protected: yes

$ sslknife convert server.der --to pem --stdout
$ sslknife convert server.p12 --to pem -o server.pem
$ sslknife convert cert.pem key.pem chain.pem --to pkcs12 -o bundle.p12
$ sslknife convert keystore.jks --to pkcs12
$ sslknife convert truststore.jks --to pem --certs-only --stdout
$ sslknife jks list keystore.jks
$ sslknife jks extract keystore.jks --dir extracted/
```

| Format | Read | Write |
|---|---|---|
| PEM (certificates, keys, CSRs, public keys) | ✓ | ✓ |
| DER certificate / key / CSR / SPKI | ✓ | ✓ (one object) |
| PKCS#7 / .p7b | ✓ | ✓ (certificates only) |
| PKCS#8 (plain, and encrypted PBES2 incl. scrypt) | ✓ | ✓ (PBKDF2-SHA256 + AES-256-CBC) |
| PKCS#1 RSA / SEC1 EC | ✓ | ✓ |
| Legacy encrypted PEM (`Proc-Type: 4,ENCRYPTED`) | ✓ | — (use PKCS#8) |
| PKCS#12 / PFX, keystores and truststores | ✓ | ✓ |
| Java JKS | ✓ | ✓ |
| Java JCEKS | detected, explained | — |
| OpenSSH private key (plain / encrypted) | ✓ | ✓ |
| authorized_keys, RFC 4716 | ✓ | ✓ |

When a conversion would lose or misrepresent data, SSLKnife refuses with exit
status 7 and explains why. Examples: several objects to DER, a private key
into a .p7b, an EC key as PKCS#1, a certificate as an SSH key.

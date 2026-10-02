# Certificate inventory

```console
$ sslknife cert import fullchain.pem --name api-prod --tag production
$ sslknife cert import api.example.com:443 --chain      # fetch and store what the server sends
$ sslknife key import server.key --name api-prod-key    # asks before storing private keys
$ sslknife cert list
ID        NAME      CN                  EXPIRES     DAYS  ALGORITHM    STATUS
d33d5147  api-prod  api.example.com     2026-10-19  19    ECDSA P-256  WARNING
9f2aeb63  vpn       vpn.example.com     2026-12-28  89    RSA 2048     OK
d74168f9  issuing   Example Issuing CA  2031-09-28  1824  ECDSA P-256  CA
$ sslknife cert show api-prod           # details, chain tree, linked key, notes
$ sslknife cert expiring --within 90d   # exit status 5 when something is found
```

Issuers and private keys are linked automatically in both directions, however
the objects are imported. Objects are addressed by ID, ID prefix, name or
fingerprint prefix.

Search uses a small query language:

```console
$ sslknife search 'expires:<30d'
$ sslknife search 'issuer:DigiCert -tag:staging'
$ sslknife search 'type:key algorithm:rsa'
$ sslknife search 'type:ssh tag:servers'
```

Fields: `name cn subject issuer san serial fingerprint spki algorithm tag type
status expires source id`. `expires` accepts `<30d`, `>1y`, `<=2027-01-01`.
Prefix a term with `-` to negate it.

**Lint** checks certificates and chains against RFC 5280, RFC 6125 and the
CA/Browser Forum Baseline Requirements. Each finding states what is wrong, why
it matters, the evidence, and the rule it comes from:

```console
$ sslknife cert lint fullchain.pem --hostname api.example.com --trust
WARNING  missing_intermediate  api.example.com
  WHAT     chain is incomplete
  WHY      clients without the missing issuer cached cannot build a path to a trusted root
  EVIDENCE no certificate for issuer CN=R11,O=Let's Encrypt,C=US (AIA caIssuers: http://r11.i.lencr.org/)
  REF      RFC 5280 §6
```

**Diff** compares any two certificates (files, stored or remote):

```console
$ sslknife cert diff old.pem new.pem --changed
SAN:
+ new.example.com
Expiration:
- 2026-10-01T00:00:00Z
+ 2027-10-01T00:00:00Z
```

Supported key algorithms: Ed25519, ECDSA P-256/P-384/P-521, RSA
2048/3072/4096, and ML-DSA-44/65/87 (FIPS 204). SSLKnife refuses to generate
RSA keys below 2048 bits.

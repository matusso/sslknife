package converter

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/matusso/sslknife/internal/certificate"
	skcrypto "github.com/matusso/sslknife/internal/crypto"
	"github.com/matusso/sslknife/internal/keys"
)

// Kind classifies bundle objects.
type Kind string

const (
	KindCertificate Kind = "certificate"
	KindPrivateKey  Kind = "private_key"
	KindPublicKey   Kind = "public_key"
	KindCSR         Kind = "csr"
)

// Object is one item decoded from a container.
type Object struct {
	Kind    Kind
	Alias   string
	Cert    *x509.Certificate
	Key     crypto.PrivateKey
	Public  crypto.PublicKey
	CSR     *x509.CertificateRequest
	Comment string
	// Trusted marks JKS/PKCS#12 trusted-certificate entries.
	Trusted bool
	Created time.Time
}

// PublicKey returns the public key carried or implied by the object.
func (o Object) PublicKey() crypto.PublicKey {
	switch o.Kind {
	case KindCertificate:
		return o.Cert.PublicKey
	case KindPrivateKey:
		p, _ := keys.Public(o.Key)
		return p
	case KindCSR:
		return o.CSR.PublicKey
	}
	return o.Public
}

// Bundle is the decoded content of one or more inputs.
type Bundle struct {
	Format    Format
	Encrypted bool // container or key was password protected
	Objects   []Object
	Notes     []string
}

// Count returns the number of objects of kind k.
func (b *Bundle) Count(k Kind) int {
	n := 0
	for _, o := range b.Objects {
		if o.Kind == k {
			n++
		}
	}
	return n
}

// Certificates returns all certificates.
func (b *Bundle) Certificates() []*x509.Certificate {
	var out []*x509.Certificate
	for _, o := range b.Objects {
		if o.Kind == KindCertificate {
			out = append(out, o.Cert)
		}
	}
	return out
}

// Filter keeps only objects of the given kinds.
func (b *Bundle) Filter(kinds ...Kind) *Bundle {
	nb := *b
	nb.Objects = nil
	for _, o := range b.Objects {
		for _, k := range kinds {
			if o.Kind == k {
				nb.Objects = append(nb.Objects, o)
			}
		}
	}
	return &nb
}

// Merge appends another bundle's objects, skipping duplicate certificates.
func (b *Bundle) Merge(o *Bundle) {
	seen := map[string]bool{}
	for _, x := range b.Objects {
		if x.Cert != nil {
			seen[string(x.Cert.Raw)] = true
		}
	}
	for _, x := range o.Objects {
		if x.Cert != nil && seen[string(x.Cert.Raw)] {
			continue
		}
		b.Objects = append(b.Objects, x)
	}
	b.Encrypted = b.Encrypted || o.Encrypted
	b.Notes = append(b.Notes, o.Notes...)
}

// DecodeOptions supply passwords on demand.
type DecodeOptions struct {
	Password keys.PasswordFunc // store / file password
	// KeyPassword is used for JKS private key entries whose password differs
	// from the store password; nil reuses the store password.
	KeyPassword keys.PasswordFunc
}

// ErrUnsupported marks formats that are recognised but cannot be read.
var ErrUnsupported = errors.New("unsupported format")

// Decode detects the format of data and decodes its objects.
func Decode(data []byte, o DecodeOptions) (*Bundle, error) {
	f := Detect(data)
	b := &Bundle{Format: f}
	var err error
	switch f {
	case FormatPEM, FormatOpenSSH:
		err = decodePEM(data, o, b)
	case FormatDER:
		certs, e := x509.ParseCertificates(data)
		err = e
		for _, c := range certs {
			b.Objects = append(b.Objects, Object{Kind: KindCertificate, Cert: c})
		}
	case FormatPKCS7:
		certs, e := certificate.ParsePKCS7(data)
		err = e
		for _, c := range certs {
			b.Objects = append(b.Objects, Object{Kind: KindCertificate, Cert: c})
		}
	case FormatPKCS8, FormatPKCS1, FormatSEC1:
		if isEncryptedPKCS8(data) {
			err = decodePEM(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: data}), o, b)
			break
		}
		if pk, e := keys.ParsePrivateKey(data, nil); e == nil {
			b.Objects = append(b.Objects, Object{Kind: KindPrivateKey, Key: pk.Key})
		} else if pub, e2 := keys.ParsePublicKey(data); e2 == nil {
			b.Objects = append(b.Objects, Object{Kind: KindPublicKey, Public: pub.Key})
		} else {
			err = e
		}
	case FormatSPKI, FormatSSHPublic, FormatRFC4716:
		pub, e := keys.ParsePublicKey(data)
		err = e
		if e == nil {
			b.Objects = append(b.Objects, Object{Kind: KindPublicKey, Public: pub.Key, Comment: pub.Comment})
		}
	case FormatCSR:
		csr, e := certificate.ParseCSR(data)
		err = e
		if e == nil {
			b.Objects = append(b.Objects, Object{Kind: KindCSR, CSR: csr})
		}
	case FormatPKCS12:
		err = decodePKCS12(data, o, b)
	case FormatJKS:
		err = decodeJKS(data, o, b)
	case FormatJCEKS:
		return b, fmt.Errorf("%w: JCEKS keystores use Sun's proprietary PBEWithMD5AndTripleDES key protection, which SSLKnife does not implement; JKS and PKCS#12 are supported", ErrUnsupported)
	default:
		return b, fmt.Errorf("%w: the input is not a recognised certificate, key or keystore format", ErrUnsupported)
	}
	if err != nil {
		return b, err
	}
	if len(b.Objects) == 0 {
		return b, errors.New("no certificates or keys found")
	}
	return b, nil
}

func decodePEM(data []byte, o DecodeOptions, b *Bundle) error {
	var password []byte
	getPW := func() ([]byte, error) {
		if password != nil {
			return password, nil
		}
		if o.Password == nil {
			return nil, keys.ErrPasswordRequired
		}
		p, err := o.Password()
		if err == nil {
			password = p
		}
		return p, err
	}
	defer skcrypto.Zero(password)
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		one := pem.EncodeToMemory(block)
		alias := block.Headers["friendlyName"]
		switch {
		case block.Type == "CERTIFICATE" || block.Type == "X509 CERTIFICATE" || block.Type == "TRUSTED CERTIFICATE" ||
			block.Type == "PKCS7" || block.Type == "CMS":
			certs, err := certificate.Parse(one)
			if err != nil {
				return err
			}
			for _, c := range certs {
				b.Objects = append(b.Objects, Object{Kind: KindCertificate, Cert: c, Alias: alias})
			}
		case keys.IsPrivateKeyBlock(block.Type):
			pk, err := keys.ParsePrivateKey(one, getPW)
			if err != nil {
				return err
			}
			b.Encrypted = b.Encrypted || pk.Encrypted
			b.Objects = append(b.Objects, Object{Kind: KindPrivateKey, Key: pk.Key, Alias: alias, Comment: pk.Comment})
		case block.Type == "CERTIFICATE REQUEST" || block.Type == "NEW CERTIFICATE REQUEST":
			csr, err := certificate.ParseCSR(one)
			if err != nil {
				return err
			}
			b.Objects = append(b.Objects, Object{Kind: KindCSR, CSR: csr})
		case block.Type == "PUBLIC KEY" || block.Type == "RSA PUBLIC KEY":
			pub, err := keys.ParsePublicKey(one)
			if err != nil {
				return err
			}
			b.Objects = append(b.Objects, Object{Kind: KindPublicKey, Public: pub.Key})
		default:
			b.Notes = append(b.Notes, fmt.Sprintf("skipped unsupported PEM block %q", block.Type))
		}
	}
	return nil
}

// decodePKCS12 tries an empty password first so unprotected files open
// without prompting.
func decodePKCS12(data []byte, o DecodeOptions, b *Bundle) error {
	objs, err := pkcs12Objects(data, "")
	if errors.Is(err, pkcs12.ErrIncorrectPassword) {
		if o.Password == nil {
			return keys.ErrPasswordRequired
		}
		pw, perr := o.Password()
		if perr != nil {
			return perr
		}
		objs, err = pkcs12Objects(data, string(pw))
		skcrypto.Zero(pw)
		if errors.Is(err, pkcs12.ErrIncorrectPassword) {
			return keys.ErrIncorrectPassword
		}
		b.Encrypted = true
	}
	if err != nil {
		return fmt.Errorf("PKCS#12: %w", err)
	}
	b.Objects = append(b.Objects, objs...)
	return nil
}

// pkcs12Objects decodes key stores with ToPEM and certificate-only trust
// stores (a single safe, as written by Java and EncodeTrustStore) with
// DecodeTrustStore.
func pkcs12Objects(data []byte, password string) ([]Object, error) {
	// ToPEM is deprecated because it labels PKCS#1/SEC1 keys as "PRIVATE
	// KEY"; the blocks are re-parsed below with every key encoding. It is
	// used because DecodeChain cannot read files holding several entries.
	blocks, err := pkcs12.ToPEM(data, password) //nolint:staticcheck // deprecated for its mislabelled keys, handled here
	var notImpl pkcs12.NotImplementedError
	if errors.As(err, &notImpl) {
		certs, terr := pkcs12.DecodeTrustStore(data, password)
		if terr != nil {
			return nil, terr
		}
		var out []Object
		for _, c := range certs {
			out = append(out, Object{Kind: KindCertificate, Cert: c, Trusted: true})
		}
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Object
	for _, bl := range blocks {
		alias := bl.Headers["friendlyName"]
		switch {
		case keys.IsPrivateKeyBlock(bl.Type):
			// ToPEM labels every key "PRIVATE KEY" although the bytes may be
			// PKCS#1 or SEC1; parse the DER with every encoding.
			pk, err := keys.ParsePrivateKey(bl.Bytes, nil)
			if err != nil {
				return nil, fmt.Errorf("key: %w", err)
			}
			out = append(out, Object{Kind: KindPrivateKey, Key: pk.Key, Alias: alias})
		case bl.Type == "CERTIFICATE":
			c, err := x509.ParseCertificate(bl.Bytes)
			if err != nil {
				return nil, fmt.Errorf("certificate: %w", err)
			}
			out = append(out, Object{Kind: KindCertificate, Cert: c, Alias: alias})
		}
	}
	return out, nil
}

func decodeJKS(data []byte, o DecodeOptions, b *Bundle) error {
	if o.Password == nil {
		return keys.ErrPasswordRequired
	}
	pw, err := o.Password()
	if err != nil {
		return err
	}
	defer skcrypto.Zero(pw)
	ks := keystore.New(keystore.WithCaseExactAliases(), keystore.WithOrderedAliases())
	if err := ks.Load(bytes.NewReader(data), pw); err != nil {
		if strings.Contains(err.Error(), "digest") || strings.Contains(err.Error(), "password") {
			return keys.ErrIncorrectPassword
		}
		return fmt.Errorf("JKS: %w", err)
	}
	b.Encrypted = true
	keyPW := pw
	for _, alias := range ks.Aliases() {
		switch {
		case ks.IsPrivateKeyEntry(alias):
			entry, err := ks.GetPrivateKeyEntry(alias, keyPW)
			if err != nil && o.KeyPassword != nil {
				if kp, perr := o.KeyPassword(); perr == nil {
					keyPW = kp
					entry, err = ks.GetPrivateKeyEntry(alias, keyPW)
				}
			}
			if err != nil {
				return fmt.Errorf("JKS entry %q: %w (the key password may differ from the store password)", alias, err)
			}
			key, err := x509.ParsePKCS8PrivateKey(entry.PrivateKey)
			skcrypto.Zero(entry.PrivateKey)
			if err != nil {
				return fmt.Errorf("JKS entry %q: %w", alias, err)
			}
			b.Objects = append(b.Objects, Object{Kind: KindPrivateKey, Key: key, Alias: alias, Created: entry.CreationTime})
			for i, c := range entry.CertificateChain {
				cert, err := x509.ParseCertificate(c.Content)
				if err != nil {
					return fmt.Errorf("JKS entry %q certificate %d: %w", alias, i, err)
				}
				a := alias
				if i > 0 {
					a = fmt.Sprintf("%s-chain-%d", alias, i)
				}
				b.Objects = append(b.Objects, Object{Kind: KindCertificate, Cert: cert, Alias: a, Created: entry.CreationTime})
			}
		case ks.IsTrustedCertificateEntry(alias):
			entry, err := ks.GetTrustedCertificateEntry(alias)
			if err != nil {
				return err
			}
			cert, err := x509.ParseCertificate(entry.Certificate.Content)
			if err != nil {
				return fmt.Errorf("JKS entry %q: %w", alias, err)
			}
			b.Objects = append(b.Objects, Object{Kind: KindCertificate, Cert: cert, Alias: alias, Trusted: true, Created: entry.CreationTime})
		}
	}
	return nil
}

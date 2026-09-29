package converter

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"golang.org/x/crypto/ssh"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/matusso/sslknife/internal/certificate"
	skcrypto "github.com/matusso/sslknife/internal/crypto"
	"github.com/matusso/sslknife/internal/keys"
)

// ErrImpossible marks conversions the target format cannot represent.
var ErrImpossible = errors.New("conversion not possible")

func impossible(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrImpossible, fmt.Sprintf(format, args...))
}

// Targets lists output formats with a short description.
var Targets = []struct {
	Name, Description string
}{
	{"pem", "PEM text: certificates, keys (PKCS#8), CSRs, public keys"},
	{"der", "binary DER of exactly one object"},
	{"pkcs7", "PKCS#7 / .p7b certificate bundle (certificates only)"},
	{"pkcs8", "PKCS#8 private key (encrypted with --out-password)"},
	{"pkcs1", "PKCS#1 RSA private or public key"},
	{"sec1", "SEC1 EC private key"},
	{"spki", "PKIX SubjectPublicKeyInfo public key"},
	{"pkcs12", "PKCS#12 / PFX keystore or truststore"},
	{"jks", "Java KeyStore"},
	{"openssh", "OpenSSH private key"},
	{"ssh", "OpenSSH authorized_keys public key line(s)"},
	{"rfc4716", "RFC 4716 SSH2 public key"},
}

// ParseTarget normalises a --to value.
func ParseTarget(s string) (Format, error) {
	switch strings.ToLower(strings.TrimPrefix(s, ".")) {
	case "pem", "crt", "cer":
		return FormatPEM, nil
	case "der":
		return FormatDER, nil
	case "pkcs7", "p7b", "p7c", "p7":
		return FormatPKCS7, nil
	case "pkcs8", "p8":
		return FormatPKCS8, nil
	case "pkcs1", "rsa":
		return FormatPKCS1, nil
	case "sec1", "ec":
		return FormatSEC1, nil
	case "spki", "pkix", "public":
		return FormatSPKI, nil
	case "pkcs12", "p12", "pfx":
		return FormatPKCS12, nil
	case "jks", "java", "keystore", "truststore":
		return FormatJKS, nil
	case "openssh":
		return FormatOpenSSH, nil
	case "ssh", "authorized_keys", "openssh-public":
		return FormatSSHPublic, nil
	case "rfc4716", "ssh2":
		return FormatRFC4716, nil
	}
	var names []string
	for _, t := range Targets {
		names = append(names, t.Name)
	}
	return "", fmt.Errorf("unknown target format %q (use %s)", s, strings.Join(names, ", "))
}

// EncodeOptions control output encoding.
type EncodeOptions struct {
	Password []byte // encrypts keys / keystores; required for pkcs12 and jks
	DER      bool   // binary output where both encodings exist (pkcs1/pkcs8/sec1/spki/pkcs7/csr)
	Alias    string // alias for the key entry in pkcs12/jks
}

// Output is an encoded result.
type Output struct {
	Data      []byte
	Secret    bool // contains private key material
	Extension string
	Notes     []string
}

// Encode renders b in format to.
func Encode(b *Bundle, to Format, o EncodeOptions) (*Output, error) {
	if len(b.Objects) == 0 {
		return nil, errors.New("nothing to convert")
	}
	switch to {
	case FormatPEM:
		return encodePEM(b, o)
	case FormatDER:
		return encodeDER(b)
	case FormatPKCS7:
		return encodePKCS7(b, o)
	case FormatPKCS8:
		return encodeKey(b, o, "pkcs8")
	case FormatPKCS1:
		return encodeKey(b, o, "pkcs1")
	case FormatSEC1:
		return encodeKey(b, o, "sec1")
	case FormatSPKI:
		return encodeSPKI(b, o)
	case FormatPKCS12:
		return encodePKCS12(b, o)
	case FormatJKS:
		return encodeJKS(b, o)
	case FormatOpenSSH:
		return encodeOpenSSH(b, o)
	case FormatSSHPublic, FormatRFC4716:
		return encodeSSHPublic(b, to)
	}
	return nil, fmt.Errorf("cannot write %s", to)
}

func summary(b *Bundle) string {
	var parts []string
	for _, k := range []Kind{KindCertificate, KindPrivateKey, KindPublicKey, KindCSR} {
		if n := b.Count(k); n > 0 {
			name := strings.ReplaceAll(string(k), "_", " ")
			if k == KindCSR {
				name = "certificate request"
			}
			if n > 1 {
				name += "s"
			}
			parts = append(parts, fmt.Sprintf("%d %s", n, name))
		}
	}
	return strings.Join(parts, ", ")
}

// orderedCerts returns certificates leaf-first along the issuing chain,
// followed by any unrelated certificates in input order.
func orderedCerts(certs []*x509.Certificate) []*x509.Certificate {
	if len(certs) < 2 {
		return certs
	}
	chain := certificate.Order(certificate.FindLeaf(certs), certs)
	in := map[*x509.Certificate]bool{}
	for _, c := range chain {
		in[c] = true
	}
	for _, c := range certs {
		if !in[c] {
			chain = append(chain, c)
		}
	}
	return chain
}

func pemEncode(t string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: t, Bytes: der})
}

func privateKeyPEM(key crypto.PrivateKey, password []byte) ([]byte, error) {
	return keys.MarshalPrivateKeyPEM(key, password)
}

func encodePEM(b *Bundle, o EncodeOptions) (*Output, error) {
	var buf bytes.Buffer
	out := &Output{Extension: "pem"}
	for _, c := range orderedCerts(b.Certificates()) {
		buf.Write(pemEncode("CERTIFICATE", c.Raw))
	}
	for _, obj := range b.Objects {
		switch obj.Kind {
		case KindPrivateKey:
			p, err := privateKeyPEM(obj.Key, o.Password)
			if err != nil {
				return nil, err
			}
			buf.Write(p)
			skcrypto.Zero(p)
			out.Secret = true
		case KindCSR:
			buf.Write(pemEncode("CERTIFICATE REQUEST", obj.CSR.Raw))
		case KindPublicKey:
			p, err := keys.MarshalPublicKeyPEM(obj.Public)
			if err != nil {
				return nil, err
			}
			buf.Write(p)
		}
	}
	out.Data = buf.Bytes()
	return out, nil
}

func encodeDER(b *Bundle) (*Output, error) {
	if len(b.Objects) != 1 {
		return nil, impossible("DER holds exactly one object but the input contains %s; use pem, pkcs7 (certificates) or pkcs12, or select one object with --certs-only/--keys-only", summary(b))
	}
	obj := b.Objects[0]
	switch obj.Kind {
	case KindCertificate:
		return &Output{Data: obj.Cert.Raw, Extension: "der"}, nil
	case KindCSR:
		return &Output{Data: obj.CSR.Raw, Extension: "der"}, nil
	case KindPublicKey:
		der, err := x509.MarshalPKIXPublicKey(obj.Public)
		return &Output{Data: der, Extension: "der"}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(obj.Key)
	return &Output{Data: der, Extension: "der", Secret: true}, err
}

func encodePKCS7(b *Bundle, o EncodeOptions) (*Output, error) {
	if n := len(b.Objects) - b.Count(KindCertificate); n > 0 {
		return nil, impossible("PKCS#7 bundles carry only certificates, but the input also contains %s which would be lost; add --certs-only to drop them explicitly", summary(b.Filter(KindPrivateKey, KindPublicKey, KindCSR)))
	}
	der, err := certificate.EncodePKCS7(orderedCerts(b.Certificates()))
	if err != nil {
		return nil, err
	}
	if o.DER {
		return &Output{Data: der, Extension: "p7b"}, nil
	}
	return &Output{Data: pemEncode("PKCS7", der), Extension: "p7b"}, nil
}

func singleKey(b *Bundle, format string) (crypto.PrivateKey, error) {
	if n := b.Count(KindPrivateKey); n != 1 {
		if n == 0 {
			return nil, impossible("%s is a private key format but the input contains %s", format, summary(b))
		}
		return nil, impossible("%s holds one private key but the input contains %d; use pem or pkcs12, or split the input", format, n)
	}
	for _, obj := range b.Objects {
		if obj.Kind == KindPrivateKey {
			return obj.Key, nil
		}
	}
	return nil, nil
}

func encodeKey(b *Bundle, o EncodeOptions, format string) (*Output, error) {
	// PKCS#1 also defines RSA public keys.
	if format == "pkcs1" && b.Count(KindPrivateKey) == 0 && b.Count(KindPublicKey) == 1 {
		for _, obj := range b.Objects {
			if pub, ok := obj.Public.(*rsa.PublicKey); ok {
				der := x509.MarshalPKCS1PublicKey(pub)
				if o.DER {
					return &Output{Data: der, Extension: "der"}, nil
				}
				return &Output{Data: pemEncode("RSA PUBLIC KEY", der), Extension: "pem"}, nil
			}
		}
		return nil, impossible("PKCS#1 is defined only for RSA keys")
	}
	key, err := singleKey(b, strings.ToUpper(format))
	if err != nil {
		return nil, err
	}
	out := &Output{Secret: true, Extension: "key"}
	if b.Count(KindCertificate) > 0 {
		out.Notes = append(out.Notes, fmt.Sprintf("%d certificate(s) in the input are not part of a %s key file and were not written", b.Count(KindCertificate), strings.ToUpper(format)))
	}
	var der []byte
	var blockType string
	switch format {
	case "pkcs8":
		if len(o.Password) > 0 {
			plain, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				return nil, err
			}
			der, err = keys.EncryptPKCS8(plain, o.Password)
			skcrypto.Zero(plain)
			if err != nil {
				return nil, err
			}
			blockType = "ENCRYPTED PRIVATE KEY"
		} else {
			if der, err = x509.MarshalPKCS8PrivateKey(key); err != nil {
				return nil, err
			}
			blockType = "PRIVATE KEY"
		}
	case "pkcs1":
		rk, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, impossible("PKCS#1 is defined only for RSA keys; the key is %s (use pkcs8%s)", keys.Describe(keyPublic(key)).Algorithm, secHint(key))
		}
		if len(o.Password) > 0 {
			return nil, impossible("PKCS#1 has no standard encryption (legacy PEM encryption uses MD5); use pkcs8 with a password instead")
		}
		der, blockType = x509.MarshalPKCS1PrivateKey(rk), "RSA PRIVATE KEY"
	case "sec1":
		ek, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, impossible("SEC1 is defined only for elliptic-curve (ECDSA) keys; the key is %s (use pkcs8)", keys.Describe(keyPublic(key)).Algorithm)
		}
		if len(o.Password) > 0 {
			return nil, impossible("SEC1 has no standard encryption; use pkcs8 with a password instead")
		}
		if der, err = x509.MarshalECPrivateKey(ek); err != nil {
			return nil, err
		}
		blockType = "EC PRIVATE KEY"
	}
	if o.DER {
		out.Data, out.Extension = der, "der"
		return out, nil
	}
	out.Data = pemEncode(blockType, der)
	skcrypto.Zero(der)
	return out, nil
}

func keyPublic(k crypto.PrivateKey) crypto.PublicKey {
	p, _ := keys.Public(k)
	return p
}

func secHint(k crypto.PrivateKey) string {
	if _, ok := k.(*ecdsa.PrivateKey); ok {
		return " or sec1"
	}
	return ""
}

func encodeSPKI(b *Bundle, o EncodeOptions) (*Output, error) {
	var pubs []crypto.PublicKey
	for _, obj := range b.Objects {
		if obj.Kind == KindPublicKey {
			pubs = append(pubs, obj.Public)
		}
	}
	if len(pubs) != 1 {
		return nil, impossible("spki writes one public key; the input contains %s (use 'sslknife key public' to extract the public key of a certificate or private key)", summary(b))
	}
	der, err := x509.MarshalPKIXPublicKey(pubs[0])
	if err != nil {
		return nil, err
	}
	if o.DER {
		return &Output{Data: der, Extension: "der"}, nil
	}
	return &Output{Data: pemEncode("PUBLIC KEY", der), Extension: "pem"}, nil
}

// keyChain returns the certificate chain for key: the certificate carrying
// its public key followed by that certificate's issuers from certs.
func keyChain(key crypto.PrivateKey, certs []*x509.Certificate) []*x509.Certificate {
	pub := keyPublic(key)
	for _, c := range certs {
		if keys.Equal(c.PublicKey, pub) {
			return certificate.Order(c, certs)
		}
	}
	return nil
}

func encodePKCS12(b *Bundle, o EncodeOptions) (*Output, error) {
	if b.Count(KindPublicKey)+b.Count(KindCSR) > 0 {
		return nil, impossible("PKCS#12 stores private keys and certificates; the input also contains %s", summary(b.Filter(KindPublicKey, KindCSR)))
	}
	if o.Password == nil {
		return nil, errors.New("PKCS#12 output needs a password")
	}
	enc := pkcs12.Modern2023.WithIterations(100_000)
	certs := b.Certificates()
	switch n := b.Count(KindPrivateKey); n {
	case 0:
		// Truststore: trusted certificate entries, readable by Java.
		data, err := enc.EncodeTrustStore(certs, string(o.Password))
		return &Output{Data: data, Extension: "p12"}, err
	case 1:
		key, _ := singleKey(b, "PKCS#12")
		chain := keyChain(key, certs)
		if chain == nil {
			return nil, impossible("a PKCS#12 key entry needs the certificate for the private key, and none of the %d certificate(s) in the input matches it", len(certs))
		}
		out := &Output{Extension: "p12", Secret: true}
		if extra := len(certs) - len(chain); extra > 0 {
			// Unrelated certificates are kept as additional CA certificates.
			in := map[*x509.Certificate]bool{}
			for _, c := range chain {
				in[c] = true
			}
			for _, c := range certs {
				if !in[c] {
					chain = append(chain, c)
				}
			}
			out.Notes = append(out.Notes, fmt.Sprintf("%d certificate(s) unrelated to the key were added as CA certificates", extra))
		}
		data, err := enc.Encode(key, chain[0], chain[1:], string(o.Password))
		out.Data = data
		return out, err
	default:
		return nil, impossible("the input contains %d private keys; SSLKnife writes one key per PKCS#12 file (Java can also read multi-key JKS: --to jks)", n)
	}
}

// MinJKSPassword is Java's minimum keystore password length.
const MinJKSPassword = 6

func encodeJKS(b *Bundle, o EncodeOptions) (*Output, error) {
	if b.Count(KindPublicKey)+b.Count(KindCSR) > 0 {
		return nil, impossible("Java keystores hold private keys and certificates; the input also contains %s", summary(b.Filter(KindPublicKey, KindCSR)))
	}
	if len(o.Password) < MinJKSPassword {
		return nil, fmt.Errorf("a Java keystore needs a password of at least %d characters", MinJKSPassword)
	}
	ks := keystore.New(keystore.WithCaseExactAliases(), keystore.WithOrderedAliases())
	certs := b.Certificates()
	used := map[*x509.Certificate]bool{}
	aliases := map[string]bool{}
	uniq := func(base string) string {
		a := base
		for i := 2; aliases[a]; i++ {
			a = fmt.Sprintf("%s-%d", base, i)
		}
		aliases[a] = true
		return a
	}
	now := time.Now()
	out := &Output{Extension: "jks",
		Notes: []string{"JKS protects keys with a weak SHA-1 based scheme; prefer PKCS#12 (the Java default since Java 9)"}}
	for i, obj := range b.Objects {
		if obj.Kind != KindPrivateKey {
			continue
		}
		chain := keyChain(obj.Key, certs)
		if chain == nil {
			return nil, impossible("JKS private key entries need a certificate chain, and no certificate in the input matches private key %d", i+1)
		}
		der, err := x509.MarshalPKCS8PrivateKey(obj.Key)
		if err != nil {
			return nil, err
		}
		entry := keystore.PrivateKeyEntry{CreationTime: now, PrivateKey: der}
		for _, c := range chain {
			used[c] = true
			entry.CertificateChain = append(entry.CertificateChain, keystore.Certificate{Type: "X509", Content: c.Raw})
		}
		alias := firstNonEmpty(obj.Alias, o.Alias, "mykey")
		if err := ks.SetPrivateKeyEntry(uniq(alias), entry, o.Password); err != nil {
			return nil, err
		}
		skcrypto.Zero(der)
		out.Secret = true
	}
	for _, c := range certs {
		if used[c] {
			continue
		}
		var alias string
		for _, obj := range b.Objects {
			if obj.Cert == c {
				alias = obj.Alias
			}
		}
		if alias == "" {
			alias = aliasFor(c)
		}
		if err := ks.SetTrustedCertificateEntry(uniq(alias), keystore.TrustedCertificateEntry{
			CreationTime: now, Certificate: keystore.Certificate{Type: "X509", Content: c.Raw},
		}); err != nil {
			return nil, err
		}
	}
	var buf bytes.Buffer
	if err := ks.Store(&buf, o.Password); err != nil {
		return nil, err
	}
	out.Data = buf.Bytes()
	return out, nil
}

// aliasFor derives a keystore alias from a certificate subject.
func aliasFor(c *x509.Certificate) string {
	n := strings.ToLower(certificate.NewName(c.Subject).DisplayName())
	n = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' {
			return r
		}
		return '-'
	}, n)
	n = strings.Trim(n, "-")
	if n == "" {
		return "cert"
	}
	return n
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func encodeOpenSSH(b *Bundle, o EncodeOptions) (*Output, error) {
	key, err := singleKey(b, "OpenSSH private key format")
	if err != nil {
		return nil, err
	}
	var block *pem.Block
	comment := ""
	for _, obj := range b.Objects {
		if obj.Kind == KindPrivateKey {
			comment = obj.Comment
		}
	}
	if len(o.Password) > 0 {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(key, comment, o.Password)
	} else {
		block, err = ssh.MarshalPrivateKey(key, comment)
	}
	if err != nil {
		return nil, impossible("OpenSSH cannot represent this key: %v", err)
	}
	return &Output{Data: pem.EncodeToMemory(block), Secret: true, Extension: "key"}, nil
}

func encodeSSHPublic(b *Bundle, to Format) (*Output, error) {
	if n := b.Count(KindCertificate) + b.Count(KindCSR); n > 0 {
		return nil, impossible("SSH public key formats hold bare keys, not X.509 %s; use 'sslknife key public <file> --ssh' to extract the public key explicitly", summary(b.Filter(KindCertificate, KindCSR)))
	}
	out := &Output{Extension: "pub"}
	var buf bytes.Buffer
	for _, obj := range b.Objects {
		pub := obj.PublicKey()
		if obj.Kind == KindPrivateKey {
			out.Notes = append(out.Notes, "wrote the public half of the private key")
		}
		sp, err := ssh.NewPublicKey(pub)
		if err != nil {
			return nil, impossible("%s keys cannot be represented in SSH format: %v", keys.Describe(pub).Algorithm, err)
		}
		if to == FormatRFC4716 {
			buf.WriteString(rfc4716(sp, obj.Comment))
			continue
		}
		line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
		if obj.Comment != "" {
			line += " " + obj.Comment
		}
		buf.WriteString(line + "\n")
	}
	out.Data = buf.Bytes()
	return out, nil
}

func rfc4716(pk ssh.PublicKey, comment string) string {
	var b strings.Builder
	b.WriteString("---- BEGIN SSH2 PUBLIC KEY ----\n")
	if comment != "" {
		fmt.Fprintf(&b, "Comment: \"%s\"\n", strings.ReplaceAll(comment, `"`, `'`))
	}
	enc := base64Std(pk.Marshal())
	for len(enc) > 70 {
		b.WriteString(enc[:70] + "\n")
		enc = enc[70:]
	}
	b.WriteString(enc + "\n---- END SSH2 PUBLIC KEY ----\n")
	return b.String()
}

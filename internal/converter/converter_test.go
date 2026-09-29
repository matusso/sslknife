package converter

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matusso/sslknife/internal/certificate"
	"github.com/matusso/sslknife/internal/keys"
)

type fixture struct {
	root, inter, leaf *x509.Certificate
	leafKey           crypto.Signer
}

func newFixture(t *testing.T, alg keys.Algorithm) *fixture {
	t.Helper()
	rk, _ := keys.Generate(keys.ECDSAP256)
	root, err := certificate.Create(certificate.Request{Profile: certificate.ProfileRootCA, Subject: pkix.Name{CommonName: "Conv Root"}, Validity: 48 * time.Hour, Key: rk, PathLen: -1})
	if err != nil {
		t.Fatal(err)
	}
	ik, _ := keys.Generate(keys.ECDSAP256)
	inter, err := certificate.Create(certificate.Request{Profile: certificate.ProfileIntermediateCA, Subject: pkix.Name{CommonName: "Conv Inter"}, Validity: 24 * time.Hour, Key: ik, Issuer: root, IssuerKey: rk, PathLen: 0})
	if err != nil {
		t.Fatal(err)
	}
	lk, _ := keys.Generate(alg)
	leaf, err := certificate.Create(certificate.Request{Profile: certificate.ProfileServer, Subject: pkix.Name{CommonName: "conv.example.com"}, Validity: time.Hour, Key: lk, Issuer: inter, IssuerKey: ik, PathLen: -1})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{root: root, inter: inter, leaf: leaf, leafKey: lk}
}

func (f *fixture) pem(t *testing.T, withKey bool) []byte {
	data := certificate.EncodePEM(f.leaf, f.inter, f.root)
	if withKey {
		k, err := keys.MarshalPrivateKeyPEM(f.leafKey, nil)
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, k...)
	}
	return data
}

func pw(s string) keys.PasswordFunc { return func() ([]byte, error) { return []byte(s), nil } }

func decode(t *testing.T, data []byte, password string) *Bundle {
	t.Helper()
	b, err := Decode(data, DecodeOptions{Password: pw(password)})
	if err != nil {
		t.Fatalf("decode %s: %v", Detect(data), err)
	}
	return b
}

func TestRoundTrips(t *testing.T) {
	f := newFixture(t, keys.ECDSAP256)
	src := decode(t, f.pem(t, true), "")
	if src.Format != FormatPEM || src.Count(KindCertificate) != 3 || src.Count(KindPrivateKey) != 1 {
		t.Fatalf("%+v", src.Summarize())
	}
	c := src.Summarize()
	if c.Leaf != 1 || c.Intermediates != 1 || c.Roots != 1 {
		t.Fatalf("%+v", c)
	}
	cases := []struct {
		to       Format
		opts     EncodeOptions
		detected Format
		certs    int
		keys     int
	}{
		{FormatPKCS12, EncodeOptions{Password: []byte("p12pass")}, FormatPKCS12, 3, 1},
		{FormatJKS, EncodeOptions{Password: []byte("changeit")}, FormatJKS, 3, 1},
		{FormatPEM, EncodeOptions{}, FormatPEM, 3, 1},
		{FormatPEM, EncodeOptions{Password: []byte("pem-pass")}, FormatPEM, 3, 1},
	}
	for _, tc := range cases {
		out, err := Encode(src, tc.to, tc.opts)
		if err != nil {
			t.Fatalf("%s: %v", tc.to, err)
		}
		if !out.Secret {
			t.Errorf("%s: output with key not marked secret", tc.to)
		}
		if d := Detect(out.Data); d != tc.detected {
			t.Fatalf("%s: detected as %s", tc.to, d)
		}
		back := decode(t, out.Data, string(tc.opts.Password))
		if back.Count(KindCertificate) != tc.certs || back.Count(KindPrivateKey) != tc.keys {
			t.Fatalf("%s: %+v", tc.to, back.Summarize())
		}
		for _, o := range back.Objects {
			if o.Kind == KindPrivateKey && !keys.Equal(o.PublicKey(), f.leafKey.Public()) {
				t.Fatalf("%s: key changed", tc.to)
			}
		}
	}

	certsOnly := src.Filter(KindCertificate)
	for _, to := range []Format{FormatPKCS7, FormatPKCS12, FormatJKS} {
		out, err := Encode(certsOnly, to, EncodeOptions{Password: []byte("trustpass")})
		if err != nil {
			t.Fatalf("%s truststore: %v", to, err)
		}
		if out.Secret {
			t.Errorf("%s: certificate-only output marked secret", to)
		}
		if back := decode(t, out.Data, "trustpass"); back.Count(KindCertificate) != 3 {
			t.Fatalf("%s truststore: %+v", to, back.Summarize())
		}
	}

	leafOnly := &Bundle{Objects: []Object{{Kind: KindCertificate, Cert: f.leaf}}}
	der, err := Encode(leafOnly, FormatDER, EncodeOptions{})
	if err != nil || Detect(der.Data) != FormatDER {
		t.Fatal(err)
	}
	keyOnly := src.Filter(KindPrivateKey)
	for _, to := range []Format{FormatPKCS8, FormatSEC1, FormatOpenSSH} {
		out, err := Encode(keyOnly, to, EncodeOptions{})
		if err != nil {
			t.Fatalf("%s: %v", to, err)
		}
		if back := decode(t, out.Data, ""); back.Count(KindPrivateKey) != 1 {
			t.Fatalf("%s: roundtrip", to)
		}
	}
	enc, err := Encode(keyOnly, FormatPKCS8, EncodeOptions{Password: []byte("x"), DER: true})
	if err != nil || Detect(enc.Data) != FormatPKCS8 {
		t.Fatal("encrypted DER PKCS#8", err)
	}
	if back := decode(t, enc.Data, "x"); back.Count(KindPrivateKey) != 1 {
		t.Fatal("encrypted DER PKCS#8 decode")
	}
	ssh, err := Encode(keyOnly, FormatSSHPublic, EncodeOptions{})
	if err != nil || !strings.HasPrefix(string(ssh.Data), "ecdsa-sha2-nistp256 ") {
		t.Fatal(err, string(ssh.Data))
	}
	rfc, err := Encode(decode(t, ssh.Data, ""), FormatRFC4716, EncodeOptions{})
	if err != nil || Detect(rfc.Data) != FormatRFC4716 {
		t.Fatal(err)
	}
}

func TestImpossible(t *testing.T) {
	f := newFixture(t, keys.ECDSAP256)
	src := decode(t, f.pem(t, true), "")
	for _, to := range []Format{FormatDER, FormatPKCS7, FormatPKCS1, FormatSSHPublic, FormatSPKI} {
		if _, err := Encode(src, to, EncodeOptions{}); !errors.Is(err, ErrImpossible) {
			t.Errorf("%s: expected ErrImpossible, got %v", to, err)
		}
	}
	if _, err := Encode(src.Filter(KindPrivateKey), FormatPKCS1, EncodeOptions{}); err == nil || !strings.Contains(err.Error(), "only for RSA") {
		t.Errorf("pkcs1 EC: %v", err)
	}
	if _, err := Encode(src, FormatJKS, EncodeOptions{Password: []byte("abc")}); err == nil {
		t.Error("short JKS password accepted")
	}
	if _, err := Encode(src, FormatPKCS12, EncodeOptions{}); err == nil {
		t.Error("PKCS#12 without password accepted")
	}
	// Key without matching certificate.
	other, _ := keys.Generate(keys.ECDSAP256)
	mismatch := &Bundle{Objects: []Object{{Kind: KindPrivateKey, Key: other}, {Kind: KindCertificate, Cert: f.leaf}}}
	if _, err := Encode(mismatch, FormatPKCS12, EncodeOptions{Password: []byte("x")}); !errors.Is(err, ErrImpossible) {
		t.Errorf("mismatched key: %v", err)
	}
	ml := newFixture(t, keys.MLDSA44)
	mlKey := &Bundle{Objects: []Object{{Kind: KindPrivateKey, Key: ml.leafKey}}}
	if _, err := Encode(mlKey, FormatOpenSSH, EncodeOptions{}); !errors.Is(err, ErrImpossible) {
		t.Errorf("ML-DSA openssh: %v", err)
	}
	if _, err := Decode([]byte{0xCE, 0xCE, 0xCE, 0xCE, 0, 0}, DecodeOptions{}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("jceks: %v", err)
	}
}

func TestWrongPasswords(t *testing.T) {
	f := newFixture(t, keys.ECDSAP256)
	src := decode(t, f.pem(t, true), "")
	for _, to := range []Format{FormatPKCS12, FormatJKS} {
		out, err := Encode(src, to, EncodeOptions{Password: []byte("rightpass")})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(out.Data, DecodeOptions{Password: pw("wrongpass")}); !errors.Is(err, keys.ErrIncorrectPassword) {
			t.Errorf("%s wrong password: %v", to, err)
		}
		if _, err := Decode(out.Data, DecodeOptions{}); !errors.Is(err, keys.ErrPasswordRequired) {
			t.Errorf("%s no password: %v", to, err)
		}
	}
}

func TestOpenSSLInterop(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not installed")
	}
	f := newFixture(t, keys.RSA2048)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	os.WriteFile(certFile, certificate.EncodePEM(f.leaf, f.inter), 0o600)
	k, _ := keys.MarshalPrivateKeyPEM(f.leafKey, nil)
	os.WriteFile(keyFile, k, 0o600)

	// OpenSSL-written PKCS#12 → SSLKnife.
	p12 := filepath.Join(dir, "o.p12")
	if out, err := exec.Command(openssl, "pkcs12", "-export", "-in", certFile, "-inkey", keyFile, "-out", p12, "-passout", "pass:secret").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	data, _ := os.ReadFile(p12)
	b := decode(t, data, "secret")
	if b.Count(KindPrivateKey) != 1 || b.Count(KindCertificate) != 2 {
		t.Fatalf("%+v", b.Summarize())
	}
	// SSLKnife-written PKCS#12 → OpenSSL.
	out, err := Encode(b, FormatPKCS12, EncodeOptions{Password: []byte("secret2")})
	if err != nil {
		t.Fatal(err)
	}
	mine := filepath.Join(dir, "m.p12")
	os.WriteFile(mine, out.Data, 0o600)
	if o, err := exec.Command(openssl, "pkcs12", "-in", mine, "-passin", "pass:secret2", "-nodes", "-noout").CombinedOutput(); err != nil {
		t.Fatalf("openssl could not read our PKCS#12: %v %s", err, o)
	}
	// PKCS#7 bundle → OpenSSL.
	p7, err := Encode(b.Filter(KindCertificate), FormatPKCS7, EncodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p7file := filepath.Join(dir, "b.p7b")
	os.WriteFile(p7file, p7.Data, 0o600)
	o, err := exec.Command(openssl, "pkcs7", "-in", p7file, "-print_certs", "-noout").CombinedOutput()
	if err != nil || strings.Count(string(o), "subject=") != 2 {
		t.Fatalf("openssl pkcs7: %v %s", err, o)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte{0xFE, 0xED, 0xFE, 0xED, 0, 0, 0, 2})
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x03})
	f.Add([]byte("ssh-ed25519 AAAA"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Decode(data, DecodeOptions{Password: pw("x"), KeyPassword: pw("y")})
	})
}

// testdata/keytool-* were created with Java keytool (store password
// "changeit"): an EC key entry in JKS and an RSA key entry in PKCS#12.
func TestKeytoolFixtures(t *testing.T) {
	for file, cn := range map[string]string{"keytool-ec.jks": "app.example.com", "keytool-rsa.p12": "p12.example.com"} {
		data, err := os.ReadFile(filepath.Join("testdata", file))
		if err != nil {
			t.Fatal(err)
		}
		b := decode(t, data, "changeit")
		if b.Count(KindPrivateKey) != 1 || b.Count(KindCertificate) != 1 || b.Certificates()[0].Subject.CommonName != cn {
			t.Fatalf("%s: %+v", file, b.Summarize())
		}
		if !keys.Equal(b.Certificates()[0].PublicKey, b.Filter(KindPrivateKey).Objects[0].PublicKey()) {
			t.Fatalf("%s: key does not match certificate", file)
		}
		// JKS → PKCS#12 → back.
		out, err := Encode(b, FormatPKCS12, EncodeOptions{Password: []byte("changeit")})
		if err != nil {
			t.Fatal(err)
		}
		if back := decode(t, out.Data, "changeit"); back.Count(KindPrivateKey) != 1 {
			t.Fatal("re-encode")
		}
	}
}

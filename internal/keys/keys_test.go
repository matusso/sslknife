package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func pw(s string) PasswordFunc { return func() ([]byte, error) { return []byte(s), nil } }

func TestGenerateAndDescribe(t *testing.T) {
	want := map[Algorithm]string{
		Ed25519: "Ed25519", ECDSAP256: "ECDSA P-256", ECDSAP384: "ECDSA P-384", RSA2048: "RSA 2048", MLDSA65: "ML-DSA-65",
	}
	for alg, desc := range want {
		k, err := Generate(alg)
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		info := Describe(k.Public())
		if info.Description != desc || len(info.SPKISHA256) != 64 {
			t.Errorf("%s: %+v", alg, info)
		}
		// Round trip through PKCS#8 PEM.
		p, err := MarshalPrivateKeyPEM(k, nil)
		if err != nil {
			t.Fatalf("%s marshal: %v", alg, err)
		}
		back, err := ParsePrivateKey(p, nil)
		if err != nil || back.Format != FormatPKCS8 || !Equal(back.Public(), k.Public()) {
			t.Fatalf("%s roundtrip: %v", alg, err)
		}
	}
}

func TestParseAlgorithm(t *testing.T) {
	cases := map[string]Algorithm{"ED25519": Ed25519, "p256": ECDSAP256, "ECDSA P-384": ECDSAP384, "rsa": RSA3072,
		"RSA 4096": RSA4096, "ml-dsa-87": MLDSA87, "secp521r1": ECDSAP521}
	for in, want := range cases {
		if got, err := ParseAlgorithm(in); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	if _, err := ParseAlgorithm("rsa1024"); err == nil || !strings.Contains(err.Error(), "insecure") {
		t.Error("rsa1024 must be refused", err)
	}
	if _, err := ParseAlgorithm("dsa"); err == nil {
		t.Error("dsa accepted")
	}
}

func TestEncryptedPKCS8(t *testing.T) {
	k, _ := Generate(ECDSAP256)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	enc, err := encryptPKCS8(der, []byte("pass"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: enc})
	if _, err := ParsePrivateKey(block, nil); !errors.Is(err, ErrPasswordRequired) {
		t.Fatal("expected password required", err)
	}
	if _, err := ParsePrivateKey(block, pw("nope")); !errors.Is(err, ErrIncorrectPassword) {
		t.Fatal("expected incorrect password", err)
	}
	got, err := ParsePrivateKey(block, pw("pass"))
	if err != nil || !got.Encrypted || !Equal(got.Public(), k.Public()) {
		t.Fatal(err)
	}
}

// testdata/openssl-*.pem were produced by OpenSSL 4 (`openssl pkcs8 -topk8`
// with -v2 aes-128-cbc -v2prf hmacWithSHA1, -v2 aes-256-cbc, and -scrypt),
// password "test", to check interoperability.
func TestOpenSSLFixtures(t *testing.T) {
	files := []string{"openssl-pbes2-aes128-sha1.pem", "openssl-pbes2-aes256-sha256.pem", "openssl-scrypt.pem"}
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join("testdata", f))
		if err != nil {
			t.Fatal(err)
		}
		k, err := ParsePrivateKey(data, pw("test"))
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if d := Describe(k.Public()); d.Description != "ECDSA P-256" {
			t.Errorf("%s: %s", f, d.Description)
		}
		if _, err := ParsePrivateKey(data, pw("wrong")); !errors.Is(err, ErrIncorrectPassword) {
			t.Errorf("%s wrong password: %v", f, err)
		}
	}
}

func TestLegacyFormats(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rk)})
	got, err := ParsePrivateKey(pkcs1, nil)
	if err != nil || got.Format != FormatPKCS1 {
		t.Fatal(err)
	}
	ek, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	sec1der, _ := x509.MarshalECPrivateKey(ek)
	got, err = ParsePrivateKey(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1der}), nil)
	if err != nil || got.Format != FormatSEC1 {
		t.Fatal(err)
	}
	// Raw DER.
	got, err = ParsePrivateKey(sec1der, nil)
	if err != nil || got.Format != FormatSEC1 {
		t.Fatal(err)
	}
	//lint:ignore SA1019 test fixture for legacy encryption.
	legacy, _ := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rk), []byte("pw"), x509.PEMCipherAES256) //nolint:staticcheck
	got, err = ParsePrivateKey(pem.EncodeToMemory(legacy), pw("pw"))
	if err != nil || got.Format != FormatLegacyPEM {
		t.Fatal(err)
	}
}

func TestOpenSSH(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "me@host", []byte("pp"))
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(block)
	got, err := ParsePrivateKey(data, pw("pp"))
	if err != nil || got.Format != FormatOpenSSH || !got.Encrypted {
		t.Fatal(err)
	}
	if _, ok := got.Key.(ed25519.PrivateKey); !ok {
		t.Fatalf("type %T", got.Key)
	}
	if _, err := ParsePrivateKey(data, pw("bad")); !errors.Is(err, ErrIncorrectPassword) {
		t.Fatal(err)
	}

	sshPub, _ := ssh.NewPublicKey(priv.Public())
	line := ssh.MarshalAuthorizedKey(sshPub)
	line = append(line[:len(line)-1], []byte(" me@host\n")...)
	pub, err := ParsePublicKey(line)
	if err != nil || pub.Comment != "me@host" || !Equal(pub.Key, priv.Public()) {
		t.Fatal(err)
	}

	rfc := "---- BEGIN SSH2 PUBLIC KEY ----\nComment: \"me@host\"\n" +
		strings.TrimSpace(strings.Fields(string(line))[1]) + "\n---- END SSH2 PUBLIC KEY ----\n"
	pub, err = ParsePublicKey([]byte(rfc))
	if err != nil || pub.Format != FormatRFC4716 || pub.Comment != "me@host" {
		t.Fatal(err)
	}
}

func TestPublicFormats(t *testing.T) {
	k, _ := Generate(RSA2048)
	p, _ := MarshalPublicKeyPEM(k.Public())
	got, err := ParsePublicKey(p)
	if err != nil || got.Format != FormatPKIX || !Equal(got.Key, k.Public()) {
		t.Fatal(err)
	}
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(k.Public().(*rsa.PublicKey))})
	if got, err := ParsePublicKey(pkcs1); err != nil || got.Format != FormatPKCS1Public {
		t.Fatal(err)
	}
	if _, err := ParsePublicKey([]byte("garbage")); !errors.Is(err, ErrNoKey) {
		t.Fatal(err)
	}
}

func TestWeakRSADescribed(t *testing.T) {
	//nolint:gosec // deliberately weak key for classification
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Skip("runtime refuses 1024-bit RSA:", err)
	}
	if info := Describe(&k.PublicKey); info.Strength != "weak" {
		t.Fatalf("%+v", info)
	}
}

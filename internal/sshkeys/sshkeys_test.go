package sshkeys

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/matusso/sslknife/internal/keys"
)

func TestGenerateParseDescribe(t *testing.T) {
	for _, a := range []keys.Algorithm{keys.Ed25519, keys.ECDSAP256, keys.RSA3072} {
		_, priv, pub, err := Generate(a, "me@host", nil)
		if err != nil {
			t.Fatal(a, err)
		}
		items, err := Parse(priv)
		if err != nil || len(items) != 1 || items[0].Kind != KindPrivate || items[0].Encrypted || items[0].Private == nil {
			t.Fatalf("%s private: %+v %v", a, items, err)
		}
		pi := Describe(items[0])
		if pi.Comment != "me@host" || !strings.HasPrefix(pi.FingerprintSHA256, "SHA256:") {
			t.Fatalf("%s: %+v", a, pi)
		}
		pubItems, err := Parse(pub)
		if err != nil || len(pubItems) != 1 {
			t.Fatal(err)
		}
		if Describe(pubItems[0]).FingerprintSHA256 != pi.FingerprintSHA256 || pubItems[0].Comment != "me@host" {
			t.Fatalf("%s: fingerprint/comment mismatch", a)
		}
	}
	if _, err := ParseAlgorithm("ml-dsa-65"); err == nil {
		t.Fatal("ML-DSA accepted for SSH")
	}
}

func TestEncryptedKeyStaysEncrypted(t *testing.T) {
	_, priv, pub, err := Generate(keys.Ed25519, "enc", []byte("secret pass"))
	if err != nil {
		t.Fatal(err)
	}
	items, err := Parse(priv)
	if err != nil {
		t.Fatal(err)
	}
	it := items[0]
	if !it.Encrypted || it.Private != nil || it.Public == nil {
		t.Fatalf("%+v", it)
	}
	pubItems, _ := Parse(pub)
	if ssh.FingerprintSHA256(it.Public) != ssh.FingerprintSHA256(pubItems[0].Public) {
		t.Fatal("public key of encrypted key differs")
	}
	if err := it.Decrypt([]byte("wrong")); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	if err := it.Decrypt([]byte("secret pass")); err != nil || it.Private == nil {
		t.Fatal(err)
	}
}

func TestAuthorizedKeysFile(t *testing.T) {
	_, _, a, _ := Generate(keys.Ed25519, "a", nil)
	_, _, b, _ := Generate(keys.ECDSAP256, "b", nil)
	data := append([]byte(`command="/bin/true",no-pty `), a...)
	data = append(data, []byte("\n# comment\n")...)
	data = append(data, b...)
	items, err := Parse(data)
	if err != nil || len(items) != 2 {
		t.Fatalf("%d %v", len(items), err)
	}
	if len(items[0].Options) != 2 || items[1].Comment != "b" {
		t.Fatalf("%+v", items)
	}
}

func TestCertificates(t *testing.T) {
	ca, _, _, _ := Generate(keys.RSA3072, "ca", nil)
	user, _, userPub, _ := Generate(keys.Ed25519, "alice", nil)
	_ = user
	items, _ := Parse(userPub)
	cert, err := SignCert(CertRequest{Key: items[0].Public, KeyID: "alice@corp", Principals: []string{"alice", "admin"},
		Validity: 24 * time.Hour, CriticalOptions: map[string]string{"source-address": "10.0.0.0/8"}}, ca)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Signature.Format != ssh.KeyAlgoRSASHA512 {
		t.Fatalf("RSA CA signed with %s", cert.Signature.Format)
	}
	if err := VerifyCert(cert, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCert(cert, "mallory"); err == nil {
		t.Fatal("principal not enforced")
	}
	line := AuthorizedKey(cert, "alice-cert")
	parsed, err := Parse(line)
	if err != nil || parsed[0].Kind != KindCertificate {
		t.Fatal(err)
	}
	info := Describe(parsed[0])
	c := info.Certificate
	if c == nil || c.CertType != "user" || c.KeyID != "alice@corp" || len(c.Principals) != 2 || c.Status != "valid" ||
		c.CriticalOptions["source-address"] != "10.0.0.0/8" || len(c.Extensions) != 5 || c.ValidBefore == nil {
		t.Fatalf("%+v", c)
	}
	host, err := SignCert(CertRequest{Key: items[0].Public, Host: true, Principals: []string{"web.example.com"}}, ca)
	if err != nil || host.CertType != ssh.HostCert || len(host.Extensions) != 0 || host.ValidBefore != ssh.CertTimeInfinity {
		t.Fatal(err)
	}
	if _, err := SignCert(CertRequest{Key: items[0].Public}, ca); err == nil {
		t.Fatal("certificate without principals accepted")
	}
}

// OpenSSH interop: ssh-keygen must accept our keys and certificates.
func TestSSHKeygenInterop(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not installed")
	}
	dir := t.TempDir()
	ca, caPriv, _, _ := Generate(keys.Ed25519, "ca", nil)
	_ = caPriv
	_, priv, pub, _ := Generate(keys.ECDSAP256, "u", []byte("pp"))
	os.WriteFile(filepath.Join(dir, "id"), priv, 0o600)
	os.WriteFile(filepath.Join(dir, "id.pub"), pub, 0o644)
	out, err := exec.Command(keygen, "-y", "-P", "pp", "-f", filepath.Join(dir, "id")).CombinedOutput()
	if err != nil || !strings.HasPrefix(string(out), "ecdsa-sha2-nistp256 ") {
		t.Fatalf("ssh-keygen -y: %v %s", err, out)
	}
	items, _ := Parse(pub)
	cert, err := SignCert(CertRequest{Key: items[0].Public, Principals: []string{"u"}, KeyID: "u1", Validity: time.Hour}, ca)
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(dir, "id-cert.pub")
	os.WriteFile(certFile, AuthorizedKey(cert, ""), 0o644)
	out, err = exec.Command(keygen, "-L", "-f", certFile).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "Key ID: \"u1\"") {
		t.Fatalf("ssh-keygen -L: %v %s", err, out)
	}
	// And we parse ssh-keygen output.
	kf := filepath.Join(dir, "k2")
	if out, err := exec.Command(keygen, "-q", "-t", "ed25519", "-N", "", "-C", "made-by-keygen", "-f", kf).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	data, _ := os.ReadFile(kf)
	its, err := Parse(data)
	if err != nil || Describe(its[0]).Comment != "made-by-keygen" {
		t.Fatalf("%v %+v", err, its)
	}
}

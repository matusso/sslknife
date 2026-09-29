package cmd

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/matusso/sslknife/internal/exitcode"
)

func TestConvertInspectJKS(t *testing.T) {
	e := newEnv(t)
	cert, key := e.path("s.crt"), e.path("s.key")
	e.ok("cert", "create", "--cn", "svc.example.com", "-o", cert, "--key-out", key)
	t.Setenv(EnvOutPassword, "storepass1")

	p12 := e.path("s.p12")
	e.ok("convert", cert, key, "--to", "pkcs12", "-o", p12)
	if st, _ := os.Stat(p12); st.Mode().Perm() != 0o600 {
		t.Fatalf("p12 mode %v", st.Mode().Perm())
	}
	// Needs the password to look inside.
	out := e.ok("inspect", p12)
	if !strings.Contains(out, "PKCS#12") || !strings.Contains(out, "need a password") {
		t.Fatal(out)
	}
	t.Setenv(EnvKeyPassword, "storepass1")
	var v fileInspectView
	if err := json.Unmarshal([]byte(e.ok("inspect", p12, "--json")), &v); err != nil {
		t.Fatal(err)
	}
	if v.Contents.PrivateKeys != 1 || v.Contents.Leaf != 1 || !v.Encrypted {
		t.Fatalf("%+v", v)
	}

	jks := e.path("s.jks")
	e.ok("convert", p12, "--to", "jks", "-o", jks)
	if out := e.ok("jks", "list", jks); !strings.Contains(out, "PrivateKeyEntry") || !strings.Contains(out, "svc.example.com") {
		t.Fatal(out)
	}
	e.ok("jks", "extract", jks, "--dir", e.path("x"))
	e.ok("key", "match", e.path("x/mykey.key"), cert)
	e.ok("jks", "convert", jks, "-o", e.path("back.p12"))

	t.Setenv(EnvKeyPassword, "wrong")
	e.code(exitcode.Auth, "jks", "list", jks)
	t.Setenv(EnvKeyPassword, "")

	// Non-secret stdout, secret stdout guard, impossible conversions.
	if out := e.ok("convert", cert, "--to", "pkcs7", "--stdout"); !strings.Contains(out, "BEGIN PKCS7") {
		t.Fatal(out)
	}
	e.code(exitcode.Usage, "convert", key, "--to", "pem", "--stdout")
	if out := e.ok("convert", key, "--to", "openssh", "--stdout", "--show-secret"); !strings.Contains(out, "OPENSSH PRIVATE KEY") {
		t.Fatal(out)
	}
	e.code(exitcode.Unsupported, "convert", cert, key, "--to", "der")
	e.code(exitcode.Unsupported, "convert", key, "--to", "pkcs1")
	e.code(exitcode.Unsupported, "convert", cert, "--to", "ssh")
	e.code(exitcode.Usage, "convert", cert, "--to", "xml")
	e.code(exitcode.Usage, "convert", cert)
	e.ok("convert", cert, "--to", "der", "-o", e.path("s.der"))
	if out := e.ok("inspect", e.path("s.der")); !strings.Contains(out, "DER X.509 certificate") {
		t.Fatal(out)
	}
	os.WriteFile(e.path("junk"), []byte("hello"), 0o644)
	e.code(exitcode.Unsupported, "inspect", e.path("junk"))

	// key export formats via the vault.
	e.ok("init")
	e.ok("key", "import", key, "--name", "svc", "--yes")
	if out := e.ok("key", "export", "svc", "--key-format", "sec1", "--stdout", "--show-secret"); !strings.Contains(out, "EC PRIVATE KEY") {
		t.Fatal(out)
	}
	e.code(exitcode.Unsupported, "key", "export", "svc", "--key-format", "pkcs1", "--stdout", "--show-secret")
}

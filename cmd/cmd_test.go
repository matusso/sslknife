package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/matusso/sslknife/internal/exitcode"
)

type env struct {
	t   *testing.T
	dir string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SSLKNIFE_DATA_DIR", filepath.Join(dir, "data"))
	t.Setenv("SSLKNIFE_CONFIG", filepath.Join(dir, "config.yaml"))
	t.Setenv("SSLKNIFE_DATABASE", "")
	t.Setenv("SSLKNIFE_PASSWORD", "test password 123")
	t.Setenv("SSLKNIFE_PASSWORD_FILE", "")
	t.Setenv("SSLKNIFE_KEY_PASSWORD", "")
	t.Setenv(EnvNoKeyring, "1")
	t.Setenv("NO_COLOR", "1")
	e := &env{t: t, dir: dir}
	return e
}

func (e *env) path(name string) string { return filepath.Join(e.dir, name) }

// run executes the CLI with stdin, returning stdout, stderr and exit code.
func (e *env) runIn(stdin string, args ...string) (string, string, int) {
	e.t.Helper()
	var out, errb bytes.Buffer
	code := Execute(args, strings.NewReader(stdin), &out, &errb)
	return out.String(), errb.String(), code
}

func (e *env) run(args ...string) (string, string, int) {
	e.t.Helper()
	return e.runIn("", args...)
}

// ok runs and requires exit code 0.
func (e *env) ok(args ...string) string {
	e.t.Helper()
	out, errs, code := e.run(args...)
	if code != 0 {
		e.t.Fatalf("sslknife %s: exit %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), code, out, errs)
	}
	return out
}

func (e *env) code(want int, args ...string) string {
	e.t.Helper()
	out, errs, code := e.run(args...)
	if code != want {
		e.t.Fatalf("sslknife %s: exit %d, want %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), code, want, out, errs)
	}
	return out + errs
}

func TestVersionAndHelp(t *testing.T) {
	e := newEnv(t)
	if out := e.ok("version"); !strings.Contains(out, "SSLKnife") {
		t.Fatal(out)
	}
	var v map[string]string
	if err := json.Unmarshal([]byte(e.ok("version", "--json")), &v); err != nil || v["go"] == "" {
		t.Fatal(err, v)
	}
	e.code(exitcode.Usage, "cert", "inspect", "--no-such-flag", "x")
	e.code(exitcode.Usage, "--format", "xml", "version")
	for _, sh := range []string{"bash", "zsh", "fish", "powershell"} {
		if out := e.ok("completion", sh); len(out) < 100 {
			t.Fatalf("%s completion too short", sh)
		}
	}
}

func TestStatelessCommands(t *testing.T) {
	e := newEnv(t)
	cert, key := e.path("host.crt"), e.path("host.key")
	e.ok("cert", "create", "--cn", "host.example.com", "--san", "10.0.0.1", "-o", cert, "--key-out", key)
	// Windows only honours the read-only bit, so Unix modes are not observable.
	if st, _ := os.Stat(key); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", st.Mode().Perm())
	}

	var view inspectView
	if err := json.Unmarshal([]byte(e.ok("cert", "inspect", cert, "--json")), &view); err != nil {
		t.Fatal(err)
	}
	info := view.Certificates[0]
	if info.Subject.CommonName != "host.example.com" || !info.SelfSigned || info.SANs.IP[0] != "10.0.0.1" {
		t.Fatalf("%+v", info)
	}

	data, _ := os.ReadFile(cert)
	if out, _, code := e.runIn(string(data), "cert", "sans", "-"); code != 0 || out != "host.example.com\n10.0.0.1\n" {
		t.Fatalf("sans from stdin: %q %d", out, code)
	}
	e.ok("key", "match", key, cert)
	other := e.path("other.key")
	e.ok("key", "generate", "-o", other, "--algorithm", "ed25519")
	e.code(exitcode.CheckFailed, "key", "match", other, cert)
	e.code(exitcode.Usage, "key", "generate", "-o", other) // exists
	if out := e.ok("key", "inspect", other); !strings.Contains(out, "Ed25519") || strings.Contains(out, "PRIVATE KEY") {
		t.Fatal(out)
	}
	if out := e.ok("key", "public", other); !strings.HasPrefix(out, "-----BEGIN PUBLIC KEY-----") {
		t.Fatal(out)
	}
	if out := e.ok("fingerprint", cert, "--plain"); !strings.Contains(out, "SHA1:") {
		t.Fatal(out)
	}
	e.ok("cert", "expires", cert, "--check", "30d")
	e.code(exitcode.CheckFailed, "cert", "expires", cert, "--check", "400d")
	e.code(exitcode.CheckFailed, "cert", "lint", cert, "--hostname", "wrong.example.com")
	e.code(exitcode.NotFound, "cert", "inspect", e.path("missing.pem"))

	der := e.ok("cert", "pem", cert, "--der")
	if err := os.WriteFile(e.path("host.der"), []byte(der), 0o644); err != nil {
		t.Fatal(err)
	}
	if out := e.ok("cert", "pem", e.path("host.der")); out != string(data) {
		t.Fatal("DER round trip")
	}
	if out := e.ok("cert", "diff", cert, e.path("host.der"), "--changed"); !strings.Contains(out, "identical") {
		t.Fatal(out)
	}
	e.ok("cert", "create", "--cn", "other.example.com", "-o", e.path("other.crt"), "--key-out", e.path("other2.key"))
	if out := e.code(exitcode.CheckFailed, "cert", "diff", cert, e.path("other.crt")); !strings.Contains(out, "+ other.example.com") {
		t.Fatal(out)
	}
}

func TestVaultWorkflow(t *testing.T) {
	e := newEnv(t)
	e.code(exitcode.NotFound, "cert", "list")
	e.ok("init")
	e.code(exitcode.Usage, "init")

	e.ok("cert", "create", "--type", "root-ca", "--cn", "Test Root", "--store", "--name", "root")
	e.ok("cert", "create", "--type", "intermediate-ca", "--cn", "Test Issuing", "--ca", "root", "--store", "--name", "issuing", "--path-len", "0")
	leaf, leafKey := e.path("api.crt"), e.path("api.key")
	e.ok("cert", "create", "--cn", "api.example.com", "--ca", "issuing", "--validity", "10d", "-o", leaf, "--key-out", leafKey)
	e.ok("cert", "import", leaf, "--name", "api", "--tag", "production")

	// Import protection: private keys need confirmation.
	e.code(exitcode.Usage, "key", "import", leafKey)
	e.ok("key", "import", leafKey, "--name", "api-key", "--yes")

	var list []certSummary
	if err := json.Unmarshal([]byte(e.ok("cert", "list", "--json")), &list); err != nil || len(list) != 3 {
		t.Fatal(err, len(list))
	}
	if list[0].Name != "api" || list[0].Status != "WARNING" || list[0].KeyID == "" {
		t.Fatalf("%+v", list[0])
	}
	if out := e.ok("cert", "show", "api"); !strings.Contains(out, "Test Root") || !strings.Contains(out, "└── ") {
		t.Fatal(out)
	}
	e.code(exitcode.CheckFailed, "cert", "expiring")
	e.ok("cert", "expiring", "--within", "1d")

	var sr searchView
	if err := json.Unmarshal([]byte(e.ok("search", "tag:production", "--json")), &sr); err != nil || len(sr.Certificates) != 1 {
		t.Fatal(err, sr)
	}
	e.code(exitcode.Usage, "search", "expires:<soon")

	// Secret output controls.
	e.code(exitcode.Usage, "key", "export", "api-key", "--stdout")
	if out := e.ok("key", "export", "api-key", "--stdout", "--show-secret"); !strings.Contains(out, "PRIVATE KEY") {
		t.Fatal("export")
	}
	exported := e.path("exported.key")
	e.ok("key", "export", "api-key", "-o", exported)
	e.ok("key", "match", exported, "api")

	chain := e.ok("cert", "export", "api", "--chain")
	if strings.Count(chain, "BEGIN CERTIFICATE") != 3 {
		t.Fatal("chain export")
	}

	e.ok("cert", "tag", "api", "k8s")
	e.ok("cert", "untag", "api", "production")
	e.ok("cert", "note", "api", "rotated")
	e.ok("cert", "rename", "api", "api-prod")
	if out := e.ok("cert", "show", "api-prod", "--json"); !strings.Contains(out, `"rotated"`) || !strings.Contains(out, `"k8s"`) {
		t.Fatal(out)
	}

	// Wrong or missing password.
	t.Setenv("SSLKNIFE_PASSWORD", "nope")
	e.code(exitcode.Auth, "cert", "list")
	t.Setenv("SSLKNIFE_PASSWORD", "")
	e.code(exitcode.Auth, "cert", "list")
	t.Setenv("SSLKNIFE_PASSWORD", "test password 123")

	e.code(exitcode.Usage, "cert", "delete", "api-prod")
	e.ok("cert", "delete", "api-prod", "--yes")
	e.code(exitcode.NotFound, "cert", "show", "api-prod")
	e.ok("key", "delete", "api-key", "--yes")
	if out := e.ok("vault", "status", "--json"); !strings.Contains(out, `"certificates": 2`) {
		t.Fatal(out)
	}
}

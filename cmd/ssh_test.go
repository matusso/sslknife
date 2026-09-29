package cmd

import (
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/matusso/sslknife/internal/exitcode"
	"github.com/matusso/sslknife/internal/sshkeys"
)

func TestSSHCommands(t *testing.T) {
	e := newEnv(t)
	id := e.path("id_test")
	t.Setenv(EnvSSHPassphrase, "ssh passphrase")
	e.ok("ssh", "generate", "-o", id, "-C", "tester@box")
	// Windows only honours the read-only bit, so Unix modes are not observable.
	if st, _ := os.Stat(id); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatal("mode")
	}
	var info sshkeys.Info
	if err := json.Unmarshal([]byte(e.ok("ssh", "inspect", id, "--json")), &info); err != nil {
		t.Fatal(err)
	}
	// The comment of an encrypted key is inside the encrypted section, so
	// only the type and the fingerprint are visible without the passphrase.
	if info.Type != "ssh-ed25519" || !info.Encrypted || info.FingerprintSHA256 == "" {
		t.Fatalf("%+v", info)
	}
	pubInfo := e.ok("ssh", "inspect", id+".pub")
	if !strings.Contains(pubInfo, "tester@box") || !strings.Contains(pubInfo, info.FingerprintSHA256) {
		t.Fatal(pubInfo)
	}
	if out := e.ok("ssh", "fingerprint", id+".pub"); !strings.HasPrefix(out, "256 SHA256:") {
		t.Fatal(out)
	}
	if out := e.ok("ssh", "public", id); !strings.HasPrefix(out, "ssh-ed25519 ") {
		t.Fatal(out)
	}
	if out := e.ok("ssh", "convert", id, "--to", "pkcs8", "--stdout", "--show-secret"); !strings.Contains(out, "BEGIN PRIVATE KEY") {
		t.Fatal(out)
	}
	if out := e.ok("ssh", "convert", id+".pub", "--to", "rfc4716", "--stdout"); !strings.Contains(out, "BEGIN SSH2 PUBLIC KEY") {
		t.Fatal(out)
	}

	// Certificates.
	ca := e.path("ca")
	e.ok("ssh", "generate", "-o", ca, "--no-passphrase", "--type", "rsa-3072")
	e.ok("ssh", "cert", "sign", "--ca", ca, "--key", id+".pub", "--principal", "alice", "--id", "alice@test", "--validity", "1h", "-O", "source-address=10.0.0.0/8")
	out := e.ok("ssh", "cert", "inspect", id+"-cert.pub")
	for _, want := range []string{"alice@test", "source-address", "rsa-sha2-512", "permit-pty"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	e.code(exitcode.Usage, "ssh", "cert", "sign", "--ca", ca, "--key", id+".pub")
	e.ok("ssh", "cert", "create", "--ca", ca, "--principal", "deploy", "--validity", "30m", "-o", e.path("deploy"), "--no-passphrase")
	if _, err := os.Stat(e.path("deploy-cert.pub")); err != nil {
		t.Fatal(err)
	}

	// Vault.
	e.ok("init")
	e.code(exitcode.Usage, "ssh", "import", id)
	e.ok("ssh", "import", id, "--yes", "--name", "laptop", "--tag", "personal")
	e.ok("ssh", "import", id+".pub") // same key, already stored
	var list []sshKeyView
	if err := json.Unmarshal([]byte(e.ok("ssh", "list", "--json")), &list); err != nil || len(list) != 1 || !list[0].Passphrase || !list[0].HasPrivate {
		t.Fatal(err, list)
	}
	exported := e.path("exported")
	e.ok("ssh", "export", "laptop", "-o", exported)
	orig, _ := os.ReadFile(id)
	got, _ := os.ReadFile(exported)
	if string(orig) != string(got) {
		t.Fatal("exported private key differs from the imported file")
	}
	e.code(exitcode.Usage, "ssh", "export", "laptop", "--stdout")
	if out := e.ok("ssh", "export", "laptop", "--public"); !strings.HasPrefix(out, "ssh-ed25519 ") {
		t.Fatal(out)
	}
	var sr searchView
	if err := json.Unmarshal([]byte(e.ok("search", "type:ssh", "tag:personal", "--json")), &sr); err != nil || len(sr.SSHKeys) != 1 || len(sr.Certificates) != 0 {
		t.Fatal(err, sr)
	}
	e.ok("ssh", "delete", "laptop", "--yes")
	e.code(exitcode.NotFound, "ssh", "show", "laptop")
}

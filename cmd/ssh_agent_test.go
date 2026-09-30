package cmd

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh/agent"

	"github.com/matusso/sslknife/internal/exitcode"
	"github.com/matusso/sslknife/internal/sshagent"
)

// startAgent runs an in-memory agent and points SSH_AUTH_SOCK at it.
func startAgent(t *testing.T) agent.Agent {
	t.Helper()
	// Unix socket paths are short (104 bytes on macOS): avoid t.TempDir.
	dir, err := os.MkdirTemp("", "ska")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	l, path, cleanup, err := sshagent.Listen(filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	kr := agent.NewKeyring()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sshagent.Serve(ctx, l, kr); close(done) }()
	t.Cleanup(func() { cancel(); <-done; cleanup() })
	t.Setenv(sshagent.EnvSocket, path)
	return kr
}

func TestSSHAgentCommands(t *testing.T) {
	e := newEnv(t)
	kr := startAgent(t)
	t.Setenv(EnvSSHPassphrase, "shared passphrase")
	laptop, deploy, plain := e.path("id_laptop"), e.path("id_deploy"), e.path("id_plain")
	e.ok("ssh", "generate", "-o", laptop, "-C", "me@laptop")
	e.ok("ssh", "generate", "-o", deploy, "-C", "deploy", "--type", "ecdsa-p256")
	e.ok("ssh", "generate", "-o", plain, "--no-passphrase", "-C", "plain")
	e.ok("init")
	e.ok("ssh", "import", laptop, "--yes", "--name", "laptop")
	e.ok("ssh", "import", deploy, "--yes", "--name", "deploy", "--tag", "prod")
	e.ok("ssh", "import", plain+".pub", "--name", "public-only")

	e.code(exitcode.Usage, "ssh", "agent", "add")
	e.code(exitcode.NotFound, "ssh", "agent", "add", "public-only")
	e.code(exitcode.Usage, "ssh", "agent", "add", "laptop", "--cert", plain+".pub")
	if out := e.ok("ssh", "agent", "list"); !strings.Contains(out, "no identities") {
		t.Fatal(out)
	}

	// Stored keys by name, and a key file with its certificate picked up.
	e.ok("ssh", "cert", "sign", "--ca", plain, "--key", laptop+".pub", "--principal", "me", "--validity", "1h")
	e.ok("ssh", "agent", "add", "laptop", "--cert", laptop+"-cert.pub", "--lifetime", "1h")
	var ids []agentIdentity
	if err := json.Unmarshal([]byte(e.ok("ssh", "agent", "list", "--json")), &ids); err != nil || len(ids) != 2 {
		t.Fatal(err, ids)
	}
	// The comment of an encrypted key is not visible, so the vault name is used.
	if ids[0].Comment != "laptop" || ids[0].Fingerprint != ids[1].Fingerprint || !ids[1].Certificate {
		t.Fatalf("%+v", ids)
	}
	ks, _ := kr.List()
	if _, err := kr.Signers(); err != nil || len(ks) != 2 {
		t.Fatal(err, len(ks))
	}

	// Removing a key also removes its certificate.
	e.ok("ssh", "agent", "remove", "laptop")
	if ks, _ := kr.List(); len(ks) != 0 {
		t.Fatal(len(ks))
	}
	e.code(exitcode.NotFound, "ssh", "agent", "remove", "laptop")

	e.ok("ssh", "agent", "add", "--tag", "prod", plain)
	if err := json.Unmarshal([]byte(e.ok("ssh", "agent", "list", "--json")), &ids); err != nil || len(ids) != 2 || ids[0].Type == ids[1].Type {
		t.Fatal(err, ids)
	}
	e.ok("ssh", "agent", "remove", "--all")
	e.ok("ssh", "agent", "add", "--all")
	if ks, _ := kr.List(); len(ks) != 2 {
		t.Fatal(len(ks))
	}

	// A wrong passphrase fails.
	t.Setenv(EnvSSHPassphrase, "wrong")
	e.code(exitcode.Auth, "ssh", "agent", "add", "laptop")
	t.Setenv(EnvSSHPassphrase, "shared passphrase")

	// No agent.
	t.Setenv(sshagent.EnvSocket, "")
	e.code(exitcode.NotFound, "ssh", "agent", "list")
}

func TestSSHAgentServe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	e := newEnv(t)
	key := e.path("id")
	e.ok("ssh", "generate", "-o", key, "--no-passphrase")
	sockFile := e.path("sock")
	// The child sees the agent socket; its exit status is passed through.
	e.ok("ssh", "agent", "serve", key, "--", "sh", "-c", `test -S "$SSH_AUTH_SOCK" && echo "$SSH_AUTH_SOCK" > `+sockFile)
	e.code(3, "ssh", "agent", "serve", key, "--", "sh", "-c", "exit 3")
	e.code(exitcode.NotFound, "ssh", "agent", "serve", key, "--", "sslknife-no-such-command")
	e.code(exitcode.Usage, "ssh", "agent", "serve", "--", "true")
	sock, err := os.ReadFile(sockFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(strings.TrimSpace(string(sock)))); !os.IsNotExist(err) {
		t.Fatal("agent socket directory left behind")
	}
}

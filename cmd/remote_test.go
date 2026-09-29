package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/matusso/sslknife/internal/exitcode"
	"github.com/matusso/sslknife/internal/vaultkv/vaulttest"
)

func TestRemoteVaultSyncAcrossDevices(t *testing.T) {
	e := newEnv(t)
	srv := vaulttest.New(t)
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("VAULT_NAMESPACE", "")
	t.Setenv("VAULT_TOKEN", srv.Token)
	t.Setenv("HOME", e.dir) // no ~/.vault-token from the developer machine

	// Two devices: separate configs and vaults, one shared Vault remote.
	device := func(name string) []string {
		cfg := e.path(name + ".yaml")
		body := fmt.Sprintf("remote:\n  type: vault\n  address: %s\n  mount: secret\n  path: team/pki\n  transit_key: %s\n", srv.URL, srv.Transit)
		if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return []string{"--config", cfg, "--database", e.path(name + ".db")}
	}
	laptop, desktop := device("laptop"), device("desktop")
	args := func(dev []string, a ...string) []string { return append(append([]string{}, dev...), a...) }

	e.ok(args(laptop, "init")...)
	e.ok(args(desktop, "init")...)

	// The laptop creates a CA with its key; auto-sync pushes it.
	_, errs, code := e.run(args(laptop, "cert", "create", "--type", "root-ca", "--cn", "Team Root", "--store", "--name", "team-root")...)
	if code != 0 || !strings.Contains(errs, "Synced with Vault: 2 pushed") {
		t.Fatalf("exit %d, stderr: %s", code, errs)
	}
	if srv.Data("team/pki/manifest") == nil {
		t.Fatalf("no manifest in Vault: %v", srv.Paths())
	}

	// The desktop sees the certificate and can use the private key to issue.
	out := e.ok(args(desktop, "cert", "list", "--json")...)
	if !strings.Contains(out, "Team Root") {
		t.Fatalf("desktop does not see the CA: %s", out)
	}
	e.ok(args(desktop, "cert", "create", "--cn", "api.example.com", "--ca", "team-root", "--store", "--name", "api")...)
	e.ok(args(laptop, "cert", "show", "api")...)

	// Explicit sync reports nothing to do; status is healthy.
	if out := e.ok(args(laptop, "remote", "sync")...); !strings.Contains(out, "Already in sync") {
		t.Fatal(out)
	}
	var st map[string]any
	if err := json.Unmarshal([]byte(e.ok(args(desktop, "remote", "status", "--json")...)), &st); err != nil {
		t.Fatal(err)
	}
	if st["objects"].(float64) != 4 || len(st["pending"].([]any)) != 0 {
		t.Fatalf("status: %v", st)
	}

	// --no-sync keeps a change local until the next sync.
	e.ok(args(laptop, "--no-sync", "cert", "tag", "api", "prod")...)
	if out := e.ok(args(laptop, "remote", "sync", "--dry-run")...); !strings.Contains(out, "push") {
		t.Fatal(out)
	}
	e.ok(args(laptop, "remote", "sync")...)
	if out := e.ok(args(desktop, "cert", "show", "api", "--json")...); !strings.Contains(out, `"prod"`) {
		t.Fatal(out)
	}

	// An unreachable remote only warns; the local vault keeps working.
	bad := e.path("bad.yaml")
	os.WriteFile(bad, []byte("remote:\n  type: vault\n  address: http://127.0.0.1:1\n"), 0o600)
	_, errs, code = e.run("--config", bad, "--database", e.path("laptop.db"), "cert", "list")
	if code != 0 || !strings.Contains(errs, "remote sync failed") {
		t.Fatalf("exit %d, stderr: %s", code, errs)
	}
	// A wrong token is an authentication failure for an explicit sync.
	t.Setenv("VAULT_TOKEN", "wrong")
	e.code(exitcode.Auth, args(laptop, "remote", "sync")...)
}

func TestRemoteNotConfigured(t *testing.T) {
	e := newEnv(t)
	e.ok("init")
	e.code(exitcode.Usage, "remote", "sync")
}

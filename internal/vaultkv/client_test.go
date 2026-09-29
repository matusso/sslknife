package vaultkv_test

import (
	"context"
	"errors"
	"testing"

	"github.com/matusso/sslknife/internal/vaultkv"
	"github.com/matusso/sslknife/internal/vaultkv/vaulttest"
)

func TestClient(t *testing.T) {
	ctx := context.Background()
	srv := vaulttest.New(t)
	srv.Users["alice"] = "correct horse"
	c, err := vaultkv.New(vaultkv.Options{Address: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.LookupSelf(ctx); !errors.Is(err, vaultkv.ErrPermission) {
		t.Fatalf("no token: %v", err)
	}
	if _, err := c.LoginPassword(ctx, "userpass", "alice", []byte("wrong")); err == nil {
		t.Fatal("wrong password accepted")
	}
	if _, err := c.LoginPassword(ctx, "userpass", "alice", []byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	c.SetToken("")
	if _, err := c.LoginAppRole(ctx, "", srv.RoleID, srv.Secret); err != nil {
		t.Fatal(err)
	}
	if ti, err := c.LookupSelf(ctx); err != nil || ti.DisplayName == "" {
		t.Fatal(ti, err)
	}

	kv := c.KV("secret")
	if _, err := kv.Get(ctx, "a/b"); !errors.Is(err, vaultkv.ErrNotFound) {
		t.Fatal(err)
	}
	if v, err := kv.Put(ctx, "a/b", map[string]any{"x": "1"}, 0); err != nil || v != 1 {
		t.Fatal(v, err)
	}
	if _, err := kv.Put(ctx, "a/b", map[string]any{"x": "2"}, 0); !errors.Is(err, vaultkv.ErrConflict) {
		t.Fatalf("cas: %v", err)
	}
	if s, err := kv.Get(ctx, "a/b"); err != nil || s.Data["x"] != "1" || s.Version != 1 {
		t.Fatal(s, err)
	}
	if keys, err := kv.List(ctx, "a"); err != nil || len(keys) != 1 || keys[0] != "b" {
		t.Fatal(keys, err)
	}
	if err := kv.Destroy(ctx, "a/b"); err != nil {
		t.Fatal(err)
	}

	tr := c.Transit("", srv.Transit)
	ct, err := tr.Encrypt(ctx, []byte("secret"))
	if err != nil || ct == "" {
		t.Fatal(ct, err)
	}
	if pt, err := tr.Decrypt(ctx, ct); err != nil || string(pt) != "secret" {
		t.Fatal(string(pt), err)
	}

	unreachable, _ := vaultkv.New(vaultkv.Options{Address: "http://127.0.0.1:1", Token: "x"})
	if _, err := unreachable.LookupSelf(ctx); !errors.Is(err, vaultkv.ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err := vaultkv.New(vaultkv.Options{Address: "vault.example.com"}); err == nil {
		t.Fatal("address without scheme accepted")
	}
}

package sshagent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh/agent"
)

func TestServeAndDial(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	kr := agent.NewKeyring()
	if err := kr.Add(agent.AddedKey{PrivateKey: priv, Comment: "test"}); err != nil {
		t.Fatal(err)
	}
	l, path, cleanup, err := Listen("")
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Dir(path)); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("socket directory: %v %v", st.Mode(), err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, l, kr) }()

	c, err := Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := c.List()
	if err != nil || len(ks) != 1 || ks[0].Comment != "test" {
		t.Fatal(ks, err)
	}
	// A second listener on a live socket must not steal it.
	if _, _, _, err := Listen(path); err == nil {
		t.Fatal("listening on a socket in use")
	}
	c.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	cleanup()
	if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("temporary socket directory left behind")
	}
}

func TestDialWithoutAgent(t *testing.T) {
	t.Setenv(EnvSocket, "")
	if _, err := Dial(""); !errors.Is(err, ErrNoAgent) {
		t.Fatal(err)
	}
}

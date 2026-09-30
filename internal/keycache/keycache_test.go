//go:build !windows

package keycache

import (
	"bytes"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func TestServe(t *testing.T) {
	// Keep the socket path short: macOS limits it to 104 bytes.
	dir, err := os.MkdirTemp("/tmp", "skc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	t.Setenv("XDG_RUNTIME_DIR", dir)

	const id = "vault-1"
	if _, err := Get(id); !errors.Is(err, ErrNotCached) {
		t.Fatal("empty cache answered", err)
	}
	path, err := SocketPath(id)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	root := []byte("0123456789abcdef0123456789abcdef")
	done := make(chan error, 1)
	go func() { done <- Serve(l, id, root, 300*time.Millisecond) }()

	got, err := Get(id)
	if err != nil || !bytes.Equal(got, root) {
		t.Fatal("get", err)
	}
	if exp, err := Status(id); err != nil || time.Until(exp) <= 0 {
		t.Fatal("status", exp, err)
	}
	if _, err := call("other", "get"); err == nil {
		t.Fatal("key handed out for another vault")
	}
	if err := Lock(id); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	// The idle timeout stops the server on its own.
	os.Remove(path)
	l, err = net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	go func() { done <- Serve(l, id, root, 50*time.Millisecond) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cache did not expire")
	}
}

func TestSocketDirMustBePrivate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)
	d, err := socketDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := socketDir(); err == nil {
		t.Fatal("accepted a world-readable socket directory")
	}
}

package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func TestSealOpen(t *testing.T) {
	key := RandomBytes(KeySize)
	nonce, ct, err := Seal(key, []byte("secret"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Open(key, nonce, ct, []byte("aad"))
	if err != nil || string(pt) != "secret" {
		t.Fatalf("open: %q %v", pt, err)
	}
	if _, err := Open(key, nonce, ct, []byte("other")); !errors.Is(err, ErrDecrypt) {
		t.Fatal("aad not bound")
	}
	ct[0] ^= 1
	if _, err := Open(key, nonce, ct, []byte("aad")); !errors.Is(err, ErrDecrypt) {
		t.Fatal("tamper not detected")
	}
	if _, err := Open(RandomBytes(KeySize), nonce, ct, nil); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, _, err := Seal([]byte("short"), nil, nil); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestDerive(t *testing.T) {
	root := RandomBytes(KeySize)
	a, _ := Derive(root, "a")
	b, _ := Derive(root, "b")
	a2, _ := Derive(root, "a")
	if bytes.Equal(a, b) || !bytes.Equal(a, a2) || len(a) != KeySize {
		t.Fatal("derive not domain separated or not deterministic")
	}
}

func TestPasswordKey(t *testing.T) {
	p := Argon2Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}
	salt := RandomBytes(16)
	k1, err := PasswordKey([]byte("pw"), salt, p)
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := PasswordKey([]byte("pw"), salt, p)
	k3, _ := PasswordKey([]byte("pw2"), salt, p)
	if !bytes.Equal(k1, k2) || bytes.Equal(k1, k3) {
		t.Fatal("kdf mismatch")
	}
	if _, err := PasswordKey([]byte("pw"), salt, Argon2Params{Time: 1, MemoryKiB: 1, Threads: 1}); err == nil {
		t.Fatal("weak params accepted")
	}
	if _, err := PasswordKey([]byte("pw"), []byte("short"), p); err == nil {
		t.Fatal("short salt accepted")
	}
}

func TestNewID(t *testing.T) {
	if a, b := NewID(), NewID(); len(a) != 12 || a == b {
		t.Fatal(a, b)
	}
}

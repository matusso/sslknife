package secrets

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	skcrypto "github.com/matusso/sslknife/internal/crypto"
)

var fastKDF = skcrypto.Argon2Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}

func TestKeyFileRoundTrip(t *testing.T) {
	kf, root := NewKeyFile()
	kr := &MemoryKeyring{}
	if _, err := kf.AddPasswordSlot(root, []byte("correct horse"), fastKDF); err != nil {
		t.Fatal(err)
	}
	krID, err := kf.AddKeyringSlot(root, kr)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sub", "db.keys")
	if err := kf.Save(path); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	// Windows only honours the read-only bit, so Unix modes are not observable.
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, root) {
		t.Fatal("root key in plaintext")
	}

	kf2, err := LoadKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := kf2.UnlockPassword([]byte("correct horse"))
	if err != nil || !bytes.Equal(got, root) {
		t.Fatal("password unlock failed", err)
	}
	if _, err := kf2.UnlockPassword([]byte("wrong")); !errors.Is(err, ErrBadPassword) {
		t.Fatal("wrong password accepted", err)
	}
	got, err = kf2.UnlockKeyring(kr)
	if err != nil || !bytes.Equal(got, root) {
		t.Fatal("keyring unlock failed", err)
	}
	if err := kf2.RemoveSlot(krID, kr); err != nil {
		t.Fatal(err)
	}
	if _, err := kf2.UnlockKeyring(kr); err == nil {
		t.Fatal("removed slot still unlocks")
	}
	if err := kf2.RemoveSlot(kf2.Slots[0].ID, kr); err == nil {
		t.Fatal("removed last slot")
	}
}

func TestSlotBoundToDB(t *testing.T) {
	kf, root := NewKeyFile()
	if _, err := kf.AddPasswordSlot(root, []byte("pw"), fastKDF); err != nil {
		t.Fatal(err)
	}
	kf.DBID = "other"
	if _, err := kf.UnlockPassword([]byte("pw")); err == nil {
		t.Fatal("slot moved to another db must not unlock")
	}
}

func TestUnlocker(t *testing.T) {
	kf, root := NewKeyFile()
	if _, err := kf.AddPasswordSlot(root, []byte("pw"), fastKDF); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{EnvPassword: "pw"}
	u := Unlocker{Getenv: func(k string) string { return env[k] }}
	got, method, err := u.Unlock(kf)
	if err != nil || method != MethodEnv || !bytes.Equal(got, root) {
		t.Fatal(method, err)
	}

	env = map[string]string{}
	if _, _, err := u.Unlock(kf); !errors.Is(err, ErrLocked) {
		t.Fatal("expected locked", err)
	}

	pwFile := filepath.Join(t.TempDir(), "pw")
	_ = os.WriteFile(pwFile, []byte("pw\n"), 0o600)
	env = map[string]string{EnvPasswordFile: pwFile}
	if _, method, err := u.Unlock(kf); err != nil || method != MethodEnv {
		t.Fatal(method, err)
	}

	env = map[string]string{}
	tries := 0
	u.Prompt = func() ([]byte, error) {
		tries++
		if tries < 2 {
			return []byte("bad"), nil
		}
		return []byte("pw"), nil
	}
	if _, method, err := u.Unlock(kf); err != nil || method != MethodPrompt || tries != 2 {
		t.Fatal(method, err, tries)
	}
}

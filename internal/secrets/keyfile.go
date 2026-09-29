// Package secrets manages the vault root key: the keyslot file that stores
// it wrapped under password- or keychain-derived keys, and the providers
// used to unlock it (environment, OS keychain, TTY).
package secrets

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	skcrypto "github.com/matusso/sslknife/internal/crypto"
)

// Slot types.
const (
	SlotPassword = "password"
	SlotKeyring  = "keyring"
)

const keyFileVersion = 1

// ErrBadPassword means no password slot accepted the supplied password.
var ErrBadPassword = errors.New("incorrect vault password")

// ErrNoSlot means the key file has no slot of the requested type.
var ErrNoSlot = errors.New("no matching keyslot")

// KeyFile is the JSON document stored next to the database. It never
// contains the root key in plaintext.
type KeyFile struct {
	Version int       `json:"version"`
	DBID    string    `json:"db_id"`
	Created time.Time `json:"created"`
	Slots   []Slot    `json:"slots"`
}

// Slot wraps the root key under one key-encryption key.
type Slot struct {
	ID      string      `json:"id"`
	Type    string      `json:"type"`
	Created time.Time   `json:"created"`
	KDF     *KDF        `json:"kdf,omitempty"`
	Keyring *KeyringRef `json:"keyring,omitempty"`
	Nonce   []byte      `json:"nonce"`
	Wrapped []byte      `json:"wrapped"`
}

// KDF describes how a password slot's KEK is derived.
type KDF struct {
	Name   string                `json:"name"`
	Salt   []byte                `json:"salt"`
	Params skcrypto.Argon2Params `json:"params"`
}

// KeyringRef locates a slot's KEK in the OS keychain.
type KeyringRef struct {
	Service string `json:"service"`
	Account string `json:"account"`
}

// NewKeyFile creates a key file for a new vault and returns the freshly
// generated root key. The caller must add at least one slot before saving.
func NewKeyFile() (*KeyFile, []byte) {
	return &KeyFile{
		Version: keyFileVersion,
		DBID:    skcrypto.NewID() + skcrypto.NewID(),
		Created: time.Now().UTC().Truncate(time.Second),
	}, skcrypto.RandomBytes(skcrypto.KeySize)
}

func (kf *KeyFile) aad(slotID string) []byte {
	return []byte("sslknife-keyslot-v1|" + kf.DBID + "|" + slotID)
}

func (kf *KeyFile) wrap(s *Slot, kek, root []byte) error {
	nonce, ct, err := skcrypto.Seal(kek, root, kf.aad(s.ID))
	if err != nil {
		return err
	}
	s.Nonce, s.Wrapped = nonce, ct
	kf.Slots = append(kf.Slots, *s)
	return nil
}

func (kf *KeyFile) unwrap(s *Slot, kek []byte) ([]byte, error) {
	return skcrypto.Open(kek, s.Nonce, s.Wrapped, kf.aad(s.ID))
}

// AddPasswordSlot wraps root under a key derived from password.
func (kf *KeyFile) AddPasswordSlot(root, password []byte, params skcrypto.Argon2Params) (string, error) {
	salt := skcrypto.RandomBytes(16)
	kek, err := skcrypto.PasswordKey(password, salt, params)
	if err != nil {
		return "", err
	}
	defer skcrypto.Zero(kek)
	s := &Slot{
		ID:      skcrypto.NewID(),
		Type:    SlotPassword,
		Created: time.Now().UTC().Truncate(time.Second),
		KDF:     &KDF{Name: "argon2id", Salt: salt, Params: params},
	}
	return s.ID, kf.wrap(s, kek, root)
}

// AddKeyringSlot stores a random KEK in the OS keychain and wraps root under it.
func (kf *KeyFile) AddKeyringSlot(root []byte, kr Keyring) (string, error) {
	kek := skcrypto.RandomBytes(skcrypto.KeySize)
	defer skcrypto.Zero(kek)
	s := &Slot{
		ID:      skcrypto.NewID(),
		Type:    SlotKeyring,
		Created: time.Now().UTC().Truncate(time.Second),
		Keyring: &KeyringRef{Service: KeyringService, Account: kf.DBID + "/" + skcrypto.NewID()},
	}
	if err := kr.Set(s.Keyring.Service, s.Keyring.Account, kek); err != nil {
		return "", fmt.Errorf("store key in OS keychain: %w", err)
	}
	return s.ID, kf.wrap(s, kek, root)
}

// UnlockPassword tries every password slot.
func (kf *KeyFile) UnlockPassword(password []byte) ([]byte, error) {
	found := false
	for i := range kf.Slots {
		s := &kf.Slots[i]
		if s.Type != SlotPassword || s.KDF == nil || s.KDF.Name != "argon2id" {
			continue
		}
		found = true
		kek, err := skcrypto.PasswordKey(password, s.KDF.Salt, s.KDF.Params)
		if err != nil {
			return nil, fmt.Errorf("keyslot %s: %w", s.ID, err)
		}
		root, err := kf.unwrap(s, kek)
		skcrypto.Zero(kek)
		if err == nil {
			return root, nil
		}
	}
	if !found {
		return nil, ErrNoSlot
	}
	return nil, ErrBadPassword
}

// UnlockKeyring tries every keychain slot.
func (kf *KeyFile) UnlockKeyring(kr Keyring) ([]byte, error) {
	lastErr := ErrNoSlot
	for i := range kf.Slots {
		s := &kf.Slots[i]
		if s.Type != SlotKeyring || s.Keyring == nil {
			continue
		}
		kek, err := kr.Get(s.Keyring.Service, s.Keyring.Account)
		if err != nil {
			lastErr = err
			continue
		}
		root, err := kf.unwrap(s, kek)
		skcrypto.Zero(kek)
		if err == nil {
			return root, nil
		}
		lastErr = fmt.Errorf("keyslot %s: %w", s.ID, err)
	}
	return nil, lastErr
}

// HasSlot reports whether a slot of type exists.
func (kf *KeyFile) HasSlot(typ string) bool {
	for _, s := range kf.Slots {
		if s.Type == typ {
			return true
		}
	}
	return false
}

// RemoveSlot deletes a slot by ID. The last slot cannot be removed because
// that would make the vault permanently inaccessible. Keychain entries are
// deleted when kr is non-nil.
func (kf *KeyFile) RemoveSlot(id string, kr Keyring) error {
	for i, s := range kf.Slots {
		if s.ID != id {
			continue
		}
		if len(kf.Slots) == 1 {
			return errors.New("refusing to remove the last keyslot")
		}
		if s.Type == SlotKeyring && kr != nil && s.Keyring != nil {
			_ = kr.Delete(s.Keyring.Service, s.Keyring.Account)
		}
		kf.Slots = append(kf.Slots[:i], kf.Slots[i+1:]...)
		return nil
	}
	return fmt.Errorf("keyslot %q not found", id)
}

// LoadKeyFile reads and validates a key file.
func LoadKeyFile(path string) (*KeyFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kf KeyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, fmt.Errorf("parse key file %s: %w", path, err)
	}
	if kf.Version != keyFileVersion {
		return nil, fmt.Errorf("unsupported key file version %d", kf.Version)
	}
	if kf.DBID == "" || len(kf.Slots) == 0 {
		return nil, fmt.Errorf("key file %s has no keyslots", path)
	}
	return &kf, nil
}

// Save writes the key file atomically with mode 0600.
func (kf *KeyFile) Save(path string) error {
	if len(kf.Slots) == 0 {
		return errors.New("key file must contain at least one keyslot")
	}
	data, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, append(data, '\n'), 0o600)
}

// WriteFileAtomic writes data to a temporary file in the same directory and
// renames it over path, so readers never observe a partial file.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

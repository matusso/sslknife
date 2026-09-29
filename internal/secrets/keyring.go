package secrets

import (
	"encoding/hex"
	"errors"
	"sync"

	"github.com/zalando/go-keyring"
)

// KeyringService is the service name used for OS keychain entries.
const KeyringService = "sslknife"

// Keyring stores small secrets in an OS credential store.
type Keyring interface {
	Get(service, account string) ([]byte, error)
	Set(service, account string, secret []byte) error
	Delete(service, account string) error
}

// ErrKeyringNotFound is returned when the entry does not exist.
var ErrKeyringNotFound = errors.New("keychain entry not found")

// OSKeyring uses macOS Keychain, Windows Credential Manager or the freedesktop
// Secret Service. Values are hex-encoded because some backends only store
// text.
type OSKeyring struct{}

func (OSKeyring) Get(service, account string) ([]byte, error) {
	s, err := keyring.Get(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, ErrKeyringNotFound
	}
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(s)
}

func (OSKeyring) Set(service, account string, secret []byte) error {
	return keyring.Set(service, account, hex.EncodeToString(secret))
}

func (OSKeyring) Delete(service, account string) error {
	err := keyring.Delete(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrKeyringNotFound
	}
	return err
}

// MemoryKeyring is an in-process keyring for tests.
type MemoryKeyring struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (k *MemoryKeyring) Get(service, account string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.m[service+"\x00"+account]
	if !ok {
		return nil, ErrKeyringNotFound
	}
	return append([]byte(nil), v...), nil
}

func (k *MemoryKeyring) Set(service, account string, secret []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.m == nil {
		k.m = map[string][]byte{}
	}
	k.m[service+"\x00"+account] = append([]byte(nil), secret...)
	return nil
}

func (k *MemoryKeyring) Delete(service, account string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.m[service+"\x00"+account]; !ok {
		return ErrKeyringNotFound
	}
	delete(k.m, service+"\x00"+account)
	return nil
}

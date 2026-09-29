// Package crypto holds the small set of primitives the vault is built from:
// AES-256-GCM sealing, HKDF key derivation, Argon2id password hashing and
// random identifiers. It deliberately contains no novel constructions.
//
// Importers usually alias it: skcrypto "github.com/matusso/sslknife/internal/crypto".
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// KeySize is the size of all symmetric keys (AES-256).
const KeySize = 32

// ErrDecrypt is returned when authenticated decryption fails: wrong key or
// tampered data.
var ErrDecrypt = errors.New("decryption failed: wrong key or corrupted data")

// RandomBytes returns n bytes from the operating system CSPRNG.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	// crypto/rand.Read never returns an error since Go 1.24; it panics
	// instead of returning weak randomness.
	_, _ = rand.Read(b)
	return b
}

// NewID returns a random 12-hex-digit identifier used for inventory objects.
func NewID() string { return hex.EncodeToString(RandomBytes(6)) }

// Seal encrypts plaintext with AES-256-GCM under key, binding aad. It
// returns a fresh random 96-bit nonce and the ciphertext with tag.
func Seal(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = RandomBytes(aead.NonceSize())
	return nonce, aead.Seal(nil, nonce, plaintext, aad), nil
}

// Open decrypts and authenticates data produced by Seal.
func Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, ErrDecrypt
	}
	pt, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key size %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Derive derives a KeySize subkey from a root key using HKDF-SHA256 with the
// given info label for domain separation.
func Derive(root []byte, info string) ([]byte, error) {
	return hkdf.Key(sha256.New, root, nil, info, KeySize)
}

// Argon2Params are Argon2id cost parameters. They are stored alongside each
// password keyslot so they can be raised later without breaking old slots.
type Argon2Params struct {
	Time      uint32 `json:"t"`
	MemoryKiB uint32 `json:"m"`
	Threads   uint8  `json:"p"`
}

// DefaultArgon2 follows the RFC 9106 second recommended option
// (t=3, m=64 MiB, p=4).
var DefaultArgon2 = Argon2Params{Time: 3, MemoryKiB: 64 * 1024, Threads: 4}

// Validate rejects parameters that are too weak or absurdly expensive, so a
// tampered keyslot file cannot downgrade or DoS the KDF.
func (p Argon2Params) Validate() error {
	if p.Time < 1 || p.Time > 64 || p.MemoryKiB < 8*1024 || p.MemoryKiB > 4*1024*1024 || p.Threads < 1 {
		return fmt.Errorf("argon2 parameters out of range: %+v", p)
	}
	return nil
}

// PasswordKey derives a key-encryption key from a password.
func PasswordKey(password, salt []byte, p Argon2Params) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if len(salt) < 16 {
		return nil, errors.New("salt too short")
	}
	return argon2.IDKey(password, salt, p.Time, p.MemoryKiB, p.Threads, KeySize), nil
}

// Zero overwrites b. Go gives no guarantee that copies were not made, so
// this is best-effort hygiene rather than a security boundary.
func Zero(b []byte) { clear(b) }

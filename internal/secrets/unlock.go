package secrets

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// Environment variables for non-interactive unlocking (CI, containers).
const (
	EnvPassword     = "SSLKNIFE_PASSWORD"
	EnvPasswordFile = "SSLKNIFE_PASSWORD_FILE"
)

// ErrLocked means no unlock method was available.
var ErrLocked = errors.New("vault is locked: set " + EnvPassword + " or " + EnvPasswordFile + ", or run in a terminal")

// Unlocker tries the configured unlock methods in order: environment,
// keychain, interactive prompt.
type Unlocker struct {
	Getenv  func(string) string
	Keyring Keyring                // nil disables keychain unlocking
	Prompt  func() ([]byte, error) // nil disables prompting
}

// Method names reported by Unlock.
const (
	MethodEnv     = "environment"
	MethodKeyring = "keychain"
	MethodPrompt  = "password"
)

// EnvPasswordValue returns the password from the environment, if any. A
// password file has one trailing newline trimmed.
func EnvPasswordValue(getenv func(string) string) ([]byte, bool, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	if p := getenv(EnvPassword); p != "" {
		return []byte(p), true, nil
	}
	if f := getenv(EnvPasswordFile); f != "" {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, false, fmt.Errorf("%s: %w", EnvPasswordFile, err)
		}
		return []byte(strings.TrimRight(string(data), "\r\n")), true, nil
	}
	return nil, false, nil
}

// Unlock returns the root key and the method that produced it.
func (u Unlocker) Unlock(kf *KeyFile) ([]byte, string, error) {
	pw, ok, err := EnvPasswordValue(u.Getenv)
	if err != nil {
		return nil, "", err
	}
	if ok {
		root, err := kf.UnlockPassword(pw)
		clear(pw)
		return root, MethodEnv, err
	}
	var keyringErr error
	if u.Keyring != nil && kf.HasSlot(SlotKeyring) {
		root, err := kf.UnlockKeyring(u.Keyring)
		if err == nil {
			return root, MethodKeyring, nil
		}
		keyringErr = err
	}
	if u.Prompt != nil && kf.HasSlot(SlotPassword) {
		for attempt := 0; attempt < 3; attempt++ {
			pw, err := u.Prompt()
			if err != nil {
				if keyringErr != nil {
					return nil, "", fmt.Errorf("%w (keychain: %w)", ErrLocked, keyringErr)
				}
				return nil, "", ErrLocked
			}
			root, err := kf.UnlockPassword(pw)
			clear(pw)
			if err == nil {
				return root, MethodPrompt, nil
			}
			if !errors.Is(err, ErrBadPassword) {
				return nil, "", err
			}
		}
		return nil, "", ErrBadPassword
	}
	if keyringErr != nil {
		return nil, "", fmt.Errorf("%w (keychain: %w)", ErrLocked, keyringErr)
	}
	return nil, "", ErrLocked
}

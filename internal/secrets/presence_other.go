//go:build !darwin

package secrets

// PresenceAvailable reports whether ConfirmPresence can prompt; only macOS
// supports it.
func PresenceAvailable() error { return ErrPresenceUnavailable }

// ConfirmPresence is unavailable outside macOS.
func ConfirmPresence(string) error { return ErrPresenceUnavailable }

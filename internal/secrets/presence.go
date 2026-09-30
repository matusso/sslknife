package secrets

import "errors"

// ErrPresenceUnavailable means this system cannot confirm user presence
// (Touch ID, Apple Watch) for keychain slots that require it.
var ErrPresenceUnavailable = errors.New("Touch ID is only available on macOS")

// ErrPresenceDenied means the user cancelled or failed the confirmation.
var ErrPresenceDenied = errors.New("Touch ID confirmation failed")

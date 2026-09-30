package secrets

import "errors"

// ErrPresenceUnavailable means this system cannot confirm user presence
// (Touch ID, Apple Watch) for keychain slots that require it.
var ErrPresenceUnavailable = errors.New("presence confirmation with Touch ID requires macOS")

// ErrPresenceDenied means the user cancelled or failed the confirmation.
var ErrPresenceDenied = errors.New("presence confirmation with Touch ID failed")

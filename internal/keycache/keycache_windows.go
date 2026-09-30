// Package keycache keeps an unlocked vault root key in a short-lived
// background process. It is not available on Windows.
package keycache

import (
	"errors"
	"io"
	"time"
)

// ErrNotCached means no cache process holds the key for this vault.
var ErrNotCached = errors.New("vault is not cached")

// Supported reports whether this platform has an unlock cache.
const Supported = false

var errUnsupported = errors.New("the unlock cache is not supported on Windows")

func Get(string) ([]byte, error)           { return nil, ErrNotCached }
func Status(string) (time.Time, error)     { return time.Time{}, ErrNotCached }
func Lock(string) error                    { return ErrNotCached }
func RunDaemon(io.Reader, io.Writer) error { return errUnsupported }

func Start(string, []string, string, []byte, time.Duration) error { return errUnsupported }

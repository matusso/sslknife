// Package logging configures structured logging with secret redaction.
package logging

import (
	"context"
	"io"
	"log/slog"
	"strings"
)

// LevelTrace is more verbose than debug.
const LevelTrace = slog.Level(-8)

// ParseLevel maps error|warn|info|debug|trace to a slog level.
func ParseLevel(s string) (slog.Level, bool) {
	switch strings.ToLower(s) {
	case "error":
		return slog.LevelError, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "info":
		return slog.LevelInfo, true
	case "debug":
		return slog.LevelDebug, true
	case "trace":
		return LevelTrace, true
	}
	return 0, false
}

// sensitive attribute keys whose values are always redacted.
var sensitive = []string{"password", "passphrase", "secret", "private", "token", "key_material", "ciphertext", "pem"}

const redacted = "[REDACTED]"

// IsSensitiveKey reports whether an attribute key names secret data.
func IsSensitiveKey(k string) bool {
	k = strings.ToLower(k)
	for _, s := range sensitive {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

// Secret wraps a value so that it is never logged.
type Secret string

// LogValue implements slog.LogValuer.
func (Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// String prevents accidental formatting of the secret with %s/%v.
func (Secret) String() string { return redacted }

func redact(_ []string, a slog.Attr) slog.Attr {
	if IsSensitiveKey(a.Key) {
		return slog.String(a.Key, redacted)
	}
	if a.Value.Kind() == slog.KindString && strings.Contains(a.Value.String(), "-----BEGIN") {
		return slog.String(a.Key, redacted)
	}
	if a.Value.Kind() == slog.KindAny {
		if _, ok := a.Value.Any().([]byte); ok {
			return slog.String(a.Key, "[bytes]")
		}
	}
	return a
}

// New returns a logger writing text records to w at level.
func New(w io.Writer, level slog.Level) *slog.Logger {
	h := slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.LevelKey && a.Value.Any() == LevelTrace {
				return slog.String(slog.LevelKey, "TRACE")
			}
			return redact(groups, a)
		},
	})
	return slog.New(h)
}

// Discard returns a logger that drops everything.
func Discard() *slog.Logger { return slog.New(discard{}) }

type discard struct{}

func (discard) Enabled(context.Context, slog.Level) bool  { return false }
func (discard) Handle(context.Context, slog.Record) error { return nil }
func (d discard) WithAttrs([]slog.Attr) slog.Handler      { return d }
func (d discard) WithGroup(string) slog.Handler           { return d }

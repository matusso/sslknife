package output

import (
	"regexp"
	"unicode/utf8"
)

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiBlue   = "\x1b[34m"
	ansiCyan   = "\x1b[36m"
)

// Style applies ANSI styling when enabled.
type Style struct{ Enabled bool }

func (s Style) wrap(code, v string) string {
	if !s.Enabled || v == "" {
		return v
	}
	return code + v + ansiReset
}

func (s Style) Bold(v string) string   { return s.wrap(ansiBold, v) }
func (s Style) Dim(v string) string    { return s.wrap(ansiDim, v) }
func (s Style) Red(v string) string    { return s.wrap(ansiRed, v) }
func (s Style) Green(v string) string  { return s.wrap(ansiGreen, v) }
func (s Style) Yellow(v string) string { return s.wrap(ansiYellow, v) }
func (s Style) Blue(v string) string   { return s.wrap(ansiBlue, v) }
func (s Style) Cyan(v string) string   { return s.wrap(ansiCyan, v) }

// Level colours a severity or status word consistently across commands.
func (s Style) Level(level string) string {
	switch level {
	case "OK", "PASS", "VALID", "SUPPORTED", "ENABLED", "MATCH", "MODERN", "secure", "known":
		return s.Green(level)
	case "WARNING", "WARN", "warning", "EXPIRING", "DEPRECATED", "WEAK", "notice", "new", "changed":
		return s.Yellow(level)
	case "ERROR", "FAIL", "EXPIRED", "CRITICAL", "INSECURE", "MISMATCH", "error", "critical", "high", "unexpected", "INVALID":
		return s.Red(level)
	case "CA", "info", "INFO":
		return s.Cyan(level)
	}
	return level
}

var ansiRE = regexp.MustCompile("\x1b\\[[0-9;]*m")

// VisibleWidth returns the printed width of s, ignoring ANSI sequences.
func VisibleWidth(s string) int {
	return utf8.RuneCountInString(ansiRE.ReplaceAllString(s, ""))
}

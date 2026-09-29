// Package exitcode maps errors to the documented, deterministic process exit
// codes (see docs/DESIGN.md §7).
package exitcode

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
)

// Exit codes. These values are part of the public interface.
const (
	OK          = 0
	Error       = 1
	Usage       = 2
	NotFound    = 3
	Auth        = 4
	CheckFailed = 5
	Network     = 6
	Unsupported = 7
	Interrupted = 130
)

// codedError carries an explicit exit code.
type codedError struct {
	code int
	err  error
}

func (e *codedError) Error() string { return e.err.Error() }
func (e *codedError) Unwrap() error { return e.err }

// With wraps err so that Code(err) returns code. A nil err stays nil.
func With(code int, err error) error {
	if err == nil {
		return nil
	}
	return &codedError{code: code, err: err}
}

// New formats a message and attaches code.
func New(code int, format string, args ...any) error {
	return &codedError{code: code, err: fmt.Errorf(format, args...)}
}

// Silent is returned by commands that already reported their result (for
// example a failed lint) and only need to set the exit status.
func Silent(code int) error {
	return &silentError{code: code}
}

type silentError struct{ code int }

func (e *silentError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// IsSilent reports whether err should not be printed.
func IsSilent(err error) bool {
	var s *silentError
	return errors.As(err, &s)
}

// Code returns the exit code for err.
func Code(err error) int {
	if err == nil {
		return OK
	}
	var s *silentError
	if errors.As(err, &s) {
		return s.code
	}
	var c *codedError
	if errors.As(err, &c) {
		return c.code
	}
	if errors.Is(err, context.Canceled) {
		return Interrupted
	}
	if errors.Is(err, fs.ErrNotExist) {
		return NotFound
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return Network
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return Network
	}
	return Error
}

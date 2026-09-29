package cmd

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/matusso/sslknife/internal/exitcode"
	"github.com/matusso/sslknife/internal/keys"
)

// maxInputSize bounds files read into memory; certificate material is tiny.
const maxInputSize = 32 << 20

// EnvKeyPassword supplies passwords for encrypted input keys and keystores.
const EnvKeyPassword = "SSLKNIFE_KEY_PASSWORD"

// readInput reads a file, or stdin for "-".
func (a *app) readInput(name string) ([]byte, error) {
	var r io.Reader
	if name == "-" {
		r = a.stdin
	} else {
		f, err := os.Open(name)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return nil, err
		}
		if st.IsDir() {
			return nil, exitcode.New(exitcode.Usage, "%s is a directory", name)
		}
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, maxInputSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxInputSize {
		return nil, exitcode.New(exitcode.Usage, "%s is larger than %d MiB", displayName(name), maxInputSize>>20)
	}
	return data, nil
}

func displayName(name string) string {
	if name == "-" {
		return "<stdin>"
	}
	return name
}

// writeNewFile writes data to path, refusing to overwrite unless force is
// set. Secret files use mode 0600.
func writeNewFile(path string, data []byte, perm fs.FileMode, force bool) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, perm)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return exitcode.New(exitcode.Usage, "%s already exists (use --force to overwrite)", path)
		}
		return err
	}
	// Tighten permissions on existing files being overwritten.
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// keyPassword returns a PasswordFunc for encrypted inputs: the password
// file flag, then $SSLKNIFE_KEY_PASSWORD, then a TTY prompt.
func (a *app) keyPassword(passwordFile, what string) keys.PasswordFunc {
	return func() ([]byte, error) {
		if passwordFile != "" {
			data, err := os.ReadFile(passwordFile)
			if err != nil {
				return nil, err
			}
			return []byte(strings.TrimRight(string(data), "\r\n")), nil
		}
		if p := os.Getenv(EnvKeyPassword); p != "" {
			return []byte(p), nil
		}
		if !a.prompt.Interactive() {
			return nil, exitcode.New(exitcode.Auth, "%s is encrypted: use --password-file or %s", what, EnvKeyPassword)
		}
		return a.prompt.Password(fmt.Sprintf("Password for %s", what))
	}
}

// newSecretPassword asks for a password to protect exported key material.
func (a *app) newSecretPassword(passwordFile string) ([]byte, error) {
	if passwordFile != "" || os.Getenv(EnvKeyPassword) != "" {
		return a.keyPassword(passwordFile, "")()
	}
	if !a.prompt.Interactive() {
		return nil, exitcode.New(exitcode.Usage, "no terminal: use --password-file or %s to set the export password", EnvKeyPassword)
	}
	return a.prompt.NewPassword("Password to encrypt the key", 8)
}

// confirm asks a yes/no question unless yes is set. Without a terminal it
// fails and tells the user to pass --yes.
func (a *app) confirm(question string, yes bool) error {
	if yes {
		return nil
	}
	if !a.prompt.Interactive() {
		return exitcode.New(exitcode.Usage, "confirmation required but no terminal is attached; re-run with --yes")
	}
	ok, err := a.prompt.Confirm(question, true)
	if err != nil {
		return err
	}
	if !ok {
		return exitcode.New(exitcode.Error, "aborted")
	}
	return nil
}

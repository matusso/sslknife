// Package prompt implements the small set of interactive TTY prompts
// SSLKnife needs: confirmations, passwords, free text and choices.
package prompt

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"
)

// ErrNotInteractive is returned when a prompt is needed but no terminal is
// attached. Callers should tell the user which flag or env var to use.
var ErrNotInteractive = errors.New("input required but no terminal is attached")

// Prompter reads answers from in and writes questions to out.
type Prompter struct {
	in          *bufio.Reader
	fd          int // terminal fd for password reads, -1 if none
	out         io.Writer
	interactive bool
}

// New creates a prompter. Prompts are only allowed when in is a terminal.
func New(in io.Reader, out io.Writer) *Prompter {
	p := &Prompter{in: bufio.NewReader(in), out: out, fd: -1}
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		p.fd = int(f.Fd())
		p.interactive = true
	}
	return p
}

// NewScripted creates a prompter that reads answers from in regardless of
// whether it is a terminal. Used by tests.
func NewScripted(in io.Reader, out io.Writer) *Prompter {
	return &Prompter{in: bufio.NewReader(in), out: out, fd: -1, interactive: true}
}

// Interactive reports whether prompting is possible.
func (p *Prompter) Interactive() bool { return p.interactive }

func (p *Prompter) readLine() (string, error) {
	line, err := p.in.ReadString('\n')
	if err != nil && (err != io.EOF || line == "") {
		if err == io.EOF {
			return "", io.ErrUnexpectedEOF
		}
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// Confirm asks a yes/no question. An empty answer returns def.
func (p *Prompter) Confirm(question string, def bool) (bool, error) {
	if !p.interactive {
		return false, ErrNotInteractive
	}
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}
	for {
		fmt.Fprintf(p.out, "%s %s ", question, hint)
		ans, err := p.readLine()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(ans)) {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		fmt.Fprintln(p.out, "Please answer y or n.")
	}
}

// Line asks for a line of text. An empty answer returns def.
func (p *Prompter) Line(question, def string) (string, error) {
	if !p.interactive {
		return "", ErrNotInteractive
	}
	if def != "" {
		fmt.Fprintf(p.out, "%s [%s]: ", question, def)
	} else {
		fmt.Fprintf(p.out, "%s: ", question)
	}
	ans, err := p.readLine()
	if err != nil {
		return "", err
	}
	if ans = strings.TrimSpace(ans); ans == "" {
		return def, nil
	}
	return ans, nil
}

// Lines reads values until an empty line.
func (p *Prompter) Lines(question string) ([]string, error) {
	if !p.interactive {
		return nil, ErrNotInteractive
	}
	fmt.Fprintf(p.out, "%s (one per line, empty line to finish):\n", question)
	var out []string
	for {
		fmt.Fprint(p.out, "> ")
		ans, err := p.readLine()
		if err != nil {
			return nil, err
		}
		if ans = strings.TrimSpace(ans); ans == "" {
			return out, nil
		}
		out = append(out, ans)
	}
}

// Choose presents numbered options and returns the selected index.
func (p *Prompter) Choose(question string, options []string, def int) (int, error) {
	if !p.interactive {
		return 0, ErrNotInteractive
	}
	fmt.Fprintf(p.out, "%s\n", question)
	for i, o := range options {
		marker := " "
		if i == def {
			marker = ">"
		}
		fmt.Fprintf(p.out, " %s %d) %s\n", marker, i+1, o)
	}
	for {
		fmt.Fprintf(p.out, "Choice [%d]: ", def+1)
		ans, err := p.readLine()
		if err != nil {
			return 0, err
		}
		ans = strings.TrimSpace(ans)
		if ans == "" {
			return def, nil
		}
		n, err := strconv.Atoi(ans)
		if err == nil && n >= 1 && n <= len(options) {
			return n - 1, nil
		}
		for i, o := range options {
			if strings.EqualFold(o, ans) {
				return i, nil
			}
		}
		fmt.Fprintf(p.out, "Enter a number between 1 and %d.\n", len(options))
	}
}

// Password reads a secret without echo. The caller should zero the result.
func (p *Prompter) Password(question string) ([]byte, error) {
	if !p.interactive {
		return nil, ErrNotInteractive
	}
	fmt.Fprintf(p.out, "%s: ", question)
	if p.fd >= 0 {
		b, err := term.ReadPassword(p.fd)
		fmt.Fprintln(p.out)
		return b, err
	}
	line, err := p.readLine()
	return []byte(line), err
}

// NewPassword asks for a password twice and checks that both match.
func (p *Prompter) NewPassword(question string, minLen int) ([]byte, error) {
	for attempt := 0; attempt < 3; attempt++ {
		a, err := p.Password(question)
		if err != nil {
			return nil, err
		}
		if len(a) < minLen {
			fmt.Fprintf(p.out, "Password must be at least %d characters.\n", minLen)
			continue
		}
		b, err := p.Password("Repeat password")
		if err != nil {
			return nil, err
		}
		if string(a) == string(b) {
			clear(b)
			return a, nil
		}
		clear(a)
		clear(b)
		fmt.Fprintln(p.out, "Passwords do not match.")
	}
	return nil, errors.New("too many attempts")
}

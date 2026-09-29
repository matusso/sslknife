// Package output renders command results as human-readable text, JSON or
// YAML. Commands pass a view model (with json tags) plus a text renderer;
// machine formats are derived from the view model only, so the JSON schema
// is what the view model declares and never an internal Go structure.
package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

// Format selects the output encoding.
type Format string

const (
	Text Format = "text"
	JSON Format = "json"
	YAML Format = "yaml"
	Raw  Format = "raw"
)

// ParseFormat validates a --format value. "table" is an alias of text.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(s) {
	case "", "text", "table":
		return Text, nil
	case "json":
		return JSON, nil
	case "yaml", "yml":
		return YAML, nil
	case "raw":
		return Raw, nil
	}
	return "", fmt.Errorf("unknown output format %q (use text, json, yaml or raw)", s)
}

// Printer writes results to Out and diagnostics to Err.
type Printer struct {
	Out    io.Writer
	Err    io.Writer
	Format Format
	Style  Style
	Quiet  bool
}

// New creates a printer. Colour is enabled only for terminals, and never
// when NO_COLOR is set or noColor is true.
func New(out, errw io.Writer, format Format, noColor, quiet bool) *Printer {
	color := !noColor && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" && isTerminal(out)
	return &Printer{Out: out, Err: errw, Format: format, Style: Style{Enabled: color}, Quiet: quiet}
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// Machine reports whether output is JSON or YAML.
func (p *Printer) Machine() bool { return p.Format == JSON || p.Format == YAML }

// Emit writes v in the selected machine format, or calls text for text/raw
// output. text may be nil when a command has no human rendering.
func (p *Printer) Emit(v any, text func(w io.Writer) error) error {
	switch p.Format {
	case JSON:
		return WriteJSON(p.Out, v)
	case YAML:
		return WriteYAML(p.Out, v)
	}
	if text == nil {
		return WriteJSON(p.Out, v)
	}
	if p.Quiet {
		return nil
	}
	return text(p.Out)
}

// Infof prints a progress or status message to stderr unless quiet.
func (p *Printer) Infof(format string, args ...any) {
	if p.Quiet {
		return
	}
	fmt.Fprintf(p.Err, format+"\n", args...)
}

// Warnf prints a warning to stderr; warnings are shown even in quiet mode
// because they usually concern security.
func (p *Printer) Warnf(format string, args ...any) {
	fmt.Fprintf(p.Err, "%s %s\n", p.Style.Yellow("warning:"), fmt.Sprintf(format, args...))
}

// WriteJSON writes indented JSON with a trailing newline.
func WriteJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// WriteYAML writes v as YAML using its JSON field names and order. The value
// is first encoded as JSON, then decoded into a yaml.Node (which keeps key
// order) and re-encoded in block style.
func WriteYAML(w io.Writer, v any) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		return err
	}
	var node yaml.Node
	if err := yaml.Unmarshal(buf.Bytes(), &node); err != nil {
		return err
	}
	resetStyle(&node)
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(&node); err != nil {
		return err
	}
	return enc.Close()
}

func resetStyle(n *yaml.Node) {
	n.Style = 0
	for _, c := range n.Content {
		resetStyle(c)
	}
}

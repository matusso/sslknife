// Package protocol reaches the point where a TLS ClientHello can be sent:
// directly for TLS-wrapped services, or after a plaintext STARTTLS-style
// negotiation (SMTP, IMAP, POP3, FTP, LDAP, XMPP, PostgreSQL, MySQL).
// New protocols are added by implementing Adapter and registering it.
package protocol

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// Adapter performs a protocol-specific TLS upgrade on a fresh connection.
type Adapter interface {
	// Name is the --protocol value, e.g. "smtp".
	Name() string
	// STARTTLS reports whether a plaintext negotiation precedes TLS.
	STARTTLS() bool
	// Upgrade negotiates TLS on s. On return the next bytes written must be
	// the ClientHello. Direct-TLS adapters do nothing.
	Upgrade(ctx context.Context, s *Session, host string) error
}

// ErrNotSupported means the server does not offer TLS for this protocol.
var ErrNotSupported = errors.New("server does not support TLS upgrade")

// Session wraps a connection during negotiation and keeps a transcript.
type Session struct {
	Conn net.Conn
	r    *bufio.Reader
	Log  []string
}

// NewSession wraps conn.
func NewSession(conn net.Conn) *Session {
	return &Session{Conn: conn, r: bufio.NewReaderSize(conn, 4096)}
}

const maxLogLine = 160

func (s *Session) log(dir, line string) {
	if len(s.Log) >= 64 {
		return
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) > maxLogLine {
		line = line[:maxLogLine] + "…"
	}
	s.Log = append(s.Log, dir+" "+line)
}

// Send writes a command line.
func (s *Session) Send(line string) error {
	s.log("C:", line)
	_, err := s.Conn.Write([]byte(line + "\r\n"))
	return err
}

// Write writes raw bytes (binary protocols).
func (s *Session) Write(b []byte, desc string) error {
	s.log("C:", desc)
	_, err := s.Conn.Write(b)
	return err
}

// ReadLine reads one CRLF-terminated line (max 4 KiB).
func (s *Session) ReadLine() (string, error) {
	var b []byte
	for {
		chunk, isPrefix, err := s.r.ReadLine()
		if err != nil {
			return "", err
		}
		b = append(b, chunk...)
		if len(b) > 4096 {
			return "", errors.New("line too long")
		}
		if !isPrefix {
			break
		}
	}
	line := string(b)
	s.log("S:", line)
	return line, nil
}

// ReadFull reads exactly n bytes.
func (s *Session) ReadFull(n int) ([]byte, error) {
	buf := make([]byte, n)
	for read := 0; read < n; {
		m, err := s.r.Read(buf[read:])
		if err != nil {
			return nil, err
		}
		read += m
	}
	return buf, nil
}

// ReadUntil reads until marker appears (max bytes).
func (s *Session) ReadUntil(markers []string, max int) (string, error) {
	var b strings.Builder
	for b.Len() < max {
		c, err := s.r.ReadByte()
		if err != nil {
			return b.String(), err
		}
		b.WriteByte(c)
		for _, m := range markers {
			if strings.HasSuffix(b.String(), m) {
				s.log("S:", b.String())
				return b.String(), nil
			}
		}
	}
	return b.String(), errors.New("response too long")
}

// Ready verifies that no plaintext bytes are pending before TLS starts.
func (s *Session) Ready() error {
	if s.r.Buffered() > 0 {
		return errors.New("server sent unexpected data before TLS")
	}
	return nil
}

var registry = map[string]Adapter{}
var aliases = map[string]string{}

func register(a Adapter, alias ...string) {
	registry[a.Name()] = a
	for _, x := range alias {
		aliases[x] = a.Name()
	}
}

// Lookup returns the adapter for a --protocol value.
func Lookup(name string) (Adapter, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if a, ok := aliases[n]; ok {
		n = a
	}
	if a, ok := registry[n]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("unknown protocol %q (supported: %s)", name, strings.Join(Names(), ", "))
}

// Names lists registered protocol names.
func Names() []string {
	var out []string
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// portMap gives the conventional protocol for well-known ports.
var portMap = map[int]string{
	443: "https", 8443: "https", 4443: "https", 9443: "https", 10443: "https",
	25: "smtp", 587: "smtp", 2525: "smtp", 465: "smtps",
	143: "imap", 993: "imaps", 110: "pop3", 995: "pop3s",
	389: "ldap", 636: "ldaps", 3268: "ldap", 3269: "ldaps",
	21: "ftp", 990: "ftps",
	5222: "xmpp", 5269: "xmpp-server", 5223: "xmpps",
	5432: "postgres", 3306: "mysql",
	8883: "mqtts", 6379: "redis", 6380: "redis",
	853: "dot", 5061: "sips", 5986: "https", 2376: "https", 6443: "https", 9093: "tls",
}

// ByPort returns the conventional protocol for port, if any.
func ByPort(port int) (string, bool) {
	p, ok := portMap[port]
	return p, ok
}

// DefaultPort returns the usual port for a protocol (443 for unknown).
func DefaultPort(name string) int {
	best := 0
	for port, p := range portMap {
		if p == name && (best == 0 || port < best) {
			best = port
		}
	}
	if best == 0 {
		return 443
	}
	return best
}

// Detection records how the protocol was chosen.
type Detection struct {
	Protocol string `json:"protocol"`
	Method   string `json:"method"`      // direct or starttls
	Via      string `json:"detected_by"` // flag, port, banner, default
	Banner   string `json:"banner,omitempty"`
}

// SniffBanner reads what a server sends without prompting. Servers that
// speak first (SMTP, FTP, IMAP, POP3, MySQL) identify themselves this way;
// silence suggests a TLS-first service.
func SniffBanner(ctx context.Context, conn net.Conn, wait time.Duration) (string, []byte) {
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	_ = conn.SetReadDeadline(time.Time{})
	buf = buf[:n]
	if n == 0 {
		return "", nil
	}
	s := string(buf)
	switch {
	case strings.HasPrefix(s, "220"):
		if strings.Contains(strings.ToUpper(s), "FTP") {
			return "ftp", buf
		}
		return "smtp", buf
	case strings.HasPrefix(s, "* OK"):
		return "imap", buf
	case strings.HasPrefix(s, "+OK"):
		return "pop3", buf
	case n > 5 && buf[3] == 0 && buf[4] == 10:
		return "mysql", buf
	}
	return "unknown", buf
}

// Printable renders a banner for display.
func Printable(b []byte) string {
	s := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' {
			return ' '
		}
		if r < 32 || r > 126 {
			return '.'
		}
		return r
	}, string(b))
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return s
}

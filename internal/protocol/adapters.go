package protocol

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
)

type direct struct{ name string }

func (d direct) Name() string                                  { return d.name }
func (direct) STARTTLS() bool                                  { return false }
func (direct) Upgrade(context.Context, *Session, string) error { return nil }

func init() {
	register(direct{"tls"}, "direct", "generic", "raw")
	register(direct{"https"}, "http", "h2")
	for _, n := range []string{"smtps", "imaps", "pop3s", "ldaps", "ftps", "xmpps", "mqtts", "redis", "dot", "sips"} {
		alias := []string{}
		switch n {
		case "mqtts":
			alias = []string{"mqtt"}
		case "redis":
			alias = []string{"rediss"}
		}
		register(direct{n}, alias...)
	}
	register(smtp{})
	register(imap{})
	register(pop3{}, "pop")
	register(ftp{})
	register(ldap{})
	register(xmpp{name: "xmpp", ns: "jabber:client"}, "jabber")
	register(xmpp{name: "xmpp-server", ns: "jabber:server"})
	register(postgres{}, "postgresql", "pg")
	register(mysql{}, "mariadb")
}

// readSMTPReply reads a (possibly multi-line) SMTP/FTP reply.
func readSMTPReply(s *Session) (code string, lines []string, err error) {
	for {
		line, err := s.ReadLine()
		if err != nil {
			return "", lines, err
		}
		if len(line) < 3 {
			return "", lines, fmt.Errorf("malformed reply %q", line)
		}
		lines = append(lines, line)
		if len(line) == 3 || line[3] == ' ' {
			return line[:3], lines, nil
		}
		if len(lines) > 100 {
			return "", lines, fmt.Errorf("reply too long")
		}
	}
}

type smtp struct{}

func (smtp) Name() string   { return "smtp" }
func (smtp) STARTTLS() bool { return true }
func (smtp) Upgrade(_ context.Context, s *Session, host string) error {
	code, _, err := readSMTPReply(s)
	if err != nil {
		return err
	}
	if code != "220" {
		return fmt.Errorf("SMTP greeting %s", code)
	}
	if err := s.Send("EHLO sslknife.invalid"); err != nil {
		return err
	}
	code, lines, err := readSMTPReply(s)
	if err != nil {
		return err
	}
	if code != "250" {
		return fmt.Errorf("SMTP EHLO rejected: %s", code)
	}
	found := false
	for _, l := range lines {
		if len(l) > 4 && strings.EqualFold(strings.TrimSpace(l[4:]), "STARTTLS") {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("%w: STARTTLS not advertised in EHLO", ErrNotSupported)
	}
	if err := s.Send("STARTTLS"); err != nil {
		return err
	}
	if code, _, err = readSMTPReply(s); err != nil {
		return err
	}
	if code != "220" {
		return fmt.Errorf("%w: STARTTLS answered %s", ErrNotSupported, code)
	}
	return s.Ready()
}

type imap struct{}

func (imap) Name() string   { return "imap" }
func (imap) STARTTLS() bool { return true }
func (imap) Upgrade(_ context.Context, s *Session, _ string) error {
	greet, err := s.ReadLine()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(greet, "* OK") && !strings.HasPrefix(greet, "* PREAUTH") {
		return fmt.Errorf("unexpected IMAP greeting %q", Printable([]byte(greet)))
	}
	if err := s.Send("a1 STARTTLS"); err != nil {
		return err
	}
	for i := 0; i < 50; i++ {
		line, err := s.ReadLine()
		if err != nil {
			return err
		}
		if strings.HasPrefix(line, "a1 ") {
			if strings.HasPrefix(strings.ToUpper(line), "A1 OK") {
				return s.Ready()
			}
			return fmt.Errorf("%w: %s", ErrNotSupported, Printable([]byte(line)))
		}
	}
	return fmt.Errorf("no tagged IMAP response")
}

type pop3 struct{}

func (pop3) Name() string   { return "pop3" }
func (pop3) STARTTLS() bool { return true }
func (pop3) Upgrade(_ context.Context, s *Session, _ string) error {
	greet, err := s.ReadLine()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(greet, "+OK") {
		return fmt.Errorf("unexpected POP3 greeting %q", Printable([]byte(greet)))
	}
	if err := s.Send("STLS"); err != nil {
		return err
	}
	line, err := s.ReadLine()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "+OK") {
		return fmt.Errorf("%w: %s", ErrNotSupported, Printable([]byte(line)))
	}
	return s.Ready()
}

type ftp struct{}

func (ftp) Name() string   { return "ftp" }
func (ftp) STARTTLS() bool { return true }
func (ftp) Upgrade(_ context.Context, s *Session, _ string) error {
	code, _, err := readSMTPReply(s)
	if err != nil {
		return err
	}
	if code != "220" {
		return fmt.Errorf("FTP greeting %s", code)
	}
	if err := s.Send("AUTH TLS"); err != nil {
		return err
	}
	if code, _, err = readSMTPReply(s); err != nil {
		return err
	}
	if code != "234" {
		return fmt.Errorf("%w: AUTH TLS answered %s", ErrNotSupported, code)
	}
	return s.Ready()
}

type ldap struct{}

func (ldap) Name() string   { return "ldap" }
func (ldap) STARTTLS() bool { return true }

// ldapStartTLS is an LDAPMessage{messageID 1, ExtendedRequest{requestName
// "1.3.6.1.4.1.1466.20037"}} (RFC 4511 §4.14).
var ldapStartTLS = append([]byte{0x30, 0x1d, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80, 0x16}, []byte("1.3.6.1.4.1.1466.20037")...)

func (ldap) Upgrade(_ context.Context, s *Session, _ string) error {
	if err := s.Write(ldapStartTLS, "ExtendedRequest StartTLS (1.3.6.1.4.1.1466.20037)"); err != nil {
		return err
	}
	hdr, err := s.ReadFull(2)
	if err != nil {
		return err
	}
	if hdr[0] != 0x30 {
		return fmt.Errorf("not an LDAP response")
	}
	n := int(hdr[1])
	if n&0x80 != 0 {
		lenBytes := n & 0x7f
		if lenBytes == 0 || lenBytes > 3 {
			return fmt.Errorf("malformed LDAP response length")
		}
		lb, err := s.ReadFull(lenBytes)
		if err != nil {
			return err
		}
		n = 0
		for _, b := range lb {
			n = n<<8 | int(b)
		}
	}
	if n > 16384 {
		return fmt.Errorf("LDAP response too large")
	}
	body, err := s.ReadFull(n)
	if err != nil {
		return err
	}
	// messageID INTEGER, then [APPLICATION 24] ExtendedResponse whose first
	// element is resultCode ENUMERATED.
	r := body
	if len(r) < 3 || r[0] != 0x02 || len(r) < 2+int(r[1]) {
		return fmt.Errorf("malformed LDAP response")
	}
	r = r[2+int(r[1]):]
	if len(r) < 2 || r[0] != 0x78 {
		return fmt.Errorf("unexpected LDAP response type")
	}
	r = berContent(r)
	if len(r) < 3 || r[0] != 0x0a {
		return fmt.Errorf("malformed LDAP ExtendedResponse")
	}
	result := int(r[2])
	s.log("S:", fmt.Sprintf("ExtendedResponse resultCode=%d", result))
	if result != 0 {
		return fmt.Errorf("%w: StartTLS resultCode %d", ErrNotSupported, result)
	}
	return s.Ready()
}

// berContent skips a BER tag and length, returning the value bytes.
func berContent(r []byte) []byte {
	if len(r) < 2 {
		return nil
	}
	if r[1]&0x80 == 0 {
		return r[2:]
	}
	n := int(r[1] & 0x7f)
	if len(r) < 2+n {
		return nil
	}
	return r[2+n:]
}

type xmpp struct{ name, ns string }

func (x xmpp) Name() string { return x.name }
func (xmpp) STARTTLS() bool { return true }
func (x xmpp) Upgrade(_ context.Context, s *Session, host string) error {
	open := fmt.Sprintf("<?xml version='1.0'?><stream:stream to='%s' xmlns='%s' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>",
		xmlEscape(host), x.ns)
	if err := s.Write([]byte(open), open); err != nil {
		return err
	}
	features, err := s.ReadUntil([]string{"</stream:features>", "</stream:stream>"}, 65536)
	if err != nil {
		return err
	}
	if !strings.Contains(features, "urn:ietf:params:xml:ns:xmpp-tls") {
		return fmt.Errorf("%w: starttls not offered in stream features", ErrNotSupported)
	}
	req := "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
	if err := s.Write([]byte(req), req); err != nil {
		return err
	}
	resp, err := s.ReadUntil([]string{"/>", "</failure>"}, 4096)
	if err != nil {
		return err
	}
	if !strings.Contains(resp, "<proceed") {
		return fmt.Errorf("%w: %s", ErrNotSupported, Printable([]byte(resp)))
	}
	return s.Ready()
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "'", "&apos;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

type postgres struct{}

func (postgres) Name() string   { return "postgres" }
func (postgres) STARTTLS() bool { return true }
func (postgres) Upgrade(_ context.Context, s *Session, _ string) error {
	// SSLRequest: int32 length 8, int32 code 80877103.
	if err := s.Write([]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}, "SSLRequest"); err != nil {
		return err
	}
	b, err := s.ReadFull(1)
	if err != nil {
		return err
	}
	s.log("S:", fmt.Sprintf("%q", b[0]))
	switch b[0] {
	case 'S':
		return s.Ready()
	case 'N':
		return fmt.Errorf("%w: server answered N", ErrNotSupported)
	}
	return fmt.Errorf("unexpected PostgreSQL response 0x%02x", b[0])
}

type mysql struct{}

func (mysql) Name() string   { return "mysql" }
func (mysql) STARTTLS() bool { return true }

const (
	mysqlClientLongPassword = 0x00000001
	mysqlClientProtocol41   = 0x00000200
	mysqlClientSSL          = 0x00000800
	mysqlClientSecureConn   = 0x00008000
	mysqlClientPluginAuth   = 0x00080000
)

func (mysql) Upgrade(_ context.Context, s *Session, _ string) error {
	hdr, err := s.ReadFull(4)
	if err != nil {
		return err
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if n < 10 || n > 1024 {
		return fmt.Errorf("malformed MySQL handshake")
	}
	p, err := s.ReadFull(n)
	if err != nil {
		return err
	}
	if p[0] == 0xff {
		return fmt.Errorf("MySQL error packet: %s", Printable(p[3:]))
	}
	if p[0] != 10 {
		return fmt.Errorf("unsupported MySQL protocol version %d", p[0])
	}
	end := 1
	for end < len(p) && p[end] != 0 {
		end++
	}
	version := string(p[1:end])
	s.log("S:", "Handshake v10 server="+version)
	// NUL, connection id (4), auth data part 1 (8), filler (1), caps low (2)
	off := end + 1 + 4 + 8 + 1
	if off+2 > len(p) {
		return fmt.Errorf("truncated MySQL handshake")
	}
	caps := uint32(binary.LittleEndian.Uint16(p[off:]))
	if caps&mysqlClientSSL == 0 {
		return fmt.Errorf("%w: CLIENT_SSL capability not set", ErrNotSupported)
	}
	req := make([]byte, 4+32)
	req[0], req[3] = 32, 1 // length 32, sequence 1
	binary.LittleEndian.PutUint32(req[4:], mysqlClientSSL|mysqlClientProtocol41|mysqlClientSecureConn|mysqlClientLongPassword|mysqlClientPluginAuth)
	binary.LittleEndian.PutUint32(req[8:], 1<<24)
	req[12] = 0x21 // utf8_general_ci
	if err := s.Write(req, "SSLRequest"); err != nil {
		return err
	}
	return s.Ready()
}

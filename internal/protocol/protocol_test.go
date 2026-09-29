package protocol

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// pipe runs server on one end of an in-memory connection and returns a
// session for the other end.
func pipe(t *testing.T, server func(c net.Conn)) *Session {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	go func() {
		_ = b.SetDeadline(time.Now().Add(3 * time.Second))
		server(b)
	}()
	_ = a.SetDeadline(time.Now().Add(3 * time.Second))
	return NewSession(a)
}

func lineServer(greeting string, script map[string]string) func(net.Conn) {
	return func(c net.Conn) {
		r := bufio.NewReader(c)
		if greeting != "" {
			io.WriteString(c, greeting)
		}
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			for prefix, reply := range script {
				if strings.HasPrefix(line, prefix) {
					io.WriteString(c, reply)
				}
			}
		}
	}
}

func upgrade(t *testing.T, name string, s *Session) error {
	t.Helper()
	a, err := Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	return a.Upgrade(context.Background(), s, "example.com")
}

func TestLineProtocols(t *testing.T) {
	ok := map[string]*Session{
		"pop3": pipe(t, lineServer("+OK ready\r\n", map[string]string{"STLS": "+OK begin\r\n"})),
		"ftp":  pipe(t, lineServer("220-Welcome\r\n220 FTP ready\r\n", map[string]string{"AUTH TLS": "234 AUTH TLS ok\r\n"})),
		"imap": pipe(t, lineServer("* OK ready\r\n", map[string]string{"a1 STARTTLS": "* BYE? no\r\na1 OK go\r\n"})),
		"smtp": pipe(t, lineServer("220 mx ESMTP\r\n", map[string]string{"EHLO": "250-mx\r\n250 STARTTLS\r\n", "STARTTLS": "220 ok\r\n"})),
	}
	for name, s := range ok {
		if err := upgrade(t, name, s); err != nil {
			t.Errorf("%s: %v (%v)", name, err, s.Log)
		}
	}
	bad := map[string]*Session{
		"pop3": pipe(t, lineServer("+OK ready\r\n", map[string]string{"STLS": "-ERR no\r\n"})),
		"ftp":  pipe(t, lineServer("220 FTP\r\n", map[string]string{"AUTH TLS": "500 no\r\n"})),
		"imap": pipe(t, lineServer("* OK ready\r\n", map[string]string{"a1": "a1 BAD no\r\n"})),
	}
	for name, s := range bad {
		if err := upgrade(t, name, s); !errors.Is(err, ErrNotSupported) {
			t.Errorf("%s: expected ErrNotSupported, got %v", name, err)
		}
	}
}

func TestLDAP(t *testing.T) {
	for result, wantErr := range map[byte]bool{0: false, 2: true} {
		s := pipe(t, func(c net.Conn) {
			req := make([]byte, len(ldapStartTLS))
			io.ReadFull(c, req)
			// LDAPMessage{id 1, ExtendedResponse{resultCode, "", ""}}
			resp := []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, result, 0x04, 0x00, 0x04, 0x00}
			c.Write(resp)
		})
		err := upgrade(t, "ldap", s)
		if (err != nil) != wantErr {
			t.Errorf("result %d: %v", result, err)
		}
	}
}

func TestXMPP(t *testing.T) {
	s := pipe(t, func(c net.Conn) {
		buf := make([]byte, 4096)
		c.Read(buf)
		io.WriteString(c, "<?xml version='1.0'?><stream:stream from='example.com' id='1' version='1.0'><stream:features>"+
			"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>")
		c.Read(buf)
		io.WriteString(c, "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
	})
	if err := upgrade(t, "xmpp", s); err != nil {
		t.Fatal(err, s.Log)
	}
}

func TestMySQL(t *testing.T) {
	handshake := func(caps uint16) []byte {
		p := []byte{10}
		p = append(p, "8.0.36\x00"...)
		p = append(p, 1, 0, 0, 0)    // connection id
		p = append(p, "abcdefgh"...) // auth data 1
		p = append(p, 0)             // filler
		p = binary.LittleEndian.AppendUint16(p, caps)
		p = append(p, 0x21, 2, 0, 0xff, 0xff) // charset, status, caps high
		return append([]byte{byte(len(p)), 0, 0, 0}, p...)
	}
	for caps, wantErr := range map[uint16]bool{0xffff: false, 0xf7ff: true} {
		s := pipe(t, func(c net.Conn) {
			c.Write(handshake(caps))
			buf := make([]byte, 36)
			io.ReadFull(c, buf)
		})
		err := upgrade(t, "mysql", s)
		if (err != nil) != wantErr {
			t.Errorf("caps %04x: %v", caps, err)
		}
	}
}

func TestSniffBanner(t *testing.T) {
	cases := map[string]string{
		"220 mail ESMTP Postfix\r\n": "smtp", "220 ProFTPD Server\r\n": "ftp", "* OK IMAP ready\r\n": "imap",
		"+OK POP3\r\n": "pop3", "SSH-2.0-OpenSSH_9\r\n": "unknown",
	}
	for banner, want := range cases {
		a, b := net.Pipe()
		go func() { io.WriteString(b, banner) }()
		got, _ := SniffBanner(context.Background(), a, time.Second)
		if got != want {
			t.Errorf("%q: %s want %s", banner, got, want)
		}
		a.Close()
		b.Close()
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if got, _ := SniffBanner(context.Background(), a, 100*time.Millisecond); got != "" {
		t.Errorf("silent server: %q", got)
	}
}

func TestLookup(t *testing.T) {
	for _, n := range []string{"smtp", "SMTPS", "postgresql", "mariadb", "tls", "https", "jabber", "mqtt"} {
		if _, err := Lookup(n); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
	if _, err := Lookup("gopher"); err == nil {
		t.Error("gopher")
	}
	if p, _ := ByPort(587); p != "smtp" {
		t.Error("587")
	}
	if DefaultPort("imaps") != 993 || DefaultPort("nope") != 443 {
		t.Error("DefaultPort")
	}
}

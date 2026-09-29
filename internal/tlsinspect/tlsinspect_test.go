package tlsinspect

import (
	"bufio"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/matusso/sslknife/internal/certificate"
	"github.com/matusso/sslknife/internal/keys"
)

type testPKI struct {
	root, inter *x509.Certificate
	interKey    crypto.Signer
	roots       *x509.CertPool
}

func newPKI(t *testing.T) *testPKI {
	t.Helper()
	rk, _ := keys.Generate(keys.ECDSAP256)
	root, err := certificate.Create(certificate.Request{Profile: certificate.ProfileRootCA, Subject: pkix.Name{CommonName: "Test Root"},
		Validity: 24 * time.Hour, Key: rk, PathLen: -1})
	if err != nil {
		t.Fatal(err)
	}
	ik, _ := keys.Generate(keys.ECDSAP256)
	inter, err := certificate.Create(certificate.Request{Profile: certificate.ProfileIntermediateCA, Subject: pkix.Name{CommonName: "Test Inter"},
		Validity: 12 * time.Hour, Key: ik, Issuer: root, IssuerKey: rk, PathLen: 0})
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &testPKI{root: root, inter: inter, interKey: ik, roots: pool}
}

// leaf issues a server certificate; nb/validity allow expired certificates.
func (p *testPKI) leaf(t *testing.T, nb time.Time, validity time.Duration, withChain bool) tls.Certificate {
	t.Helper()
	k, _ := keys.Generate(keys.ECDSAP256)
	c, err := certificate.Create(certificate.Request{Profile: certificate.ProfileServer, Subject: pkix.Name{CommonName: "localhost"},
		SANs: []string{"localhost", "127.0.0.1"}, NotBefore: nb, Validity: validity, Key: k, Issuer: p.inter, IssuerKey: p.interKey, PathLen: -1})
	if err != nil {
		t.Fatal(err)
	}
	chain := [][]byte{c.Raw}
	if withChain {
		chain = append(chain, p.inter.Raw)
	}
	return tls.Certificate{Certificate: chain, PrivateKey: k}
}

// listen serves TLS on raw connections after an optional plaintext preamble.
func listen(t *testing.T, cfg *tls.Config, preamble func(net.Conn) bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				if preamble != nil && !preamble(c) {
					return
				}
				tc := tls.Server(c, cfg)
				if tc.Handshake() == nil {
					_, _ = io.Copy(io.Discard, tc)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func connect(t *testing.T, addr, proto string) *Connector {
	t.Helper()
	target, err := ParseTarget(addr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewConnector(context.Background(), target, Options{Protocol: proto, SNI: "localhost", Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func ids(f []certificate.Finding) []string {
	var out []string
	for _, x := range f {
		out = append(out, x.ID)
	}
	return out
}

func TestInspectTrustedChain(t *testing.T) {
	p := newPKI(t)
	addr := listen(t, &tls.Config{Certificates: []tls.Certificate{p.leaf(t, time.Time{}, time.Hour, true)}}, nil)
	c := connect(t, addr, "tls")
	res, err := c.Inspect(context.Background(), InspectOptions{Roots: p.roots, Resumption: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Validation.Trusted || !res.Validation.HostnameValid || !res.Validation.ChainOrdered || len(res.Chain) != 2 {
		t.Fatalf("%+v", res.Validation)
	}
	if res.TLS.Version != "TLS 1.3" || res.TLS.Cipher == "" || res.TLS.KeyExchangeGroup == "" || res.TLS.Handshake != "go" {
		t.Fatalf("%+v", res.TLS)
	}
	if res.TLS.SessionResumption == nil || !*res.TLS.SessionResumption {
		t.Errorf("session resumption not detected: %v", res.TLS.SessionResumption)
	}
	if res.Protocol.Method != "direct" || res.Protocol.Via != "flag" {
		t.Fatalf("%+v", res.Protocol)
	}
}

func TestInspectIncompleteExpiredSelfSigned(t *testing.T) {
	p := newPKI(t)
	// Incomplete chain.
	addr := listen(t, &tls.Config{Certificates: []tls.Certificate{p.leaf(t, time.Time{}, time.Hour, false)}}, nil)
	res, err := connect(t, addr, "tls").Inspect(context.Background(), InspectOptions{Roots: p.roots})
	if err != nil {
		t.Fatal(err)
	}
	if res.Validation.Trusted || res.Validation.Reason != "unknown_authority" || !slices.Contains(ids(res.Findings), "missing_intermediate") {
		t.Fatalf("%+v %v", res.Validation, ids(res.Findings))
	}

	// Expired.
	addr = listen(t, &tls.Config{Certificates: []tls.Certificate{p.leaf(t, time.Now().Add(-3*time.Hour), time.Hour, true)}}, nil)
	res, err = connect(t, addr, "tls").Inspect(context.Background(), InspectOptions{Roots: p.roots})
	if err != nil {
		t.Fatal(err)
	}
	if res.Validation.Trusted || res.Validation.Reason != "expired" || !slices.Contains(ids(res.Findings), "expired") {
		t.Fatalf("%+v %v", res.Validation, ids(res.Findings))
	}

	// Self-signed, validated against the system store.
	k, _ := keys.Generate(keys.ECDSAP256)
	self, _ := certificate.Create(certificate.Request{Profile: certificate.ProfileServer, Subject: pkix.Name{CommonName: "localhost"},
		Validity: time.Hour, Key: k, PathLen: -1})
	addr = listen(t, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{self.Raw}, PrivateKey: k}}}, nil)
	res, err = connect(t, addr, "tls").Inspect(context.Background(), InspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Validation.Trusted || !res.Certificate.SelfSigned || res.Validation.TrustStore != "system" {
		t.Fatalf("%+v", res.Validation)
	}
}

func smtpPreamble(c net.Conn) bool {
	r := bufio.NewReader(c)
	io.WriteString(c, "220 mail.test ESMTP ready\r\n")
	line, _ := r.ReadString('\n')
	if !strings.HasPrefix(line, "EHLO") {
		return false
	}
	io.WriteString(c, "250-mail.test\r\n250-PIPELINING\r\n250 STARTTLS\r\n")
	line, _ = r.ReadString('\n')
	if !strings.HasPrefix(line, "STARTTLS") {
		return false
	}
	io.WriteString(c, "220 go ahead\r\n")
	return true
}

func imapPreamble(c net.Conn) bool {
	r := bufio.NewReader(c)
	io.WriteString(c, "* OK [CAPABILITY IMAP4rev1 STARTTLS] ready\r\n")
	line, _ := r.ReadString('\n')
	if !strings.HasPrefix(line, "a1 STARTTLS") {
		return false
	}
	io.WriteString(c, "a1 OK begin TLS\r\n")
	return true
}

func postgresPreamble(c net.Conn) bool {
	buf := make([]byte, 8)
	if _, err := io.ReadFull(c, buf); err != nil || buf[7] != 0x2f {
		return false
	}
	c.Write([]byte{'S'})
	return true
}

func TestSTARTTLS(t *testing.T) {
	p := newPKI(t)
	cfg := &tls.Config{Certificates: []tls.Certificate{p.leaf(t, time.Time{}, time.Hour, true)}}
	for _, tc := range []struct {
		proto    string
		preamble func(net.Conn) bool
	}{{"smtp", smtpPreamble}, {"imap", imapPreamble}, {"postgres", postgresPreamble}} {
		addr := listen(t, cfg, tc.preamble)
		c := connect(t, addr, tc.proto)
		res, err := c.Inspect(context.Background(), InspectOptions{Roots: p.roots})
		if err != nil {
			t.Fatalf("%s: %v", tc.proto, err)
		}
		if !res.Validation.Trusted || res.Protocol.Method != "starttls" || len(res.Transcript) == 0 {
			t.Fatalf("%s: %+v %+v", tc.proto, res.Validation, res.Protocol)
		}
	}
}

func TestSMTPWithoutSTARTTLS(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		io.WriteString(c, "220 mail ESMTP\r\n")
		r.ReadString('\n')
		io.WriteString(c, "250-mail\r\n250 SIZE 100\r\n")
		r.ReadString('\n')
	}()
	c := connect(t, ln.Addr().String(), "smtp")
	_, err := c.Inspect(context.Background(), InspectOptions{})
	if err == nil || !strings.Contains(err.Error(), "STARTTLS not advertised") {
		t.Fatal(err)
	}
}

func TestBannerDetection(t *testing.T) {
	p := newPKI(t)
	addr := listen(t, &tls.Config{Certificates: []tls.Certificate{p.leaf(t, time.Time{}, time.Hour, true)}}, smtpPreamble)
	c := connect(t, addr, "")
	if c.Detection.Protocol != "smtp" || c.Detection.Via != "banner" || !strings.Contains(c.Detection.Banner, "ESMTP") {
		t.Fatalf("%+v", c.Detection)
	}
}

func TestScan(t *testing.T) {
	p := newPKI(t)
	addr := listen(t, &tls.Config{Certificates: []tls.Certificate{p.leaf(t, time.Time{}, time.Hour, true)}, MinVersion: tls.VersionTLS12}, nil)
	c := connect(t, addr, "tls")
	res, err := c.Scan(context.Background(), ScanOptions{Inspect: InspectOptions{Roots: p.roots}})
	if err != nil {
		t.Fatal(err)
	}
	var enabled []string
	for _, v := range res.Versions {
		if v.Supported {
			enabled = append(enabled, v.Version)
		}
	}
	if !slices.Equal(enabled, []string{"TLS 1.2", "TLS 1.3"}) {
		t.Fatalf("versions %v", enabled)
	}
	for _, f := range res.Findings {
		if f.Severity == Critical || f.Severity == High {
			t.Errorf("unexpected finding %+v", f)
		}
	}
	checks := map[string]SummaryItem{}
	for _, s := range res.Summary {
		checks[s.Check] = s
	}
	if checks["Certificate Chain"].Status != "PASS" || checks["TLS 1.3"].Status != "ENABLED" || checks["SSLv3"].Status != "DISABLED" ||
		checks["Weak Ciphers"].Status != "NONE" {
		t.Fatalf("%+v", res.Summary)
	}
	if len(res.Groups.TLS13) == 0 {
		t.Fatal("no groups")
	}
}

func TestParseTarget(t *testing.T) {
	cases := map[string]Target{
		"example.com":             {Host: "example.com", Port: 443},
		"example.com:8443":        {Host: "example.com", Port: 8443},
		"[2001:db8::1]:993":       {Host: "2001:db8::1", Port: 993},
		"smtp://mail.example.com": {Host: "mail.example.com", Port: 25, Protocol: "smtp"},
		"https://x.example/path":  {Host: "x.example", Port: 443, Protocol: "https"},
		"imaps://x.example:10993": {Host: "x.example", Port: 10993, Protocol: "imaps"},
	}
	for in, want := range cases {
		got, err := ParseTarget(in)
		if err != nil || got != want {
			t.Errorf("%q: %+v %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "host:99999", "host:abc", "a b"} {
		if _, err := ParseTarget(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if !LooksLikeTarget("example.com:443") || LooksLikeTarget("cert.pem") || !LooksLikeTarget("https://x") {
		t.Fatal("LooksLikeTarget")
	}
}

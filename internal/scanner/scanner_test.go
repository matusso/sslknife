package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"slices"
	"testing"
	"time"
)

func testCert(t *testing.T, rsaKey bool) tls.Certificate {
	t.Helper()
	var key any
	var pub any
	if rsaKey {
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		key, pub = k, &k.PublicKey
	} else {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		key, pub = k, &k.PublicKey
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serve runs a TLS server that completes handshakes and closes.
func serve(t *testing.T, cfg *tls.Config) *Prober {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
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
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				_ = c.(*tls.Conn).Handshake()
				c.Close()
			}()
		}
	}()
	addr := ln.Addr().String()
	return &Prober{
		Dial:       func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", addr) },
		ServerName: "localhost",
		Timeout:    3 * time.Second,
	}
}

func supported(res []VersionResult) []string {
	var out []string
	for _, r := range res {
		if r.Supported {
			out = append(out, r.Version)
		}
		if r.Error != "" {
			panic(r.Version + ": " + r.Error)
		}
	}
	return out
}

func TestVersionsTLS12Only(t *testing.T) {
	p := serve(t, &tls.Config{Certificates: []tls.Certificate{testCert(t, false)}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
	got := supported(p.Versions(context.Background()))
	if !slices.Equal(got, []string{"TLS 1.2"}) {
		t.Fatalf("got %v", got)
	}
}

func TestVersionsModern(t *testing.T) {
	p := serve(t, &tls.Config{Certificates: []tls.Certificate{testCert(t, false)}, MinVersion: tls.VersionTLS12})
	got := supported(p.Versions(context.Background()))
	if !slices.Equal(got, []string{"TLS 1.2", "TLS 1.3"}) {
		t.Fatalf("got %v", got)
	}
}

func TestCiphersTLS12(t *testing.T) {
	want := []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256}
	p := serve(t, &tls.Config{Certificates: []tls.Certificate{testCert(t, false)}, MaxVersion: tls.VersionTLS12, CipherSuites: want})
	res := p.Ciphers(context.Background(), VersionTLS12)
	if res.Error != "" {
		t.Fatal(res.Error)
	}
	var got []uint16
	for _, s := range res.Suites {
		got = append(got, s.ID)
		if s.KeyExchange == nil || s.KeyExchange.Kind != "ECDH" {
			t.Errorf("%s: missing key exchange params: %+v", s.Name, s.KeyExchange)
		}
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("got %x want %x", got, want)
	}
	for _, s := range res.Suites {
		if s.ID == tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA && s.Strength != "deprecated" {
			t.Errorf("CBC suite strength %s", s.Strength)
		}
	}
}

func TestCiphersTLS13AndGroups(t *testing.T) {
	p := serve(t, &tls.Config{Certificates: []tls.Certificate{testCert(t, false)}, MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}})
	res := p.Ciphers(context.Background(), VersionTLS13)
	if len(res.Suites) != 3 {
		t.Fatalf("expected the 3 Go TLS 1.3 suites, got %+v", res)
	}
	groups := p.Groups13(context.Background())
	if !slices.Equal(groups, []string{"x25519", "secp256r1"}) {
		t.Fatalf("groups %v", groups)
	}
}

func TestRSAKeyExchangeDetected(t *testing.T) {
	suites := []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
	p := serve(t, &tls.Config{Certificates: []tls.Certificate{testCert(t, true)}, MaxVersion: tls.VersionTLS12, CipherSuites: suites})
	res := p.Ciphers(context.Background(), VersionTLS12)
	var names []string
	for _, s := range res.Suites {
		names = append(names, s.Name)
	}
	if !slices.Contains(names, "TLS_RSA_WITH_AES_128_GCM_SHA256") {
		t.Skipf("runtime does not serve static RSA key exchange: %v", names)
	}
	for _, s := range res.Suites {
		if s.Name == "TLS_RSA_WITH_AES_128_GCM_SHA256" && (s.ForwardSecret() || s.Strength != "deprecated") {
			t.Fatalf("%+v", s)
		}
	}
}

func TestExtras(t *testing.T) {
	p := serve(t, &tls.Config{Certificates: []tls.Certificate{testCert(t, false)}, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12})
	vers := supported(p.Versions(context.Background()))
	e := p.CheckExtras(context.Background(), VersionTLS10, VersionTLS12)
	if e.SecureRenegotiation == nil || !*e.SecureRenegotiation {
		t.Error("secure renegotiation not detected")
	}
	if e.Compression == nil || *e.Compression {
		t.Error("compression")
	}
	if slices.Contains(vers, "TLS 1.0") {
		if e.FallbackSCSV == nil || !*e.FallbackSCSV {
			t.Errorf("fallback SCSV: %v", e.FallbackSCSV)
		}
	}
}

func TestNotTLS(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			c.Close()
		}
	}()
	addr := ln.Addr().String()
	p := &Prober{Dial: func(ctx context.Context) (net.Conn, error) { return net.Dial("tcp", addr) }, Timeout: time.Second}
	for _, r := range p.Versions(context.Background()) {
		if r.Supported {
			t.Fatalf("%s reported supported on a non-TLS server", r.Version)
		}
	}
}

func TestClassify(t *testing.T) {
	cases := map[uint16]string{
		0x0004: "insecure", 0x0003: "insecure", 0x0001: "insecure", 0x0018: "insecure",
		0x000A: "weak", 0xC012: "weak",
		0x002F: "deprecated", 0x009C: "deprecated", 0xC013: "deprecated",
		0xC02F: "modern", 0xCCA9: "modern", 0x1301: "modern", 0x1305: "deprecated",
	}
	for id, want := range cases {
		if s := Lookup(id); s.Strength != want {
			t.Errorf("%s: %s want %s (%v)", s.Name, s.Strength, want, s.Reasons)
		}
	}
	s := Lookup(0xC02B)
	if s.KeyExch != "ECDHE" || s.Auth != "ECDSA" || s.Cipher != "AES" || s.Bits != 128 || s.Mode != "GCM" || s.MAC != "AEAD" {
		t.Fatalf("%+v", s)
	}
	if s := Lookup(0x1303); !s.TLS13 || s.Cipher != "CHACHA20" {
		t.Fatalf("%+v", s)
	}
}

func FuzzServerHello(f *testing.F) {
	f.Add([]byte{22, 3, 3, 0, 4, 2, 0, 0, 0})
	f.Add([]byte{21, 3, 3, 0, 2, 2, 40})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = readServerHello(bytesReader(data), true)
	})
}

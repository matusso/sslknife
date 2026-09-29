package cmd

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/matusso/sslknife/internal/certificate"
	"github.com/matusso/sslknife/internal/exitcode"
	"github.com/matusso/sslknife/internal/keys"
	"github.com/matusso/sslknife/internal/tlsinspect"
)

// tlsServer starts a local TLS 1.2+ server with a self-signed certificate
// and writes its certificate to a file usable as --truststore.
func tlsServer(t *testing.T, e *env) (addr, rootFile string) {
	t.Helper()
	k, _ := keys.Generate(keys.ECDSAP256)
	c, err := certificate.Create(certificate.Request{Profile: certificate.ProfileServer, Subject: pkix.Name{CommonName: "localhost"},
		SANs: []string{"localhost", "127.0.0.1"}, Validity: time.Hour, Key: k, PathLen: -1})
	if err != nil {
		t.Fatal(err)
	}
	rootFile = e.path("server.pem")
	if err := os.WriteFile(rootFile, certificate.EncodePEM(c), 0o644); err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{c.Raw}, PrivateKey: k}}, MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if conn.(*tls.Conn).Handshake() == nil {
					_, _ = io.Copy(io.Discard, conn)
				}
			}()
		}
	}()
	return ln.Addr().String(), rootFile
}

func TestTLSCommands(t *testing.T) {
	e := newEnv(t)
	addr, root := tlsServer(t, e)
	_, port, _ := net.SplitHostPort(addr)
	target := "localhost:" + port
	common := []string{"--protocol", "tls", "--ip", "127.0.0.1", "--timeout", "3s"}

	var res tlsinspect.Result
	out := e.ok(append([]string{"tls", "inspect", target, "--json", "--truststore", root}, common...)...)
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	if !res.Validation.Trusted || !res.Validation.HostnameValid || res.TLS.Version != "TLS 1.3" || res.TLS.ALPN != "h2" {
		t.Fatalf("%+v %+v", res.Validation, res.TLS)
	}
	if out := e.ok(append([]string{"tls", "inspect", target}, common...)...); !strings.Contains(out, "INVALID") {
		t.Fatal("self-signed certificate should be untrusted against the system store:\n" + out)
	}

	out = e.ok(append([]string{"tls", "versions", target}, common...)...)
	if !strings.Contains(out, "TLS 1.3   SUPPORTED") || !strings.Contains(out, "TLS 1.1   NOT SUPPORTED") {
		t.Fatal(out)
	}
	out = e.ok(append([]string{"tls", "ciphers", target, "--version", "tls1.3"}, common...)...)
	if !strings.Contains(out, "TLS_AES_128_GCM_SHA256") {
		t.Fatal(out)
	}
	if out := e.ok(append([]string{"tls", "alpn", target}, common...)...); strings.TrimSpace(out) != "h2" {
		t.Fatalf("alpn: %q", out)
	}

	var scan tlsinspect.ScanResult
	out = e.ok(append([]string{"tls", "scan", target, "--json", "--truststore", root}, common...)...)
	if err := json.Unmarshal([]byte(out), &scan); err != nil {
		t.Fatal(err)
	}
	if len(scan.Summary) == 0 || len(scan.Ciphers) != 2 {
		t.Fatalf("%+v", scan.Summary)
	}
	// Self-signed leaf is untrusted by the system store: high finding.
	e.code(exitcode.CheckFailed, append([]string{"tls", "scan", target, "--fail-on", "high", "--no-ciphers"}, common...)...)
	e.code(exitcode.Usage, "tls", "scan", target, "--fail-on", "severe")
	e.code(exitcode.Network, "tls", "inspect", "127.0.0.1:1", "--protocol", "tls", "--timeout", "1s")

	// History and remote import need the vault.
	e.ok("init")
	e.ok(append([]string{"tls", "inspect", target, "--save", "--truststore", root}, common...)...)
	e.ok(append([]string{"tls", "inspect", target, "--save", "--truststore", root}, common...)...)
	if out := e.ok("tls", "history", target); !strings.Contains(out, "inspect") {
		t.Fatal(out)
	}
	e.ok("tls", "diff", target) // identical observations
	e.ok("cert", "import", "https://127.0.0.1:"+port, "--chain", "--name", "local")
	if out := e.ok("cert", "show", "local"); !strings.Contains(out, "localhost") {
		t.Fatal(out)
	}
}

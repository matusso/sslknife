// Package server runs the local SSLKnife web interface and REST API.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/matusso/sslknife/internal/certificate"
	"github.com/matusso/sslknife/internal/config"
	skcrypto "github.com/matusso/sslknife/internal/crypto"
	"github.com/matusso/sslknife/internal/database"
	"github.com/matusso/sslknife/internal/inventory"
	"github.com/matusso/sslknife/internal/keys"
	"github.com/matusso/sslknife/internal/netdial"
	"github.com/matusso/sslknife/internal/views"
)

// Options configure the server.
type Options struct {
	Listen       string
	PlainHTTP    bool   // serve HTTP instead of HTTPS (loopback only unless AllowInsecure)
	CertFile     string // optional TLS certificate/key files
	KeyFile      string
	Token        string // access token; random when empty
	AllowedHosts []string
	Config       *config.Config
	Logger       *slog.Logger
	Dialer       netdial.Dialer
	CTProvider   string
	CTToken      string
	CTBaseURL    string // alternative CT endpoint (self-hosted or test)
	Version      string
	Jobs         bool
	Static       fs.FS // web UI assets
}

// Server is a running web interface bound to an unlocked vault.
type Server struct {
	opts        Options
	db          *database.DB
	inv         *inventory.Service
	auth        *auth
	log         *slog.Logger
	scanSem     chan struct{}
	listener    net.Listener
	tlsConfig   *tls.Config
	fingerprint string
}

// IsLoopback reports whether a listen address only accepts local connections.
func IsLoopback(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// New prepares a server. It binds the listener so that port errors are
// reported before the URL is printed.
func New(ctx context.Context, db *database.DB, o Options) (*Server, error) {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	s := &Server{opts: o, db: db, inv: inventory.New(db), auth: newAuth(o.Token), log: o.Logger, scanSem: make(chan struct{}, 2)}
	if !o.PlainHTTP {
		cfg, fp, err := s.loadTLS(ctx)
		if err != nil {
			return nil, err
		}
		s.tlsConfig, s.fingerprint = cfg, fp
	}
	ln, err := net.Listen("tcp", o.Listen)
	if err != nil {
		return nil, err
	}
	s.listener = ln
	return s, nil
}

// Addr returns the bound address.
func (s *Server) Addr() string { return s.listener.Addr().String() }

// URL returns the login URL including the access token.
func (s *Server) URL() string {
	scheme := "https"
	if s.opts.PlainHTTP {
		scheme = "http"
	}
	host, port, _ := net.SplitHostPort(s.Addr())
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("%s://%s/?token=%s", scheme, net.JoinHostPort(host, port), s.auth.token)
}

// Fingerprint is the SHA-256 of the server certificate (empty for HTTP).
func (s *Server) Fingerprint() string { return s.fingerprint }

// Token returns the access token (for API clients).
func (s *Server) Token() string { return s.auth.token }

func (s *Server) allowedHosts() map[string]bool {
	m := map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}
	host, _, _ := net.SplitHostPort(s.opts.Listen)
	if host != "" && host != "0.0.0.0" && host != "::" {
		m[strings.ToLower(host)] = true
	}
	for _, h := range s.opts.AllowedHosts {
		m[strings.ToLower(strings.Trim(h, "[]"))] = true
	}
	if host == "0.0.0.0" || host == "::" || host == "" {
		// Listening on all interfaces: accept the machine's own addresses.
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok {
					m[ipn.IP.String()] = true
				}
			}
		}
	}
	return m
}

// Handler builds the HTTP handler (exposed for tests).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	api := http.NewServeMux()
	s.routes(api)
	mux.Handle("/api/", s.auth.requireAuth(api))
	mux.HandleFunc("GET /{$}", s.index)
	if s.opts.Static != nil {
		files := http.FileServerFS(s.opts.Static)
		mux.Handle("GET /assets/", http.StripPrefix("/assets/", files))
	}
	return securityHeaders(hostCheck(s.allowedHosts(), mux))
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if s.auth.login(w, r) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if s.auth.lookup(r) == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `<!doctype html><meta charset="utf-8"><title>SSLKnife</title><link rel="stylesheet" href="/assets/style.css">`+
			`<main class="locked"><h1>SSLKnife</h1><p>Open the URL printed by <code>sslknife server</code>; it contains the access token.</p></main>`)
		return
	}
	if s.opts.Static == nil {
		http.Error(w, "web UI not available", http.StatusNotFound)
		return
	}
	data, err := fs.ReadFile(s.opts.Static, "index.html")
	if err != nil {
		http.Error(w, "web UI not available", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// Run serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      5 * time.Minute, // TLS scans are synchronous
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
		TLSConfig:         s.tlsConfig,
	}
	if s.opts.Jobs {
		go s.runJobs(ctx)
	}
	errc := make(chan error, 1)
	go func() {
		if s.tlsConfig != nil {
			errc <- srv.ServeTLS(s.listener, "", "")
		} else {
			errc <- srv.Serve(s.listener)
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := srv.Shutdown(shutdown)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		return err
	}
}

const (
	settingTLSCert = "server.tls.cert"
	settingTLSKey  = "server.tls.key"
)

// loadTLS returns the server TLS configuration: user-supplied files, or a
// self-signed identity persisted (encrypted) in the vault so the browser
// sees the same certificate across restarts.
func (s *Server) loadTLS(ctx context.Context) (*tls.Config, string, error) {
	if s.opts.CertFile != "" {
		pair, err := tls.LoadX509KeyPair(s.opts.CertFile, s.opts.KeyFile)
		if err != nil {
			return nil, "", fmt.Errorf("server certificate: %w", err)
		}
		leaf, _ := x509.ParseCertificate(pair.Certificate[0])
		return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, certificate.Fingerprint(leaf).SHA256, nil
	}
	hosts := s.identityHosts()
	certDER, err1 := s.db.GetSetting(ctx, settingTLSCert)
	keyDER, err2 := s.db.GetSetting(ctx, settingTLSKey)
	defer skcrypto.Zero(keyDER)
	var leaf *x509.Certificate
	if err1 == nil && err2 == nil {
		if c, err := x509.ParseCertificate(certDER); err == nil && time.Until(c.NotAfter) > 30*24*time.Hour && coversAll(c, hosts) {
			leaf = c
		}
	}
	if leaf == nil {
		k, err := keys.Generate(keys.ECDSAP256)
		if err != nil {
			return nil, "", err
		}
		leaf, err = certificate.Create(certificate.Request{Profile: certificate.ProfileServer,
			Subject: pkix.Name{CommonName: "SSLKnife local server", Organization: []string{"SSLKnife"}},
			SANs:    hosts, Validity: 397 * 24 * time.Hour, Key: k, PathLen: -1})
		if err != nil {
			return nil, "", err
		}
		if keyDER, err = x509.MarshalPKCS8PrivateKey(k); err != nil {
			return nil, "", err
		}
		if err := s.db.SetSetting(ctx, settingTLSKey, keyDER, true); err != nil {
			return nil, "", err
		}
		if err := s.db.SetSetting(ctx, settingTLSCert, leaf.Raw, false); err != nil {
			return nil, "", err
		}
		s.log.Info("generated server certificate", "sha256", certificate.Fingerprint(leaf).SHA256)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, "", err
	}
	pair := tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, certificate.Fingerprint(leaf).SHA256, nil
}

func (s *Server) identityHosts() []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	for h := range s.allowedHosts() {
		if !slices.Contains(hosts, h) && (net.ParseIP(h) != nil || certificate.ValidateDNSName(h) == nil) {
			hosts = append(hosts, h)
		}
	}
	slices.Sort(hosts[3:])
	return hosts
}

func coversAll(c *x509.Certificate, hosts []string) bool {
	for _, h := range hosts {
		if c.VerifyHostname(h) != nil {
			return false
		}
	}
	return true
}

func (s *Server) expiry() views.Expiry {
	return views.Expiry{WarningDays: s.opts.Config.Expiry.WarningDays, CriticalDays: s.opts.Config.Expiry.CriticalDays}
}

package tlsinspect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/matusso/sslknife/internal/certificate"
	"github.com/matusso/sslknife/internal/protocol"
	"github.com/matusso/sslknife/internal/scanner"
)

// InspectOptions control Inspect.
type InspectOptions struct {
	Roots          *x509.CertPool // nil = system trust store
	TrustStoreName string         // for display
	Hostname       string         // name to validate; default SNI or host
	ALPN           []string       // default depends on protocol
	Resumption     bool           // test session resumption (one extra handshake)
	Now            time.Time
	WarningDays    int
}

// Result is the JSON schema of `tls inspect`.
type Result struct {
	Target      string                `json:"target"`
	Host        string                `json:"host"`
	Port        int                   `json:"port"`
	SNI         string                `json:"sni,omitempty"`
	IPs         []string              `json:"resolved_ips,omitempty"`
	ConnectedTo string                `json:"connected_to"`
	Protocol    protocol.Detection    `json:"protocol"`
	Transcript  []string              `json:"starttls_transcript,omitempty"`
	TLS         SessionInfo           `json:"tls"`
	Certificate *certificate.Info     `json:"certificate,omitempty"`
	Chain       []ChainCert           `json:"chain"`
	Validation  Validation            `json:"validation"`
	OCSP        *OCSPInfo             `json:"ocsp,omitempty"`
	Findings    []certificate.Finding `json:"certificate_findings"`
	Duration    string                `json:"duration"`
	Error       string                `json:"error,omitempty"` // handshake error when only partial data is available
}

// SessionInfo describes the negotiated session.
type SessionInfo struct {
	Version           string   `json:"version"`
	Cipher            string   `json:"cipher"`
	CipherStrength    string   `json:"cipher_strength"`
	KeyExchangeGroup  string   `json:"key_exchange_group,omitempty"`
	ALPN              string   `json:"alpn,omitempty"`
	OfferedALPN       []string `json:"offered_alpn,omitempty"`
	HelloRetryRequest bool     `json:"hello_retry_request"`
	OCSPStapled       bool     `json:"ocsp_stapled"`
	SCTsInHandshake   int      `json:"scts_in_handshake"`
	SessionResumption *bool    `json:"session_resumption,omitempty"`
	Handshake         string   `json:"handshake"` // go (full handshake) or probe (certificate only)
}

// ChainCert is one certificate as presented by the server.
type ChainCert struct {
	Position     int       `json:"position"`
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	NotAfter     time.Time `json:"not_after"`
	SHA256       string    `json:"sha256"`
	Key          string    `json:"key"`
	Signature    string    `json:"signature_algorithm"`
	IsCA         bool      `json:"is_ca"`
	SelfSigned   bool      `json:"self_signed"`
	IssuedByNext bool      `json:"issued_by_next"` // chain order check
}

// Validation summarises trust.
type Validation struct {
	Trusted       bool     `json:"trusted"`
	TrustStore    string   `json:"trust_store"`
	HostnameValid bool     `json:"hostname_valid"`
	Hostname      string   `json:"hostname"`
	ChainOrdered  bool     `json:"chain_ordered"`
	VerifiedChain []string `json:"verified_chain,omitempty"`
	Missing       []string `json:"missing_intermediates,omitempty"` // supplied by the verifier, not the server
	Error         string   `json:"error,omitempty"`
	Reason        string   `json:"reason,omitempty"`
}

// OCSPInfo describes a stapled OCSP response.
type OCSPInfo struct {
	Stapled    bool      `json:"stapled"`
	Status     string    `json:"status,omitempty"` // good, revoked, unknown
	ProducedAt time.Time `json:"produced_at,omitempty"`
	ThisUpdate time.Time `json:"this_update,omitempty"`
	NextUpdate time.Time `json:"next_update,omitempty"`
	RevokedAt  time.Time `json:"revoked_at,omitempty"`
	Error      string    `json:"error,omitempty"`
	Responders []string  `json:"responders,omitempty"`
	MustStaple bool      `json:"must_staple"`
}

func defaultALPN(p string) []string {
	switch p {
	case "https", "tls":
		return []string{"h2", "http/1.1"}
	case "xmpp", "xmpps":
		return []string{"xmpp-client"}
	case "dot":
		return []string{"dot"}
	case "mqtts":
		return []string{"mqtt"}
	}
	return nil
}

// allSuites enables every suite Go implements, including insecure ones, so
// that legacy servers can still be inspected. This client never sends data.
func allSuites() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
}

func (c *Connector) tlsConfig(o InspectOptions, cache tls.ClientSessionCache) *tls.Config {
	alpn := o.ALPN
	if alpn == nil {
		alpn = defaultALPN(c.Adapter.Name())
	}
	return &tls.Config{
		ServerName: c.SNI,
		// Verification is done separately so that an untrusted chain can
		// still be reported in full.
		InsecureSkipVerify: true, //nolint:gosec // verified below
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       allSuites(),
		NextProtos:         alpn,
		ClientSessionCache: cache,
	}
}

// dialError marks failures to connect or upgrade, as opposed to TLS
// handshake failures.
type dialError struct{ err error }

func (e *dialError) Error() string { return e.err.Error() }
func (e *dialError) Unwrap() error { return e.err }

func (c *Connector) handshake(ctx context.Context, cfg *tls.Config) (*tls.Conn, error) {
	raw, err := c.Dial(ctx)
	if err != nil {
		return nil, &dialError{err}
	}
	conn := tls.Client(raw, cfg)
	hctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()
	if err := conn.HandshakeContext(hctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

// Inspect performs a handshake and reports the session and chain.
func (c *Connector) Inspect(ctx context.Context, o InspectOptions) (*Result, error) {
	start := time.Now()
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	res := &Result{
		Target: c.Target.String(), Host: c.Target.Host, Port: c.Target.Port, SNI: c.SNI, IPs: c.IPs,
		ConnectedTo: c.addr, Protocol: c.Detection, Validation: trustStoreValidation(o),
	}
	var cache tls.ClientSessionCache
	if o.Resumption {
		cache = tls.NewLRUClientSessionCache(4)
	}
	cfg := c.tlsConfig(o, cache)
	conn, err := c.handshake(ctx, cfg)
	res.Transcript = c.Transcript()
	var peer []*x509.Certificate
	if err != nil {
		var de *dialError
		if errors.As(err, &de) {
			return nil, de.err
		}
		// The handshake may fail for reasons Go refuses to negotiate
		// (SSLv3, unknown suites). Fall back to a raw probe for the chain.
		peer, err = c.probeChain(ctx)
		if err != nil {
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		res.Error = "full handshake not possible with this client; certificate data obtained from a raw probe"
		res.TLS.Handshake = "probe"
	} else {
		st := conn.ConnectionState()
		peer = st.PeerCertificates
		suite := scanner.Lookup(st.CipherSuite)
		res.TLS = SessionInfo{
			Version: tls.VersionName(st.Version), Cipher: suite.Name, CipherStrength: suite.Strength,
			ALPN: st.NegotiatedProtocol, OfferedALPN: cfg.NextProtos, HelloRetryRequest: st.HelloRetryRequest,
			OCSPStapled: len(st.OCSPResponse) > 0, SCTsInHandshake: len(st.SignedCertificateTimestamps), Handshake: "go",
		}
		if st.CurveID != 0 {
			res.TLS.KeyExchangeGroup = scanner.GroupName(uint16(st.CurveID))
		}
		if o.Resumption {
			res.TLS.SessionResumption = c.checkResumption(ctx, conn, cfg)
		}
		if len(peer) > 0 {
			res.OCSP = ocspInfo(st.OCSPResponse, peer)
		}
		conn.Close()
	}
	if len(peer) == 0 {
		return nil, errors.New("server presented no certificate")
	}
	c.fillCertificates(res, peer, o)
	res.Duration = time.Since(start).Round(time.Millisecond).String()
	return res, nil
}

// trustStoreValidation returns a Validation stub carrying the trust store label.
func trustStoreValidation(o InspectOptions) Validation {
	name := "system"
	if o.Roots != nil {
		name = o.TrustStoreName
		if name == "" {
			name = "custom"
		}
	}
	return Validation{TrustStore: name}
}

func (c *Connector) checkResumption(ctx context.Context, first *tls.Conn, cfg *tls.Config) *bool {
	// TLS 1.3 tickets arrive after the handshake; a short read lets the
	// client process them.
	_ = first.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	var b [1]byte
	_, _ = first.Read(b[:])
	second, err := c.handshake(ctx, cfg)
	if err != nil {
		return nil
	}
	defer second.Close()
	r := second.ConnectionState().DidResume
	return &r
}

func (c *Connector) probeChain(ctx context.Context) ([]*x509.Certificate, error) {
	p := &scanner.Prober{Dial: c.Dial, ServerName: c.SNI, Timeout: c.opts.Timeout}
	var lastErr error
	for _, v := range []uint16{scanner.VersionTLS12, scanner.VersionTLS10, scanner.VersionSSL3} {
		sh, err := p.Send(ctx, &scanner.Hello{Version: v, Suites: scanner.LegacySuites()}, true)
		if err != nil {
			lastErr = err
			continue
		}
		var out []*x509.Certificate
		for _, der := range sh.Certificates {
			if cert, err := x509.ParseCertificate(der); err == nil {
				out = append(out, cert)
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no certificate received")
	}
	return nil, lastErr
}

func (c *Connector) fillCertificates(res *Result, peer []*x509.Certificate, o InspectOptions) {
	leaf := peer[0]
	info := certificate.Describe(leaf, certificate.Options{Now: o.Now, WarningDays: o.WarningDays})
	res.Certificate = &info
	res.Validation.ChainOrdered = true
	for i, cert := range peer {
		cc := ChainCert{
			Position: i, Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), NotAfter: cert.NotAfter.UTC(),
			SHA256: certificate.Fingerprint(cert).SHA256, Key: certificate.Describe(cert, certificate.Options{}).PublicKey.Description,
			Signature: cert.SignatureAlgorithm.String(), IsCA: cert.IsCA, SelfSigned: certificate.IsSelfSigned(cert),
		}
		if i+1 < len(peer) {
			cc.IssuedByNext = certificate.Issues(peer[i+1], cert)
			if !cc.IssuedByNext {
				res.Validation.ChainOrdered = false
			}
		}
		res.Chain = append(res.Chain, cc)
	}
	host := o.Hostname
	if host == "" {
		host = c.SNI
	}
	if host == "" {
		host = c.Target.Host
	}
	res.Validation.Hostname = host
	res.Validation.HostnameValid = leaf.VerifyHostname(host) == nil
	vr := certificate.Verify(leaf, certificate.VerifyOptions{Roots: o.Roots, Intermediates: peer[1:], Now: o.Now})
	res.Validation.Trusted = vr.Trusted
	res.Validation.VerifiedChain = vr.Chain
	res.Validation.Error, res.Validation.Reason = vr.Error, vr.Reason
	res.Validation.Missing = vr.Missing
	res.Findings = certificate.Lint(peer, certificate.LintOptions{Now: o.Now, Hostname: host, Roots: o.Roots, CheckTrust: true})
	if res.Findings == nil {
		res.Findings = []certificate.Finding{}
	}
	if res.OCSP == nil {
		res.OCSP = &OCSPInfo{}
	}
	res.OCSP.Responders = leaf.OCSPServer
	res.OCSP.MustStaple = info.MustStaple
}

func ocspInfo(raw []byte, peer []*x509.Certificate) *OCSPInfo {
	info := &OCSPInfo{Stapled: len(raw) > 0}
	if len(raw) == 0 {
		return info
	}
	var issuer *x509.Certificate
	if len(peer) > 1 {
		issuer = peer[1]
	}
	resp, err := ocsp.ParseResponseForCert(raw, peer[0], issuer)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	fillOCSP(info, resp)
	return info
}

func fillOCSP(info *OCSPInfo, resp *ocsp.Response) {
	switch resp.Status {
	case ocsp.Good:
		info.Status = "good"
	case ocsp.Revoked:
		info.Status = "revoked"
		info.RevokedAt = resp.RevokedAt
	default:
		info.Status = "unknown"
	}
	info.ProducedAt, info.ThisUpdate, info.NextUpdate = resp.ProducedAt, resp.ThisUpdate, resp.NextUpdate
}

// Certificates fetches the presented chain (used by `cert import host:port`).
func (c *Connector) Certificates(ctx context.Context) ([]*x509.Certificate, error) {
	conn, err := c.handshake(ctx, c.tlsConfig(InspectOptions{}, nil))
	if err != nil {
		var de *dialError
		if errors.As(err, &de) {
			return nil, de.err
		}
		return c.probeChain(ctx)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates, nil
}

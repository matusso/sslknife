package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"time"
)

// Dialer returns a connection that is ready for a ClientHello: for
// STARTTLS protocols the plaintext upgrade has already happened.
type Dialer func(ctx context.Context) (net.Conn, error)

// Prober sends ClientHello probes to one endpoint.
type Prober struct {
	Dial        Dialer
	ServerName  string
	Timeout     time.Duration // per probe; default 10s
	Concurrency int           // parallel probes; default 8
}

func (p *Prober) timeout() time.Duration {
	if p.Timeout <= 0 {
		return 10 * time.Second
	}
	return p.Timeout
}

// ErrRejected means the server refused the offered parameters (alert, or
// closed the connection) — i.e. "not supported".
var ErrRejected = errors.New("rejected by server")

// Send performs one probe. wantMore also reads Certificate and
// ServerKeyExchange for TLS ≤1.2.
func (p *Prober) Send(ctx context.Context, h *Hello, wantMore bool) (*ServerHello, error) {
	if h.ServerName == "" {
		h.ServerName = p.ServerName
	}
	msg, err := h.Marshal()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	conn, err := p.Dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := conn.Write(msg); err != nil {
		return nil, ErrRejected
	}
	sh, err := readServerHello(conn, wantMore)
	if sh != nil {
		return sh, nil
	}
	var alert *AlertError
	switch {
	case errors.As(err, &alert):
		return nil, err
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), isReset(err):
		return nil, ErrRejected
	}
	return nil, err
}

func isReset(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && !op.Timeout()
}

// rejected reports whether err is a negative answer rather than a failure.
func rejected(err error) bool {
	var alert *AlertError
	return errors.Is(err, ErrRejected) || errors.As(err, &alert) || errors.Is(err, ErrNotTLS)
}

// VersionResult is the outcome for one protocol version.
type VersionResult struct {
	Version   string `json:"version"`
	ID        uint16 `json:"id"`
	Supported bool   `json:"supported"`
	Error     string `json:"error,omitempty"` // probe failed (not a rejection)
}

// AllVersions is the probe order.
var AllVersions = []uint16{VersionSSL2, VersionSSL3, VersionTLS10, VersionTLS11, VersionTLS12, VersionTLS13}

// helloFor builds a default hello for a version with the given suites.
func helloFor(v uint16, suites []uint16) *Hello {
	if v == VersionTLS13 {
		return &Hello{Version: VersionTLS12, Suites: suites, SupportedVersions: []uint16{VersionTLS13}}
	}
	return &Hello{Version: v, Suites: suites}
}

// ProbeVersion tests whether the server accepts version v.
func (p *Prober) ProbeVersion(ctx context.Context, v uint16) VersionResult {
	res := VersionResult{Version: VersionName(v), ID: v}
	if v == VersionSSL2 {
		ok, err := p.probeSSLv2(ctx)
		res.Supported = ok
		if err != nil && !rejected(err) {
			res.Error = err.Error()
		}
		return res
	}
	suites := LegacySuites()
	if v == VersionTLS13 {
		suites = TLS13Suites()
	}
	sh, err := p.Send(ctx, helloFor(v, suites), false)
	switch {
	case err == nil:
		res.Supported = sh.Version == v
	case !rejected(err):
		res.Error = err.Error()
	}
	return res
}

// Versions probes every protocol version concurrently.
func (p *Prober) Versions(ctx context.Context) []VersionResult {
	out := make([]VersionResult, len(AllVersions))
	p.parallel(len(AllVersions), func(i int) { out[i] = p.ProbeVersion(ctx, AllVersions[i]) })
	return out
}

func (p *Prober) parallel(n int, f func(i int)) {
	c := p.Concurrency
	if c <= 0 {
		c = 8
	}
	sem := make(chan struct{}, c)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			f(i)
		}()
	}
	wg.Wait()
}

// AcceptedSuite is a cipher suite the server negotiated.
type AcceptedSuite struct {
	Suite
	KeyExchange *KeyExchange `json:"key_exchange_params,omitempty"`
}

// accepted combines a suite with the server's key exchange parameters and
// downgrades its strength when the parameters are weak (small DH groups or
// curves).
func accepted(s Suite, kx *KeyExchange) AcceptedSuite {
	a := AcceptedSuite{Suite: s, KeyExchange: kx}
	if kx == nil {
		return a
	}
	rank := map[string]int{"modern": 0, "deprecated": 1, "weak": 2, "insecure": 3}
	worsen := func(to, reason string) {
		if rank[to] > rank[a.Strength] {
			a.Strength = to
		}
		a.Reasons = append([]string{reason}, a.Reasons...)
	}
	switch {
	case kx.Kind == "DH" && kx.Bits < 1024:
		worsen("insecure", fmt.Sprintf("%d-bit DH group (Logjam)", kx.Bits))
	case kx.Kind == "DH" && kx.Bits < 2048:
		worsen("weak", fmt.Sprintf("%d-bit DH group", kx.Bits))
	case kx.Kind == "ECDH" && kx.Bits > 0 && kx.Bits < 256:
		worsen("weak", fmt.Sprintf("%d-bit curve %s", kx.Bits, kx.Group))
	}
	return a
}

// CipherResult lists the suites accepted for one version.
type CipherResult struct {
	Version         string          `json:"version"`
	ID              uint16          `json:"id"`
	Suites          []AcceptedSuite `json:"suites"`
	ServerPreferred *bool           `json:"server_order,omitempty"` // nil when fewer than two suites
	Error           string          `json:"error,omitempty"`
}

// Ciphers enumerates the suites accepted with version v by repeatedly
// offering every not-yet-accepted suite. When the server enforces its own
// order the result is in server preference order.
func (p *Prober) Ciphers(ctx context.Context, v uint16) CipherResult {
	res := CipherResult{Version: VersionName(v), ID: v}
	remaining := LegacySuites()
	if v == VersionTLS13 {
		remaining = TLS13Suites()
	}
	for len(remaining) > 0 {
		if ctx.Err() != nil {
			res.Error = ctx.Err().Error()
			break
		}
		sh, err := p.Send(ctx, helloFor(v, remaining), v != VersionTLS13)
		if err != nil {
			if !rejected(err) {
				res.Error = err.Error()
			}
			break
		}
		if sh.Version != v || !slices.Contains(remaining, sh.CipherSuite) {
			break // version downgrade, or a suite we did not offer
		}
		res.Suites = append(res.Suites, accepted(Lookup(sh.CipherSuite), sh.KeyExchange))
		remaining = slices.DeleteFunc(remaining, func(id uint16) bool { return id == sh.CipherSuite })
	}
	if len(res.Suites) >= 2 {
		a, b := res.Suites[0].ID, res.Suites[1].ID
		if sh, err := p.Send(ctx, helloFor(v, []uint16{b, a}), false); err == nil {
			serverOrder := sh.CipherSuite == a
			res.ServerPreferred = &serverOrder
		}
	}
	return res
}

// CiphersAll enumerates suites for each supported version concurrently.
func (p *Prober) CiphersAll(ctx context.Context, versions []uint16) []CipherResult {
	out := make([]CipherResult, len(versions))
	p.parallel(len(versions), func(i int) { out[i] = p.Ciphers(ctx, versions[i]) })
	return out
}

// GroupResult lists supported key exchange groups.
type GroupResult struct {
	TLS13 []string `json:"tls13,omitempty"`
	TLS12 []string `json:"tls12,omitempty"` // ECDHE curves accepted with TLS ≤1.2
}

// Groups13 finds the TLS 1.3 groups the server accepts. Each probe offers a
// single group with no key share; a supporting server must answer with a
// HelloRetryRequest naming that group.
func (p *Prober) Groups13(ctx context.Context) []string {
	ok := make([]bool, len(TLS13Groups))
	p.parallel(len(TLS13Groups), func(i int) {
		g := TLS13Groups[i]
		h := &Hello{Version: VersionTLS12, Suites: TLS13Suites(), SupportedVersions: []uint16{VersionTLS13},
			Groups: []uint16{g}, NoKeyShares: true}
		sh, err := p.Send(ctx, h, false)
		ok[i] = err == nil && sh.Version == VersionTLS13 && (sh.KeyShareGroup == g)
	})
	var out []string
	for i, g := range TLS13Groups {
		if ok[i] {
			out = append(out, GroupName(g))
		}
	}
	return out
}

// Curves12 finds ECDHE curves accepted with TLS ≤1.2 using the given ECDHE
// suites (from cipher enumeration).
func (p *Prober) Curves12(ctx context.Context, v uint16, ecdheSuites []uint16) []string {
	if len(ecdheSuites) == 0 {
		return nil
	}
	curves := []uint16{GroupX25519, GroupSecp256r1, GroupSecp384r1, GroupSecp521r1, GroupX448, 26, 27, 28, 22, 21, 19}
	ok := make([]bool, len(curves))
	p.parallel(len(curves), func(i int) {
		h := &Hello{Version: v, Suites: ecdheSuites, Groups: []uint16{curves[i]}}
		sh, err := p.Send(ctx, h, true)
		ok[i] = err == nil && sh.KeyExchange != nil && sh.KeyExchange.GroupID == curves[i]
	})
	var out []string
	for i, g := range curves {
		if ok[i] {
			out = append(out, GroupName(g))
		}
	}
	return out
}

// Extras holds protocol behaviour checks.
type Extras struct {
	SecureRenegotiation  *bool    `json:"secure_renegotiation,omitempty"` // RFC 5746
	FallbackSCSV         *bool    `json:"fallback_scsv,omitempty"`        // RFC 7507; nil if not testable
	Compression          *bool    `json:"compression,omitempty"`          // TLS compression accepted (CRIME)
	SessionTickets       *bool    `json:"session_tickets,omitempty"`
	ExtendedMasterSecret *bool    `json:"extended_master_secret,omitempty"`
	EncryptThenMAC       *bool    `json:"encrypt_then_mac,omitempty"`
	Extensions           []string `json:"server_extensions,omitempty"` // at the highest TLS ≤1.2 version
}

func boolPtr(b bool) *bool { return &b }

// CheckExtras runs behaviour probes. maxLegacy is the highest supported
// version ≤ TLS 1.2 (0 if none); minLegacy the lowest ≥ TLS 1.0.
func (p *Prober) CheckExtras(ctx context.Context, minLegacy, maxLegacy uint16) Extras {
	var e Extras
	if maxLegacy == 0 {
		return e
	}
	suites := LegacySuites()
	if sh, err := p.Send(ctx, helloFor(maxLegacy, suites), false); err == nil {
		e.SecureRenegotiation = boolPtr(sh.HasExtension(extRenegotiationInfo))
		e.SessionTickets = boolPtr(sh.HasExtension(extSessionTicket))
		e.ExtendedMasterSecret = boolPtr(sh.HasExtension(extExtendedMaster))
		e.EncryptThenMAC = boolPtr(sh.HasExtension(extEncryptThenMAC))
		for _, t := range sh.Extensions {
			e.Extensions = append(e.Extensions, ExtensionName(t))
		}
	}
	h := helloFor(maxLegacy, suites)
	h.Compression = []byte{1, 0} // DEFLATE, null
	if sh, err := p.Send(ctx, h, false); err == nil {
		e.Compression = boolPtr(sh.Compression != 0)
	}
	if minLegacy != 0 && minLegacy < maxLegacy {
		h := helloFor(minLegacy, suites)
		h.Fallback = true
		_, err := p.Send(ctx, h, false)
		var alert *AlertError
		switch {
		case errors.As(err, &alert):
			e.FallbackSCSV = boolPtr(alert.Description == alertInappropriateFallback)
		case err == nil:
			e.FallbackSCSV = boolPtr(false)
		}
	}
	return e
}

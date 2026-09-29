package tlsinspect

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/matusso/sslknife/internal/certificate"
	"github.com/matusso/sslknife/internal/scanner"
)

// Severity levels for scan findings, following common vulnerability
// reporting practice. There is no aggregate score.
const (
	Critical = "critical"
	High     = "high"
	Medium   = "medium"
	Low      = "low"
	Info     = "info"
)

// Finding is one factual scan observation with its rationale.
type Finding struct {
	ID        string `json:"id"`
	Severity  string `json:"severity"`
	What      string `json:"what"`
	Why       string `json:"why"`
	Evidence  string `json:"evidence"`
	Reference string `json:"reference,omitempty"`
}

// SummaryItem is one line of the scan summary table.
type SummaryItem struct {
	Check  string `json:"check"`
	Status string `json:"status"` // PASS, FAIL, WARN, ENABLED, DISABLED, NONE, ...
	Level  string `json:"level"`  // good, warn, bad, info: how to read the status
	Detail string `json:"detail,omitempty"`
}

// ScanOptions control Scan.
type ScanOptions struct {
	Inspect     InspectOptions
	Concurrency int
	SkipCiphers bool
}

// ScanResult is the JSON schema of `tls scan`.
type ScanResult struct {
	Connection *Result                 `json:"connection"`
	Versions   []scanner.VersionResult `json:"versions"`
	Ciphers    []scanner.CipherResult  `json:"ciphers,omitempty"`
	Groups     scanner.GroupResult     `json:"groups"`
	Behaviour  scanner.Extras          `json:"behaviour"`
	Summary    []SummaryItem           `json:"summary"`
	Findings   []Finding               `json:"findings"`
	ScannedAt  time.Time               `json:"scanned_at"`
	Duration   string                  `json:"duration"`
}

// Prober returns a raw-probe scanner bound to this connector.
func (c *Connector) Prober(concurrency int) *scanner.Prober {
	return &scanner.Prober{Dial: c.Dial, ServerName: c.SNI, Timeout: c.opts.Timeout, Concurrency: concurrency}
}

// Scan runs inspection plus version, cipher, group and behaviour probes.
func (c *Connector) Scan(ctx context.Context, o ScanOptions) (*ScanResult, error) {
	start := time.Now()
	res := &ScanResult{ScannedAt: start.UTC().Truncate(time.Second)}
	insp, err := c.Inspect(ctx, o.Inspect)
	if err != nil {
		return nil, err
	}
	res.Connection = insp
	p := c.Prober(o.Concurrency)
	res.Versions = p.Versions(ctx)

	var supported []uint16
	for _, v := range res.Versions {
		if v.Supported && v.ID != scanner.VersionSSL2 {
			supported = append(supported, v.ID)
		}
	}
	if !o.SkipCiphers && len(supported) > 0 {
		res.Ciphers = p.CiphersAll(ctx, supported)
	}
	var minLegacy, maxLegacy uint16
	for _, v := range supported {
		if v <= scanner.VersionTLS12 && v >= scanner.VersionTLS10 {
			if minLegacy == 0 || v < minLegacy {
				minLegacy = v
			}
			maxLegacy = max(maxLegacy, v)
		}
	}
	if slices.Contains(supported, scanner.VersionTLS13) {
		res.Groups.TLS13 = p.Groups13(ctx)
	}
	if maxLegacy != 0 {
		var ecdhe []uint16
		for _, cr := range res.Ciphers {
			if cr.ID == maxLegacy {
				for _, s := range cr.Suites {
					if s.KeyExch == "ECDHE" {
						ecdhe = append(ecdhe, s.ID)
					}
				}
			}
		}
		res.Groups.TLS12 = p.Curves12(ctx, maxLegacy, ecdhe)
	}
	res.Behaviour = p.CheckExtras(ctx, minLegacy, maxLegacy)
	res.Findings = findings(res, o.Inspect)
	res.Summary = summary(res)
	res.Duration = time.Since(start).Round(time.Millisecond).String()
	return res, nil
}

func (r *ScanResult) versionSupported(v uint16) bool {
	for _, x := range r.Versions {
		if x.ID == v {
			return x.Supported
		}
	}
	return false
}

// UniqueSuites returns each accepted suite once, with the versions that accept it.
func (r *ScanResult) UniqueSuites() ([]scanner.AcceptedSuite, map[uint16][]string) {
	var out []scanner.AcceptedSuite
	versions := map[uint16][]string{}
	for i := len(r.Ciphers) - 1; i >= 0; i-- {
		for _, s := range r.Ciphers[i].Suites {
			if _, seen := versions[s.ID]; !seen {
				out = append(out, s)
			}
			versions[s.ID] = append(versions[s.ID], r.Ciphers[i].Version)
		}
	}
	return out, versions
}

// AllSuites returns every accepted suite across versions.
func (r *ScanResult) AllSuites() []scanner.AcceptedSuite {
	var out []scanner.AcceptedSuite
	for _, c := range r.Ciphers {
		out = append(out, c.Suites...)
	}
	return out
}

func findings(r *ScanResult, o InspectOptions) []Finding {
	var f []Finding
	add := func(id, sev, what, why, evidence, ref string) {
		f = append(f, Finding{ID: id, Severity: sev, What: what, Why: why, Evidence: evidence, Reference: ref})
	}
	// Protocol versions.
	if r.versionSupported(scanner.VersionSSL2) {
		add("sslv2", Critical, "SSLv2 is enabled", "SSLv2 is broken and enables DROWN attacks against other protocols sharing the key",
			"server answered an SSLv2 CLIENT-HELLO", "RFC 6176; CVE-2016-0800")
	}
	if r.versionSupported(scanner.VersionSSL3) {
		add("sslv3", High, "SSLv3 is enabled", "SSLv3 CBC padding is exploitable (POODLE) and the protocol is prohibited",
			"server negotiated SSLv3", "RFC 7568; CVE-2014-3566")
	}
	for _, v := range []uint16{scanner.VersionTLS10, scanner.VersionTLS11} {
		if r.versionSupported(v) {
			add("deprecated_"+strings.ReplaceAll(strings.ToLower(scanner.VersionName(v)), " ", ""), Medium,
				scanner.VersionName(v)+" is enabled", "TLS 1.0 and 1.1 are deprecated: SHA-1/MD5 handshake hashes, no AEAD ciphers, and browsers have removed support",
				"server negotiated "+scanner.VersionName(v), "RFC 8996")
		}
	}
	if !r.versionSupported(scanner.VersionTLS12) && !r.versionSupported(scanner.VersionTLS13) {
		add("no_modern_tls", High, "neither TLS 1.2 nor TLS 1.3 is supported", "modern clients refuse older protocol versions",
			"no ServerHello for TLS 1.2 or 1.3", "RFC 8996")
	} else if !r.versionSupported(scanner.VersionTLS13) {
		add("no_tls13", Low, "TLS 1.3 is not supported", "TLS 1.3 removes legacy algorithms and encrypts more of the handshake",
			"no TLS 1.3 ServerHello", "RFC 8446")
	}

	// Cipher suites.
	var insecure, weak, noFS, cbc []string
	fs := 0
	unique, inVersions := r.UniqueSuites()
	label := func(s scanner.AcceptedSuite) string {
		return s.Name + " (" + strings.Join(inVersions[s.ID], ", ") + ")"
	}
	for _, s := range unique {
		switch s.Strength {
		case "insecure":
			insecure = append(insecure, label(s))
		case "weak":
			weak = append(weak, label(s))
		}
		if s.ForwardSecret() {
			fs++
		} else if s.KeyExch != "PSK" {
			noFS = append(noFS, s.Name)
		}
		if s.Mode == "CBC" {
			cbc = append(cbc, s.Name)
		}
	}
	for _, s := range r.AllSuites() {
		if kx := s.KeyExchange; kx != nil && kx.Kind == "DH" {
			switch {
			case kx.Bits < 1024:
				add("dh_"+s.Name, High, fmt.Sprintf("%d-bit Diffie-Hellman group", kx.Bits),
					"DH groups below 1024 bits can be broken with precomputation (Logjam)", s.Name+": "+kx.String(), "RFC 7919; CVE-2015-4000")
			case kx.Bits < 2048:
				add("dh_"+s.Name, Medium, fmt.Sprintf("%d-bit Diffie-Hellman group", kx.Bits),
					"DH groups below 2048 bits are within reach of nation-state precomputation", s.Name+": "+kx.String(), "NIST SP 800-57; RFC 7919")
			}
		}
		if kx := s.KeyExchange; kx != nil && kx.Kind == "ECDH" && kx.Bits > 0 && kx.Bits < 256 {
			add("weak_curve_"+s.Name, Medium, "ECDHE curve "+kx.Group+" below 256 bits",
				"curves below 256 bits provide less than 128-bit security", s.Name+": "+kx.String(), "NIST SP 800-57")
		}
	}
	f = dedupe(f)
	if len(insecure) > 0 {
		add("insecure_ciphers", High, fmt.Sprintf("%d insecure cipher suite(s) accepted", len(insecure)),
			"NULL, anonymous, export, RC4 and DES suites provide no or trivially breakable protection", strings.Join(insecure, ", "), "RFC 7465; RFC 7525")
	}
	if len(weak) > 0 {
		add("weak_ciphers", Medium, fmt.Sprintf("%d weak cipher suite(s) accepted", len(weak)),
			"64-bit block ciphers allow plaintext recovery from long connections (Sweet32)", strings.Join(weak, ", "), "CVE-2016-2183")
	}
	if len(r.Ciphers) > 0 && fs == 0 {
		add("no_forward_secrecy", Medium, "no forward-secret key exchange", "a later compromise of the server key decrypts all recorded traffic",
			"no ECDHE/DHE or TLS 1.3 suites accepted", "RFC 7525 §4.2")
	} else if len(noFS) > 0 {
		add("static_key_exchange", Low, fmt.Sprintf("%d suite(s) without forward secrecy", len(noFS)),
			"static RSA/DH key exchange loses confidentiality if the key leaks and enables ROBOT-style oracles", strings.Join(noFS, ", "), "RFC 7525 §4.2")
	}
	if len(cbc) > 0 {
		add("cbc_ciphers", Low, fmt.Sprintf("%d CBC-mode suite(s) accepted", len(cbc)),
			"MAC-then-encrypt CBC has a history of padding-oracle and timing attacks (Lucky13); AEAD suites avoid them", strings.Join(cbc, ", "), "RFC 7457")
	}
	for _, cr := range r.Ciphers {
		if cr.ServerPreferred != nil && !*cr.ServerPreferred && cr.ID <= scanner.VersionTLS12 {
			worst := false
			for _, s := range cr.Suites {
				if s.Strength != "modern" {
					worst = true
				}
			}
			if worst {
				add("client_cipher_order_"+strings.ReplaceAll(cr.Version, " ", ""), Low, "server follows the client's cipher order in "+cr.Version,
					"with weaker suites enabled, a client that prefers them gets them; servers should enforce their own order", "order depends on ClientHello", "RFC 7525 §4.2")
			}
		}
	}

	// Behaviour.
	b := r.Behaviour
	if b.Compression != nil && *b.Compression {
		add("compression", High, "TLS compression is enabled", "compression leaks secrets via ciphertext length (CRIME)", "server selected DEFLATE", "CVE-2012-4929")
	}
	if b.SecureRenegotiation != nil && !*b.SecureRenegotiation {
		add("insecure_renegotiation", Medium, "secure renegotiation is not supported",
			"without RFC 5746 an attacker can splice plaintext into the start of a session", "no renegotiation_info in ServerHello", "RFC 5746; CVE-2009-3555")
	}
	if b.FallbackSCSV != nil && !*b.FallbackSCSV {
		add("no_fallback_scsv", Low, "TLS_FALLBACK_SCSV is not honoured",
			"clients that retry with lower versions can be downgraded by an active attacker", "no inappropriate_fallback alert", "RFC 7507")
	}

	// Certificate and session.
	c := r.Connection
	if c != nil {
		if !c.Validation.HostnameValid {
			add("hostname_mismatch", High, "certificate does not match "+c.Validation.Hostname,
				"clients reject certificates that do not cover the requested name", "SANs: "+strings.Join(c.Certificate.SANs.All(), ", "), "RFC 6125")
		}
		if !c.Validation.Trusted {
			add("untrusted_chain", High, "certificate chain is not trusted ("+c.Validation.TrustStore+" trust store)",
				"clients using this trust store will reject the connection", c.Validation.Error, "RFC 5280 §6")
		}
		if !c.Validation.ChainOrdered {
			add("chain_order", Low, "certificates are not in issuing order", "RFC 8446 requires each certificate to certify the preceding one; strict clients fail",
				"see chain", "RFC 8446 §4.4.2")
		}
		if o := c.OCSP; o != nil {
			if o.MustStaple && !o.Stapled {
				add("must_staple_missing", High, "certificate requires OCSP stapling but none was sent",
					"clients honouring Must-Staple hard-fail the connection", "TLS Feature status_request, no stapled response", "RFC 7633")
			}
			if o.Status == "revoked" {
				add("revoked", Critical, "stapled OCSP response says the certificate is revoked", "the CA has revoked this certificate",
					"revoked at "+o.RevokedAt.Format(time.RFC3339), "RFC 6960")
			}
			if !o.Stapled && len(o.Responders) > 0 {
				add("no_ocsp_stapling", Info, "OCSP stapling is not enabled",
					"without stapling, clients must query the CA (privacy leak, latency) or skip revocation checks", "no stapled response", "RFC 6066 §8")
			}
		}
		for _, lf := range c.Findings {
			if lf.ID == "hostname_mismatch" || lf.ID == "untrusted_root" || lf.ID == "chain_invalid" {
				continue // reported above
			}
			sev := Info
			switch lf.Severity {
			case certificate.SevError:
				sev = High
			case certificate.SevWarning:
				sev = Medium
			}
			add("cert_"+lf.ID, sev, lf.What+" ("+lf.Certificate+")", lf.Why, lf.Evidence, lf.Reference)
		}
		if v := c.Certificate.Validity; v.Status == "expiring" {
			add("cert_expiring", Medium, fmt.Sprintf("certificate expires in %d days", v.DaysRemaining),
				"renew before expiry to avoid outages", "notAfter="+v.NotAfter.Format(time.RFC3339), "")
		}
	}
	if f == nil {
		f = []Finding{}
	}
	order := map[string]int{Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4}
	slices.SortStableFunc(f, func(a, b Finding) int { return order[a.Severity] - order[b.Severity] })
	return f
}

func dedupe(f []Finding) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for _, x := range f {
		key := x.What + "|" + x.Severity
		if seen[key] {
			for i := range out {
				if out[i].What+"|"+out[i].Severity == key {
					out[i].Evidence += "; " + x.Evidence
				}
			}
			continue
		}
		seen[key] = true
		out = append(out, x)
	}
	return out
}

func summary(r *ScanResult) []SummaryItem {
	var s []SummaryItem
	add := func(check, status, level, detail string) {
		s = append(s, SummaryItem{Check: check, Status: status, Level: level, Detail: detail})
	}
	passFail := func(check string, ok bool, detail string) {
		if ok {
			add(check, "PASS", "good", detail)
		} else {
			add(check, "FAIL", "bad", detail)
		}
	}
	c := r.Connection
	certOK := true
	for _, f := range c.Findings {
		if f.Severity == certificate.SevError && f.ID != "hostname_mismatch" && f.ID != "untrusted_root" &&
			f.ID != "chain_invalid" && f.ID != "missing_intermediate" && f.ID != "expired" {
			certOK = false
		}
	}
	passFail("Certificate", certOK, c.Certificate.PublicKey.Description+", "+c.Certificate.SignatureAlgorithm)
	if c.Validation.Trusted && len(c.Validation.Missing) > 0 {
		add("Certificate Chain", "WARN", "warn", "incomplete: missing "+strings.Join(c.Validation.Missing, ", "))
	} else {
		passFail("Certificate Chain", c.Validation.Trusted, c.Validation.Reason)
	}
	passFail("Hostname", c.Validation.HostnameValid, c.Validation.Hostname)
	exp := c.Certificate.Validity
	expDetail := fmt.Sprintf("%s (%d days)", exp.NotAfter.Format(time.DateOnly), exp.DaysRemaining)
	switch exp.Status {
	case "expired", "not_yet_valid":
		add("Expiration", "FAIL", "bad", expDetail)
	case "expiring":
		add("Expiration", "WARN", "warn", expDetail)
	default:
		add("Expiration", "PASS", "good", expDetail)
	}
	for i := len(r.Versions) - 1; i >= 0; i-- {
		v := r.Versions[i]
		legacy := v.ID < scanner.VersionTLS12
		switch {
		case v.Error != "":
			add(v.Version, "ERROR", "warn", v.Error)
		case v.Supported && legacy:
			add(v.Version, "ENABLED", "bad", "")
		case v.Supported:
			add(v.Version, "ENABLED", "good", "")
		case legacy:
			add(v.Version, "DISABLED", "good", "")
		case v.ID == scanner.VersionTLS13:
			add(v.Version, "DISABLED", "warn", "")
		default:
			add(v.Version, "DISABLED", "info", "")
		}
	}
	weak, fs, total := 0, 0, 0
	unique, _ := r.UniqueSuites()
	for _, x := range unique {
		total++
		if x.Strength == "weak" || x.Strength == "insecure" {
			weak++
		}
		if x.ForwardSecret() {
			fs++
		}
	}
	if len(r.Ciphers) > 0 {
		if weak == 0 {
			add("Weak Ciphers", "NONE", "good", fmt.Sprintf("%d distinct suites accepted", total))
		} else {
			add("Weak Ciphers", fmt.Sprint(weak), "bad", fmt.Sprintf("of %d distinct suites accepted", total))
		}
		detail := fmt.Sprintf("%d of %d suites", fs, total)
		switch {
		case fs == 0:
			add("Forward Secrecy", "NO", "bad", detail)
		case fs < total:
			add("Forward Secrecy", "PARTIAL", "warn", detail)
		default:
			add("Forward Secrecy", "YES", "good", detail)
		}
	}
	if c.OCSP != nil && c.OCSP.Stapled {
		add("OCSP Stapling", "ENABLED", "good", c.OCSP.Status)
	} else {
		add("OCSP Stapling", "DISABLED", "info", "")
	}
	b := r.Behaviour
	if b.SecureRenegotiation != nil {
		if *b.SecureRenegotiation {
			add("Secure Renegotiation", "ENABLED", "good", "")
		} else {
			add("Secure Renegotiation", "DISABLED", "bad", "")
		}
	}
	if b.FallbackSCSV != nil {
		if *b.FallbackSCSV {
			add("Fallback SCSV", "ENABLED", "good", "")
		} else {
			add("Fallback SCSV", "DISABLED", "warn", "")
		}
	}
	if b.Compression != nil {
		if *b.Compression {
			add("TLS Compression", "ENABLED", "bad", "CRIME")
		} else {
			add("TLS Compression", "DISABLED", "good", "")
		}
	}
	if len(r.Groups.TLS13) > 0 {
		add("Key Exchange Groups", fmt.Sprint(len(r.Groups.TLS13)), "info", strings.Join(r.Groups.TLS13, ", "))
	}
	return s
}

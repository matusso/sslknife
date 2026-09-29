package certificate

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"
)

// Severity levels, from most to least serious.
const (
	SevError   = "error"   // violates a MUST in a standard or is exploitable
	SevWarning = "warning" // violates a SHOULD, or will break common clients
	SevNotice  = "notice"  // unusual but not wrong
)

// Finding is one lint result. Every finding explains WHAT is wrong, WHY it
// matters, the EVIDENCE observed, and which standard it comes from.
type Finding struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Certificate string `json:"certificate"` // subject display name
	What        string `json:"what"`
	Why         string `json:"why"`
	Evidence    string `json:"evidence"`
	Reference   string `json:"reference,omitempty"`
}

// LintOptions control Lint.
type LintOptions struct {
	Now      time.Time
	Hostname string // check the leaf matches this name
	// Roots is used for trust checks when CheckTrust is set; nil = system roots.
	Roots      *x509.CertPool
	CheckTrust bool
}

// Lifetime limits for publicly-trusted TLS server certificates
// (CA/Browser Forum Baseline Requirements §6.3.2, ballot SC-081).
var tlsLifetimeLimits = []struct {
	from time.Time
	days int
}{
	{time.Date(2029, 3, 15, 0, 0, 0, 0, time.UTC), 47},
	{time.Date(2027, 3, 15, 0, 0, 0, 0, time.UTC), 100},
	{time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), 200},
	{time.Date(2020, 9, 1, 0, 0, 0, 0, time.UTC), 398},
	{time.Time{}, 825},
}

// MaxTLSLifetimeDays returns the BR lifetime limit for a certificate issued at nb.
func MaxTLSLifetimeDays(nb time.Time) int {
	for _, l := range tlsLifetimeLimits {
		if !nb.Before(l.from) {
			return l.days
		}
	}
	return 825
}

// Lint checks certs. The first certificate is treated as the leaf unless
// the bundle is unordered, in which case the leaf is detected. Chain checks
// run when more than one certificate is supplied or CheckTrust is set.
func Lint(certs []*x509.Certificate, opts LintOptions) []Finding {
	if len(certs) == 0 {
		return nil
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	var out []Finding
	for _, c := range certs {
		out = append(out, lintOne(c, now)...)
	}
	leaf := FindLeaf(certs)
	if opts.Hostname != "" {
		if err := leaf.VerifyHostname(opts.Hostname); err != nil {
			out = append(out, finding("hostname_mismatch", SevError, leaf,
				fmt.Sprintf("certificate is not valid for %q", opts.Hostname),
				"clients compare the requested hostname with the DNS and IP SANs and reject the connection on mismatch",
				"SANs: "+strings.Join(CertSANs(leaf).All(), ", "), "RFC 6125 §6"))
		}
	}
	if len(certs) > 1 || opts.CheckTrust {
		out = append(out, lintChain(certs, leaf, now, opts)...)
	}
	return out
}

func finding(id, sev string, c *x509.Certificate, what, why, evidence, ref string) Finding {
	return Finding{ID: id, Severity: sev, Certificate: NewName(c.Subject).DisplayName(), What: what, Why: why, Evidence: evidence, Reference: ref}
}

func isLeafTLSServer(c *x509.Certificate) bool {
	if c.IsCA {
		return false
	}
	if len(c.ExtKeyUsage) == 0 && len(c.UnknownExtKeyUsage) == 0 {
		return len(c.DNSNames)+len(c.IPAddresses) > 0
	}
	return slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
}

func lintOne(c *x509.Certificate, now time.Time) []Finding {
	var f []Finding
	add := func(id, sev, what, why, evidence, ref string) {
		f = append(f, finding(id, sev, c, what, why, evidence, ref))
	}
	selfSigned := IsSelfSigned(c)
	validity := fmt.Sprintf("notBefore=%s notAfter=%s", c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339))

	// Validity.
	if now.After(c.NotAfter) {
		add("expired", SevError, "certificate has expired",
			"relying parties reject certificates outside their validity period", validity, "RFC 5280 §4.1.2.5")
	}
	if now.Before(c.NotBefore) {
		add("not_yet_valid", SevError, "certificate is not yet valid",
			"relying parties reject certificates before notBefore; this often indicates clock skew at issuance", validity, "RFC 5280 §4.1.2.5")
	}
	if !c.NotAfter.After(c.NotBefore) {
		add("invalid_validity", SevError, "notAfter is not after notBefore", "the certificate can never be valid", validity, "RFC 5280 §4.1.2.5")
	}
	if isLeafTLSServer(c) && !selfSigned {
		days := int(c.NotAfter.Sub(c.NotBefore).Hours() / 24)
		if limit := MaxTLSLifetimeDays(c.NotBefore); days > limit {
			add("excessive_lifetime", SevWarning, fmt.Sprintf("validity of %d days exceeds %d days", days, limit),
				"publicly-trusted TLS certificates issued on this date may not exceed this lifetime; browsers reject longer ones. Private PKIs may choose otherwise",
				validity, "CA/B Forum BR §6.3.2")
		}
	}

	// Version and serial.
	if c.Version != 3 {
		add("not_v3", SevWarning, fmt.Sprintf("X.509 version %d", c.Version),
			"extensions such as SAN and basicConstraints require v3; v1 CA certificates are ambiguous about being a CA", fmt.Sprintf("version=%d", c.Version), "RFC 5280 §4.1.2.1")
	}
	if c.SerialNumber != nil {
		if c.SerialNumber.Sign() <= 0 {
			add("serial_not_positive", SevError, "serial number is zero or negative",
				"serial numbers MUST be positive integers", "serial="+c.SerialNumber.String(), "RFC 5280 §4.1.2.2")
		}
		if n := len(c.SerialNumber.Bytes()); n > 20 {
			add("serial_too_long", SevError, "serial number longer than 20 octets",
				"conforming implementations need not handle longer serials", fmt.Sprintf("%d octets", n), "RFC 5280 §4.1.2.2")
		} else if n < 8 && !selfSigned {
			add("serial_low_entropy", SevNotice, "serial number shorter than 64 bits",
				"CAs must include at least 64 bits of CSPRNG output to make chosen-prefix collision attacks impractical", fmt.Sprintf("%d octets", n), "CA/B Forum BR §7.1")
		}
	}

	// Signature.
	switch SignatureStrength(c.SignatureAlgorithm) {
	case "insecure":
		add("signature_broken", SevError, "signature uses "+c.SignatureAlgorithm.String(),
			"MD2/MD5 collisions allow forging certificates (e.g. the 2008 rogue CA attack)", "signatureAlgorithm="+c.SignatureAlgorithm.String(), "RFC 6151")
	case "deprecated":
		sev, why := SevError, "SHA-1 chosen-prefix collisions are practical (SHAmbles, 2020); clients reject SHA-1 signed certificates"
		if selfSigned {
			sev, why = SevNotice, "a self-signed root's own signature is not relied upon, but SHA-1 signatures are still flagged by some tools"
		}
		add("signature_deprecated", sev, "signature uses "+c.SignatureAlgorithm.String(), why, "signatureAlgorithm="+c.SignatureAlgorithm.String(), "CA/B Forum BR §7.1.3.2")
	}

	// Public key.
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		if bits < 2048 {
			add("rsa_weak", SevError, fmt.Sprintf("RSA key is %d bits", bits),
				"RSA below 2048 bits offers under 112 bits of security and is disallowed", fmt.Sprintf("modulus=%d bits", bits), "NIST SP 800-131A; CA/B BR §6.1.5")
		} else if bits%8 != 0 {
			add("rsa_odd_size", SevNotice, fmt.Sprintf("RSA modulus of %d bits is not a multiple of 8", bits),
				"CA/B Forum requires moduli divisible by 8; odd sizes suggest a generation bug", fmt.Sprintf("modulus=%d bits", bits), "CA/B BR §6.1.5")
		}
		if k.E != 65537 {
			add("rsa_exponent", SevNotice, fmt.Sprintf("RSA public exponent is %d", k.E),
				"65537 is the standard exponent; small exponents amplify padding weaknesses", fmt.Sprintf("e=%d", k.E), "CA/B BR §6.1.6")
		}
	case *ecdsa.PublicKey:
		name := k.Curve.Params().Name
		if name != "P-256" && name != "P-384" && name != "P-521" {
			add("ec_curve", SevWarning, "ECDSA curve "+name+" is not widely supported",
				"TLS clients and the CA/B Forum accept only P-256, P-384 and P-521", "curve="+name, "CA/B BR §6.1.5")
		}
	}

	// Critical extensions not understood.
	for _, oid := range c.UnhandledCriticalExtensions {
		add("unknown_critical_extension", SevError, "unrecognised critical extension "+oid.String(),
			"a relying party MUST reject a certificate with a critical extension it does not recognise", "oid="+oid.String(), "RFC 5280 §4.2")
	}

	// Basic constraints and key usage.
	certSign := c.KeyUsage&x509.KeyUsageCertSign != 0
	isCA := c.BasicConstraintsValid && c.IsCA
	bcCritical := false
	for _, e := range c.Extensions {
		if e.Id.Equal(oidBasicCons) {
			bcCritical = e.Critical
		}
	}
	if certSign && !isCA {
		add("certsign_without_ca", SevError, "keyCertSign is set but basicConstraints CA is not TRUE",
			"keyCertSign MUST only be asserted by CA certificates; clients will not accept the certificate as an issuer", "keyUsage="+strings.Join(KeyUsageNames(c.KeyUsage), ","), "RFC 5280 §4.2.1.3")
	}
	if isCA {
		if !bcCritical {
			add("ca_basic_constraints_not_critical", SevWarning, "basicConstraints is not critical in a CA certificate",
				"CA certificates used to validate signatures MUST mark basicConstraints critical", "critical=false", "RFC 5280 §4.2.1.9")
		}
		if c.KeyUsage == 0 {
			add("ca_missing_key_usage", SevError, "CA certificate has no keyUsage extension",
				"conforming CAs MUST include keyUsage in certificates that sign other certificates or CRLs", "keyUsage absent", "RFC 5280 §4.2.1.3")
		} else if !certSign {
			add("ca_without_certsign", SevError, "CA certificate lacks keyCertSign",
				"without keyCertSign the key may not verify certificate signatures", "keyUsage="+strings.Join(KeyUsageNames(c.KeyUsage), ","), "RFC 5280 §4.2.1.3")
		}
		if len(c.SubjectKeyId) == 0 {
			add("ca_missing_ski", SevWarning, "CA certificate has no Subject Key Identifier",
				"SKI MUST appear in CA certificates to support path building", "subjectKeyIdentifier absent", "RFC 5280 §4.2.1.2")
		}
		if slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageAny) {
			add("ca_any_eku", SevNotice, "CA certificate asserts anyExtendedKeyUsage",
				"subordinate CAs should restrict their EKUs to the purposes they are trusted for", "EKU=Any", "CA/B BR §7.1.2.2")
		}
	} else {
		if c.BasicConstraintsValid && (c.MaxPathLen > 0 || c.MaxPathLenZero) {
			add("pathlen_on_leaf", SevError, "pathLenConstraint present on a non-CA certificate",
				"CAs MUST NOT include pathLenConstraint unless cA is TRUE", fmt.Sprintf("pathLen=%d", c.MaxPathLen), "RFC 5280 §4.2.1.9")
		}
		if !c.BasicConstraintsValid && c.Version == 1 && selfSigned {
			add("v1_ca", SevWarning, "self-signed v1 certificate is implicitly treated as a CA by some software",
				"v1 certificates cannot express CA status, which confuses validators", "version=1", "RFC 5280 §6.1.4")
		}
		switch c.PublicKey.(type) {
		case *ecdsa.PublicKey, ed25519.PublicKey:
			if c.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
				add("keyencipherment_non_rsa", SevWarning, "keyEncipherment set on a non-RSA key",
					"key transport is only defined for RSA; some TLS stacks reject ECDSA certificates asserting it", "keyUsage="+strings.Join(KeyUsageNames(c.KeyUsage), ","), "RFC 8813 §3")
			}
		}
		if len(c.ExtKeyUsage) == 0 && len(c.UnknownExtKeyUsage) == 0 && !selfSigned {
			add("leaf_no_eku", SevNotice, "end-entity certificate has no extendedKeyUsage",
				"without EKU the key is usable for any purpose; the BRs require serverAuth/clientAuth for TLS", "extendedKeyUsage absent", "CA/B BR §7.1.2.7.10")
		}
		if slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageAny) {
			add("leaf_any_eku", SevWarning, "end-entity certificate asserts anyExtendedKeyUsage",
				"the key can be used for any purpose including code signing", "EKU=Any", "RFC 5280 §4.2.1.12")
		}
		if selfSigned {
			add("self_signed_leaf", SevNotice, "end-entity certificate is self-signed",
				"no client trusts it unless explicitly pinned or installed", "subject == issuer, signature verifies with own key", "")
		}
	}
	if !selfSigned && len(c.AuthorityKeyId) == 0 {
		add("missing_aki", SevWarning, "Authority Key Identifier is missing",
			"AKI MUST be present in all non-self-signed certificates to support path building", "authorityKeyIdentifier absent", "RFC 5280 §4.2.1.1")
	}

	// SANs.
	if isLeafTLSServer(c) || (!isCA && c.Subject.CommonName != "" && len(c.DNSNames) > 0) {
		f = append(f, lintSANs(c)...)
	}
	return f
}

func lintSANs(c *x509.Certificate) []Finding {
	var f []Finding
	add := func(id, sev, what, why, evidence, ref string) {
		f = append(f, finding(id, sev, c, what, why, evidence, ref))
	}
	if len(c.DNSNames)+len(c.IPAddresses) == 0 {
		add("no_san", SevError, "TLS server certificate has no DNS or IP SAN",
			"browsers and most TLS libraries ignore the Common Name and only match SANs", "CN="+c.Subject.CommonName, "RFC 6125 §6.4.4; CA/B BR §7.1.2.7.12")
		return f
	}
	if cn := c.Subject.CommonName; cn != "" {
		inSAN := slices.ContainsFunc(c.DNSNames, func(d string) bool { return strings.EqualFold(d, cn) })
		for _, ip := range c.IPAddresses {
			if ip.String() == cn {
				inSAN = true
			}
		}
		if !inSAN && (net.ParseIP(cn) != nil || strings.Contains(cn, ".")) {
			add("cn_not_in_san", SevWarning, "Common Name is not repeated in the SANs",
				"if a CN is present it must match one of the SAN entries", "CN="+cn, "CA/B BR §7.1.4.3")
		}
	}
	seen := map[string]bool{}
	for _, d := range c.DNSNames {
		ld := strings.ToLower(d)
		if seen[ld] {
			add("duplicate_san", SevNotice, "duplicate DNS SAN "+d, "duplicates waste space and suggest a tooling bug", "dNSName="+d, "")
		}
		seen[ld] = true
		if net.ParseIP(d) != nil {
			add("ip_in_dns_san", SevError, "IP address encoded as a DNS SAN",
				"IP addresses must use the iPAddress SAN type; clients will not match them as DNS names", "dNSName="+d, "RFC 5280 §4.2.1.6")
			continue
		}
		if strings.Count(d, "*") > 1 || (strings.Contains(d, "*") && !strings.HasPrefix(d, "*.")) {
			add("bad_wildcard", SevError, "wildcard not confined to the whole left-most label",
				"clients only support a single '*' as the complete left-most label", "dNSName="+d, "RFC 6125 §6.4.3; CA/B BR §7.1.2.7.12")
			continue
		}
		if strings.HasPrefix(d, "*.") && strings.Count(d, ".") < 2 {
			add("wildcard_too_broad", SevError, "wildcard directly below a top-level domain",
				"a wildcard for a whole TLD or public suffix is never valid", "dNSName="+d, "CA/B BR §3.2.2.6")
		}
		if d != ld {
			add("uppercase_san", SevNotice, "DNS SAN contains upper-case characters",
				"DNS names are case-insensitive but should be encoded in lower case", "dNSName="+d, "")
		}
		if strings.HasSuffix(d, ".") {
			add("trailing_dot_san", SevWarning, "DNS SAN ends with a dot",
				"fully-qualified trailing dots are not allowed in dNSName", "dNSName="+d, "RFC 5280 §4.2.1.6")
		}
		if ValidateDNSName(strings.TrimSuffix(ld, ".")) != nil {
			add("invalid_dns_san", SevError, "DNS SAN is not a valid hostname",
				"dNSName must follow preferred name syntax (letters, digits, hyphens)", "dNSName="+d, "RFC 5280 §4.2.1.6; RFC 1034 §3.5")
		} else if strings.Contains(d, "_") {
			add("underscore_san", SevWarning, "DNS SAN contains an underscore",
				"underscores are not valid in hostnames and are prohibited in publicly-trusted certificates", "dNSName="+d, "CA/B Ballot SC-12")
		}
		if strings.HasSuffix(ld, ".local") || strings.HasSuffix(ld, ".internal") || strings.HasSuffix(ld, ".lan") || !strings.Contains(ld, ".") {
			add("internal_name", SevNotice, "DNS SAN is an internal name",
				"publicly-trusted CAs may not issue for internal names; fine for private PKI", "dNSName="+d, "CA/B BR §7.1.2.7.12")
		}
	}
	for _, ip := range c.IPAddresses {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			add("reserved_ip_san", SevNotice, "IP SAN "+ip.String()+" is private or reserved",
				"publicly-trusted CAs may not issue for reserved addresses; fine for private PKI", "iPAddress="+ip.String(), "CA/B BR §7.1.2.7.12")
		}
	}
	return f
}

func lintChain(certs []*x509.Certificate, leaf *x509.Certificate, now time.Time, opts LintOptions) []Finding {
	var f []Finding
	// Order as supplied: each certificate should be issued by the next.
	if certs[0] != leaf {
		f = append(f, finding("leaf_not_first", SevWarning, leaf, "the end-entity certificate is not first",
			"TLS requires the sender's certificate first; many clients do not reorder", fmt.Sprintf("leaf is certificate #%d", slices.Index(certs, leaf)+1), "RFC 8446 §4.4.2"))
	}
	for i := 0; i+1 < len(certs); i++ {
		if !Issues(certs[i+1], certs[i]) && !IsSelfSigned(certs[i]) {
			f = append(f, finding("chain_misordered", SevWarning, certs[i], "next certificate in the bundle did not issue this one",
				"each certificate should directly certify the one preceding it; out-of-order chains break older clients",
				fmt.Sprintf("#%d issuer=%q, #%d subject=%q", i+1, certs[i].Issuer.String(), i+2, certs[i+1].Subject.String()), "RFC 5246 §7.4.2"))
		}
	}
	seen := map[string]bool{}
	for i, c := range certs {
		if seen[string(c.Raw)] {
			f = append(f, finding("duplicate_certificate", SevNotice, c, "certificate appears more than once",
				"duplicates increase handshake size without benefit", fmt.Sprintf("position #%d", i+1), ""))
		}
		seen[string(c.Raw)] = true
	}
	ordered := Order(leaf, certs)
	for _, c := range ordered[1:] {
		if !c.IsCA || !c.BasicConstraintsValid {
			f = append(f, finding("issuer_not_ca", SevError, c, "an issuer in the chain is not a CA",
				"only certificates with basicConstraints CA:TRUE may issue certificates", "basicConstraints CA=false or absent", "RFC 5280 §6.1.4 (k)"))
		}
		if now.After(c.NotAfter) {
			f = append(f, finding("issuer_expired", SevError, c, "an issuer in the chain has expired",
				"every certificate on the path must be within its validity period", "notAfter="+c.NotAfter.UTC().Format(time.RFC3339), "RFC 5280 §6.1.3"))
		}
	}
	top := ordered[len(ordered)-1]
	if IsSelfSigned(top) && len(ordered) > 1 {
		f = append(f, finding("root_included", SevNotice, top, "the chain includes the self-signed root",
			"clients use their own trust store copy; sending the root only adds bytes", "subject == issuer", "RFC 8446 §4.4.2"))
	}
	if !IsSelfSigned(top) {
		trustedIssuer := false
		if opts.CheckTrust {
			res := Verify(leaf, VerifyOptions{Roots: opts.Roots, Intermediates: certs, Now: now})
			trustedIssuer = (res.Trusted && len(res.Missing) == 0) || (!res.Trusted && res.Reason != "unknown_authority")
			if res.Trusted && len(res.Missing) > 0 {
				f = append(f, finding("missing_intermediate", SevWarning, top, "chain is incomplete",
					"the verifier had to fetch or supply the missing issuer itself; clients that do not (most non-browser TLS stacks) will fail",
					"not sent by the server: "+strings.Join(res.Missing, ", "), "RFC 8446 §4.4.2"))
				trustedIssuer = true
			}
		}
		if !trustedIssuer {
			evidence := "no certificate for issuer " + top.Issuer.String()
			if len(top.IssuingCertificateURL) > 0 {
				evidence += " (AIA caIssuers: " + strings.Join(top.IssuingCertificateURL, ", ") + ")"
			}
			sev := SevWarning
			if opts.CheckTrust {
				sev = SevError
			}
			f = append(f, finding("missing_intermediate", sev, top, "chain is incomplete",
				"clients without the missing issuer cached cannot build a path to a trusted root", evidence, "RFC 5280 §6"))
		}
	}
	if opts.CheckTrust {
		res := Verify(leaf, VerifyOptions{Roots: opts.Roots, Intermediates: certs, Now: now})
		if !res.Trusted && res.Reason != "unknown_authority" && res.Reason != "expired" {
			f = append(f, finding("chain_invalid", SevError, leaf, "chain validation failed",
				"the certificate would be rejected by standard path validation", res.Error, "RFC 5280 §6"))
		} else if !res.Trusted && res.Reason == "unknown_authority" && IsSelfSigned(top) {
			f = append(f, finding("untrusted_root", SevError, top, "chain ends at a root that is not in the trust store",
				"clients only accept chains that terminate at a root they trust", "root="+top.Subject.String(), "RFC 5280 §6.1"))
		}
	}
	return f
}

// HasErrors reports whether any finding has error severity.
func HasErrors(f []Finding) bool {
	return slices.ContainsFunc(f, func(x Finding) bool { return x.Severity == SevError })
}

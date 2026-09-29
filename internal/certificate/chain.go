package certificate

import (
	"bytes"
	"crypto/x509"
	"errors"
	"time"
)

// Issues reports whether parent signed child: names chain, key identifiers
// agree when present, and the signature verifies.
func Issues(parent, child *x509.Certificate) bool {
	if !bytes.Equal(parent.RawSubject, child.RawIssuer) {
		return false
	}
	if len(child.AuthorityKeyId) > 0 && len(parent.SubjectKeyId) > 0 &&
		!bytes.Equal(child.AuthorityKeyId, parent.SubjectKeyId) {
		return false
	}
	return child.CheckSignatureFrom(parent) == nil ||
		// CheckSignatureFrom rejects non-CA parents; still report the
		// relationship for self-issued or malformed chains.
		parent.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature) == nil
}

// FindLeaf picks the end-entity certificate from an unordered bundle: the
// certificate that issued no other certificate in the set. Ties go to the
// first such certificate.
func FindLeaf(certs []*x509.Certificate) *x509.Certificate {
	if len(certs) == 0 {
		return nil
	}
	for _, c := range certs {
		issuedOther := false
		for _, o := range certs {
			if o != c && !IsSelfSigned(o) && Issues(c, o) {
				issuedOther = true
				break
			}
		}
		if !issuedOther {
			return c
		}
	}
	return certs[0]
}

// Order returns the path from leaf towards the root using certificates from
// pool, stopping at a self-signed certificate or when no issuer is found.
func Order(leaf *x509.Certificate, pool []*x509.Certificate) []*x509.Certificate {
	chain := []*x509.Certificate{leaf}
	seen := map[string]bool{string(leaf.Raw): true}
	cur := leaf
	for len(chain) < 16 && !IsSelfSigned(cur) {
		var next *x509.Certificate
		for _, c := range pool {
			if !seen[string(c.Raw)] && Issues(c, cur) {
				next = c
				break
			}
		}
		if next == nil {
			break
		}
		chain = append(chain, next)
		seen[string(next.Raw)] = true
		cur = next
	}
	return chain
}

// VerifyOptions control Verify.
type VerifyOptions struct {
	Roots         *x509.CertPool // nil: system roots
	Intermediates []*x509.Certificate
	Hostname      string
	Now           time.Time
	// KeyUsages defaults to any; TLS callers pass ServerAuth.
	KeyUsages []x509.ExtKeyUsage
}

// VerifyResult summarises chain validation.
type VerifyResult struct {
	Trusted bool `json:"trusted"`
	// Missing lists intermediates the verifier had to supply itself (for
	// example fetched via AIA by the macOS or Windows platform verifier):
	// the presented chain is incomplete even though validation succeeded.
	Missing []string `json:"missing_intermediates,omitempty"`
	Chain   []string `json:"chain,omitempty"` // subjects, leaf first, of the first verified chain
	Error   string   `json:"error,omitempty"`
	Reason  string   `json:"reason,omitempty"` // expired, unknown_authority, hostname_mismatch, invalid, ...
}

// Verify validates leaf against the trust store.
func Verify(leaf *x509.Certificate, opts VerifyOptions) VerifyResult {
	inter := x509.NewCertPool()
	for _, c := range opts.Intermediates {
		inter.AddCert(c)
	}
	usages := opts.KeyUsages
	if usages == nil {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots: opts.Roots, Intermediates: inter, DNSName: opts.Hostname, CurrentTime: opts.Now, KeyUsages: usages,
	})
	if err != nil {
		return VerifyResult{Error: err.Error(), Reason: verifyReason(err)}
	}
	res := VerifyResult{Trusted: true}
	presented := map[string]bool{string(leaf.Raw): true}
	for _, c := range opts.Intermediates {
		presented[string(c.Raw)] = true
	}
	chain := chains[0]
	for i, c := range chain {
		res.Chain = append(res.Chain, NewName(c.Subject).DisplayName())
		if i > 0 && i < len(chain)-1 && !presented[string(c.Raw)] {
			res.Missing = append(res.Missing, NewName(c.Subject).DisplayName())
		}
	}
	return res
}

func verifyReason(err error) string {
	var hn x509.HostnameError
	var ua x509.UnknownAuthorityError
	var ci x509.CertificateInvalidError
	switch {
	case errors.As(err, &hn):
		return "hostname_mismatch"
	case errors.As(err, &ua):
		return "unknown_authority"
	case errors.As(err, &ci):
		switch ci.Reason {
		case x509.Expired:
			return "expired"
		case x509.IncompatibleUsage:
			return "incompatible_usage"
		case x509.NameConstraintsWithoutSANs, x509.CANotAuthorizedForThisName:
			return "name_constraints"
		case x509.NotAuthorizedToSign:
			return "not_authorized_to_sign"
		case x509.TooManyIntermediates:
			return "path_length"
		}
		return "invalid"
	}
	var sys x509.SystemRootsError
	if errors.As(err, &sys) {
		return "no_system_roots"
	}
	return "error"
}

// LoadPool builds a CertPool from PEM/DER data.
func LoadPool(data []byte) (*x509.CertPool, []*x509.Certificate, error) {
	certs, err := Parse(data)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool, certs, nil
}

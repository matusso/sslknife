package certificate

import (
	"crypto/sha1" //nolint:gosec // SHA-1 fingerprints are shown as a legacy identifier only
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
)

// Fingerprints are hashes identifying a certificate. SHA-1 is included for
// compatibility with tools that still display it; it is a legacy
// identifier, not a security mechanism.
type Fingerprints struct {
	SHA256     string `json:"sha256"`
	SHA1       string `json:"sha1"`
	SPKISHA256 string `json:"spki_sha256"`
}

// Fingerprint computes the fingerprints of c as lowercase hex.
func Fingerprint(c *x509.Certificate) Fingerprints {
	s256 := sha256.Sum256(c.Raw)
	s1 := sha1.Sum(c.Raw) //nolint:gosec // legacy identifier only
	spki := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return Fingerprints{
		SHA256:     hex.EncodeToString(s256[:]),
		SHA1:       hex.EncodeToString(s1[:]),
		SPKISHA256: hex.EncodeToString(spki[:]),
	}
}

// Colon formats hex as upper-case colon-separated octets (AB:CD:...).
func Colon(h string) string {
	h = strings.ToUpper(h)
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i:min(i+2, len(h))])
	}
	return b.String()
}

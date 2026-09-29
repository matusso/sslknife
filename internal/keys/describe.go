// Package keys parses, generates, describes and compares private and public
// keys in the formats SSLKnife supports.
package keys

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
)

// PublicKeyInfo is the stable, serialisable description of a public key.
type PublicKeyInfo struct {
	Algorithm   string   `json:"algorithm"`       // RSA, ECDSA, Ed25519, ML-DSA, X25519, DSA
	Bits        int      `json:"bits"`            // modulus or curve size
	Curve       string   `json:"curve,omitempty"` // P-256, ...
	Parameters  string   `json:"parameters,omitempty"`
	Exponent    int      `json:"exponent,omitempty"` // RSA public exponent
	Description string   `json:"description"`        // e.g. "ECDSA P-256"
	SPKISHA256  string   `json:"spki_sha256"`
	Strength    string   `json:"strength"` // modern, acceptable, weak, insecure
	Notes       []string `json:"notes,omitempty"`
}

// SPKI returns the DER SubjectPublicKeyInfo of pub.
func SPKI(pub crypto.PublicKey) ([]byte, error) { return x509.MarshalPKIXPublicKey(pub) }

// SPKIFingerprint returns the lowercase hex SHA-256 of the SPKI.
func SPKIFingerprint(spki []byte) string {
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}

// Describe returns a description of pub. Unsupported key types produce an
// "unknown" description rather than an error so certificates carrying them
// can still be inspected.
func Describe(pub crypto.PublicKey) PublicKeyInfo {
	var info PublicKeyInfo
	if spki, err := SPKI(pub); err == nil {
		info.SPKISHA256 = SPKIFingerprint(spki)
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		info.Algorithm = "RSA"
		info.Bits = k.N.BitLen()
		info.Exponent = k.E
		info.Description = fmt.Sprintf("RSA %d", info.Bits)
		switch {
		case info.Bits < 1024:
			info.Strength = "insecure"
			info.Notes = append(info.Notes, "RSA keys below 1024 bits can be factored with modest resources")
		case info.Bits < 2048:
			info.Strength = "weak"
			info.Notes = append(info.Notes, "RSA keys below 2048 bits are disallowed by NIST SP 800-131A and the CA/B Forum")
		case info.Bits < 3072:
			info.Strength = "acceptable"
		default:
			info.Strength = "modern"
		}
		if k.E == 3 {
			info.Notes = append(info.Notes, "public exponent 3 is fragile under poor padding; 65537 is standard")
		}
	case *ecdsa.PublicKey:
		info.Algorithm = "ECDSA"
		info.Curve = k.Curve.Params().Name
		info.Bits = k.Curve.Params().BitSize
		info.Description = "ECDSA " + info.Curve
		info.Strength = "modern"
		if info.Bits < 256 {
			info.Strength = "weak"
			info.Notes = append(info.Notes, "curves below 256 bits are not accepted by modern TLS clients")
		}
	case ed25519.PublicKey:
		info.Algorithm, info.Bits, info.Description, info.Strength = "Ed25519", 256, "Ed25519", "modern"
	case *mldsa.PublicKey:
		name := k.Parameters().String()
		info.Algorithm, info.Parameters, info.Description, info.Strength = "ML-DSA", name, name, "modern"
		info.Bits = len(k.Bytes()) * 8
		info.Notes = append(info.Notes, "post-quantum signature scheme (FIPS 204); client support is still limited")
	case *ecdh.PublicKey:
		info.Algorithm, info.Bits, info.Description, info.Strength = "X25519", 256, "X25519", "modern"
	default:
		info.Algorithm, info.Description, info.Strength = "unknown", fmt.Sprintf("%T", pub), "unknown"
		if s := fmt.Sprintf("%T", pub); strings.Contains(s, "dsa.PublicKey") {
			info.Algorithm, info.Description, info.Strength = "DSA", "DSA", "insecure"
		}
	}
	return info
}

// Public returns the public half of a private key.
func Public(priv crypto.PrivateKey) (crypto.PublicKey, error) {
	switch k := priv.(type) {
	case crypto.Signer:
		return k.Public(), nil
	case *ecdh.PrivateKey:
		return k.PublicKey(), nil
	}
	return nil, fmt.Errorf("unsupported private key type %T", priv)
}

// Equal reports whether two public keys are identical.
func Equal(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if e, ok := a.(equaler); ok {
		return e.Equal(b)
	}
	return false
}

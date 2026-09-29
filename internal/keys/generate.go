package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
)

// Algorithm identifies a key type and size that SSLKnife can generate.
type Algorithm string

const (
	Ed25519   Algorithm = "ed25519"
	ECDSAP256 Algorithm = "ecdsa-p256"
	ECDSAP384 Algorithm = "ecdsa-p384"
	ECDSAP521 Algorithm = "ecdsa-p521"
	RSA2048   Algorithm = "rsa-2048"
	RSA3072   Algorithm = "rsa-3072"
	RSA4096   Algorithm = "rsa-4096"
	MLDSA44   Algorithm = "ml-dsa-44"
	MLDSA65   Algorithm = "ml-dsa-65"
	MLDSA87   Algorithm = "ml-dsa-87"
)

// Algorithms lists generatable algorithms in the order shown to users.
var Algorithms = []Algorithm{ECDSAP256, ECDSAP384, ECDSAP521, Ed25519, RSA2048, RSA3072, RSA4096, MLDSA44, MLDSA65, MLDSA87}

// Label returns a human-readable algorithm name.
func (a Algorithm) Label() string {
	switch a {
	case Ed25519:
		return "Ed25519"
	case ECDSAP256:
		return "ECDSA P-256"
	case ECDSAP384:
		return "ECDSA P-384"
	case ECDSAP521:
		return "ECDSA P-521"
	case RSA2048:
		return "RSA 2048"
	case RSA3072:
		return "RSA 3072"
	case RSA4096:
		return "RSA 4096"
	case MLDSA44:
		return "ML-DSA-44"
	case MLDSA65:
		return "ML-DSA-65"
	case MLDSA87:
		return "ML-DSA-87"
	}
	return string(a)
}

// ParseAlgorithm accepts common spellings: "ed25519", "ecdsa", "p256",
// "ec-384", "rsa", "rsa4096", "RSA 3072", "mldsa65", ...
func ParseAlgorithm(s string) (Algorithm, error) {
	n := strings.ToLower(strings.TrimSpace(s))
	n = strings.NewReplacer(" ", "", "-", "", "_", "").Replace(n)
	switch n {
	case "ed25519", "eddsa":
		return Ed25519, nil
	case "ecdsa", "ec", "p256", "ecdsap256", "ec256", "ecp256", "prime256v1", "secp256r1":
		return ECDSAP256, nil
	case "p384", "ecdsap384", "ec384", "ecp384", "secp384r1":
		return ECDSAP384, nil
	case "p521", "ecdsap521", "ec521", "ecp521", "secp521r1":
		return ECDSAP521, nil
	case "rsa2048":
		return RSA2048, nil
	case "rsa", "rsa3072":
		return RSA3072, nil
	case "rsa4096":
		return RSA4096, nil
	case "mldsa44":
		return MLDSA44, nil
	case "mldsa", "mldsa65":
		return MLDSA65, nil
	case "mldsa87":
		return MLDSA87, nil
	case "rsa1024", "rsa512":
		return "", fmt.Errorf("refusing to generate %s: RSA keys below 2048 bits are insecure", s)
	}
	return "", fmt.Errorf("unknown key algorithm %q (supported: %s)", s, algorithmList())
}

func algorithmList() string {
	names := make([]string, len(Algorithms))
	for i, a := range Algorithms {
		names[i] = string(a)
	}
	return strings.Join(names, ", ")
}

// Generate creates a new private key using crypto/rand.
func Generate(a Algorithm) (crypto.Signer, error) {
	switch a {
	case Ed25519:
		_, k, err := ed25519.GenerateKey(rand.Reader)
		return k, err
	case ECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case ECDSAP521:
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case RSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case RSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	case RSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case MLDSA44:
		return mldsa.GenerateKey(mldsa.MLDSA44())
	case MLDSA65:
		return mldsa.GenerateKey(mldsa.MLDSA65())
	case MLDSA87:
		return mldsa.GenerateKey(mldsa.MLDSA87())
	}
	return nil, fmt.Errorf("unsupported algorithm %q", a)
}

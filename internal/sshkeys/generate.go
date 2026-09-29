package sshkeys

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/matusso/sslknife/internal/keys"
)

// Algorithms usable for SSH keys, in the order offered to users.
var Algorithms = []keys.Algorithm{keys.Ed25519, keys.ECDSAP256, keys.ECDSAP384, keys.ECDSAP521, keys.RSA3072, keys.RSA4096}

// ParseAlgorithm accepts ed25519, ecdsa[-p256|-p384|-p521], rsa[-3072|-4096].
func ParseAlgorithm(s string) (keys.Algorithm, error) {
	if s == "" {
		return keys.Ed25519, nil
	}
	a, err := keys.ParseAlgorithm(s)
	if err != nil {
		return "", err
	}
	for _, x := range Algorithms {
		if x == a {
			return a, nil
		}
	}
	return "", fmt.Errorf("%s keys are not supported by OpenSSH (use ed25519, ecdsa or rsa)", a.Label())
}

// Generate creates a key pair and returns the OpenSSH private key PEM
// (encrypted when passphrase is set) and the authorized_keys line.
func Generate(a keys.Algorithm, comment string, passphrase []byte) (crypto.Signer, []byte, []byte, error) {
	k, err := keys.Generate(a)
	if err != nil {
		return nil, nil, nil, err
	}
	priv, pub, err := Marshal(k, comment, passphrase)
	return k, priv, pub, err
}

// Marshal encodes a private key in OpenSSH format plus its public line.
func Marshal(k crypto.PrivateKey, comment string, passphrase []byte) ([]byte, []byte, error) {
	var block *pem.Block
	var err error
	if len(passphrase) > 0 {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(k, comment, passphrase)
	} else {
		block, err = ssh.MarshalPrivateKey(k, comment)
	}
	if err != nil {
		return nil, nil, err
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("not a signing key")
	}
	sp, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(block), AuthorizedKey(sp, comment), nil
}

// AuthorizedKey renders "type base64 comment\n".
func AuthorizedKey(pub ssh.PublicKey, comment string) []byte {
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if comment != "" {
		line += " " + comment
	}
	return []byte(line + "\n")
}

// CertRequest describes a certificate to sign.
type CertRequest struct {
	Key        ssh.PublicKey
	Host       bool
	KeyID      string
	Serial     uint64 // 0 = random
	Principals []string
	ValidAfter time.Time
	Validity   time.Duration // 0 = forever
	// Extensions for user certificates; nil = OpenSSH defaults.
	Extensions      []string
	CriticalOptions map[string]string
}

// DefaultUserExtensions are what ssh-keygen grants by default.
var DefaultUserExtensions = []string{"permit-X11-forwarding", "permit-agent-forwarding", "permit-port-forwarding", "permit-pty", "permit-user-rc"}

// SignCert issues an OpenSSH certificate. RSA CAs sign with rsa-sha2-512,
// never SHA-1 ssh-rsa.
func SignCert(req CertRequest, ca crypto.Signer) (*ssh.Certificate, error) {
	if req.Key == nil {
		return nil, errors.New("no public key to certify")
	}
	if len(req.Principals) == 0 {
		return nil, errors.New("at least one principal is required (user name or host name)")
	}
	signer, err := ssh.NewSignerFromSigner(ca)
	if err != nil {
		return nil, fmt.Errorf("CA key: %w", err)
	}
	if _, ok := ca.Public().(*rsa.PublicKey); ok {
		as, ok := signer.(ssh.AlgorithmSigner)
		if !ok {
			return nil, errors.New("RSA CA key cannot select a signature algorithm")
		}
		if signer, err = ssh.NewSignerWithAlgorithms(as, []string{ssh.KeyAlgoRSASHA512}); err != nil {
			return nil, err
		}
	}
	serial := req.Serial
	if serial == 0 {
		var b [8]byte
		_, _ = rand.Read(b[:])
		serial = binary.BigEndian.Uint64(b[:]) >> 1
	}
	after := req.ValidAfter
	if after.IsZero() {
		after = time.Now().Add(-5 * time.Minute)
	}
	c := &ssh.Certificate{
		Key: req.Key, Serial: serial, KeyId: req.KeyID, ValidPrincipals: req.Principals,
		ValidAfter: uint64(after.Unix()), ValidBefore: ssh.CertTimeInfinity,
		Permissions: ssh.Permissions{CriticalOptions: req.CriticalOptions, Extensions: map[string]string{}},
		CertType:    ssh.UserCert,
	}
	if req.Validity > 0 {
		c.ValidBefore = uint64(after.Add(req.Validity).Unix())
	}
	if req.Host {
		c.CertType = ssh.HostCert
	} else {
		exts := req.Extensions
		if exts == nil {
			exts = DefaultUserExtensions
		}
		for _, e := range exts {
			c.Extensions[e] = ""
		}
	}
	if err := c.SignCert(rand.Reader, signer); err != nil {
		return nil, err
	}
	return c, nil
}

// VerifyCert checks the certificate signature, validity window and that
// principal is listed (the first principal when empty).
func VerifyCert(c *ssh.Certificate, principal string) error {
	if principal == "" && len(c.ValidPrincipals) > 0 {
		principal = c.ValidPrincipals[0]
	}
	checker := &ssh.CertChecker{SupportedCriticalOptions: []string{"source-address", "force-command", "verify-required"}}
	return checker.CheckCert(principal, c)
}

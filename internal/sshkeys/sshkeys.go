// Package sshkeys parses, describes, generates and certifies SSH keys
// (OpenSSH public/private keys, authorized_keys, RFC 4716 and OpenSSH
// certificates). Encrypted private keys are described without decrypting
// them whenever the format exposes the public key.
package sshkeys

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/matusso/sslknife/internal/keys"
)

// Item kinds.
const (
	KindPublic      = "public"
	KindPrivate     = "private"
	KindCertificate = "certificate"
)

// Item is one SSH object found in input.
type Item struct {
	Kind      string
	Format    string // openssh, pem, authorized_keys, rfc4716
	Public    ssh.PublicKey
	Cert      *ssh.Certificate
	Comment   string
	Options   []string // authorized_keys options
	Encrypted bool
	// Private is set only when the key was decrypted (or not encrypted).
	Private crypto.PrivateKey
	// Raw holds the original private key PEM so it can be stored unchanged
	// (still encrypted with its passphrase).
	Raw []byte
}

// ErrNoSSHKey means no SSH key was found.
var ErrNoSSHKey = errors.New("no SSH key found")

// Parse reads public keys (authorized_keys lines, RFC 4716), OpenSSH and
// PEM private keys, and OpenSSH certificates. Private keys are not
// decrypted: Private is nil for encrypted keys unless decrypt is called.
func Parse(data []byte) ([]Item, error) {
	trimmed := bytes.TrimSpace(data)
	switch {
	case bytes.HasPrefix(trimmed, []byte("-----BEGIN")):
		return parsePrivate(trimmed)
	case bytes.HasPrefix(trimmed, []byte("---- BEGIN SSH2 PUBLIC KEY")):
		pk, err := keys.ParsePublicKey(trimmed)
		if err != nil {
			return nil, err
		}
		sp, err := ssh.NewPublicKey(pk.Key)
		if err != nil {
			return nil, err
		}
		return []Item{{Kind: KindPublic, Format: "rfc4716", Public: sp, Comment: pk.Comment}}, nil
	}
	var out []Item
	rest := trimmed
	for len(bytes.TrimSpace(rest)) > 0 {
		pub, comment, options, next, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			if len(out) > 0 {
				break
			}
			return nil, ErrNoSSHKey
		}
		it := Item{Kind: KindPublic, Format: "authorized_keys", Public: pub, Comment: comment, Options: options}
		if c, ok := pub.(*ssh.Certificate); ok {
			it.Kind, it.Cert = KindCertificate, c
		}
		out = append(out, it)
		rest = next
	}
	if len(out) == 0 {
		return nil, ErrNoSSHKey
	}
	return out, nil
}

func parsePrivate(data []byte) ([]Item, error) {
	block, _ := pem.Decode(data)
	if block == nil || !keys.IsPrivateKeyBlock(block.Type) {
		return nil, ErrNoSSHKey
	}
	format := "pem"
	if block.Type == "OPENSSH PRIVATE KEY" {
		format = "openssh"
	}
	raw := pem.EncodeToMemory(block)
	it := Item{Kind: KindPrivate, Format: format, Raw: raw}
	k, err := ssh.ParseRawPrivateKey(raw)
	var missing *ssh.PassphraseMissingError
	switch {
	case errors.As(err, &missing):
		it.Encrypted = true
		it.Public = missing.PublicKey // nil for legacy encrypted PEM
	case err != nil:
		return nil, err
	default:
		it.Private = normalize(k)
		if it.Public, err = ssh.NewPublicKey(publicOf(it.Private)); err != nil {
			return nil, fmt.Errorf("unsupported SSH key type: %w", err)
		}
	}
	if format == "openssh" {
		it.Comment = opensshComment(raw)
	}
	return []Item{it}, nil
}

// Decrypt decrypts an encrypted private key item in place.
func (it *Item) Decrypt(passphrase []byte) error {
	if it.Kind != KindPrivate || !it.Encrypted || it.Private != nil {
		return nil
	}
	k, err := ssh.ParseRawPrivateKeyWithPassphrase(it.Raw, passphrase)
	if err != nil {
		return keys.ErrIncorrectPassword
	}
	it.Private = normalize(k)
	pub, err := ssh.NewPublicKey(publicOf(it.Private))
	if err != nil {
		return err
	}
	it.Public = pub
	return nil
}

func normalize(k any) crypto.PrivateKey {
	if p, ok := k.(*ed25519.PrivateKey); ok {
		return *p
	}
	return k
}

func publicOf(k crypto.PrivateKey) crypto.PublicKey {
	if s, ok := k.(crypto.Signer); ok {
		return s.Public()
	}
	return nil
}

// opensshComment extracts the comment from an unencrypted OpenSSH key; for
// encrypted keys the comment is inside the encrypted section.
func opensshComment(raw []byte) string {
	// x/crypto/ssh does not expose the comment; parse the unencrypted
	// section directly: "openssh-key-v1\0" string cipher, string kdf,
	// string kdfopts, uint32 n, string pubkey, string privsection.
	block, _ := pem.Decode(raw)
	if block == nil {
		return ""
	}
	b := block.Bytes
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(b, []byte(magic)) {
		return ""
	}
	r := b[len(magic):]
	var cipher string
	if cipher, r = sshString(r); cipher != "none" {
		return ""
	}
	_, r = sshString(r) // kdfname
	_, r = sshString(r) // kdfoptions
	if len(r) < 4 {
		return ""
	}
	r = r[4:]
	_, r = sshString(r) // public key
	priv, _ := sshString(r)
	p := []byte(priv)
	if len(p) < 8 {
		return ""
	}
	p = p[8:] // check ints
	keyType, p2 := sshString(p)
	p = p2
	// Skip key-type specific fields.
	fields := map[string]int{"ssh-ed25519": 2, "ssh-rsa": 6, "ecdsa-sha2-nistp256": 3, "ecdsa-sha2-nistp384": 3, "ecdsa-sha2-nistp521": 3}
	n, ok := fields[keyType]
	if !ok {
		return ""
	}
	for i := 0; i < n; i++ {
		_, p = sshString(p)
	}
	comment, _ := sshString(p)
	return comment
}

func sshString(b []byte) (string, []byte) {
	if len(b) < 4 {
		return "", nil
	}
	n := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if n < 0 || len(b) < 4+n {
		return "", nil
	}
	return string(b[4 : 4+n]), b[4+n:]
}

// Info is the stable description of an SSH key.
type Info struct {
	Kind              string    `json:"kind"`
	Format            string    `json:"format"`
	Type              string    `json:"type"`
	Bits              int       `json:"bits"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	FingerprintMD5    string    `json:"fingerprint_md5"`
	Comment           string    `json:"comment,omitempty"`
	Options           []string  `json:"options,omitempty"`
	Encrypted         bool      `json:"encrypted"`
	Strength          string    `json:"strength"`
	Notes             []string  `json:"notes,omitempty"`
	Certificate       *CertInfo `json:"certificate,omitempty"`
	PublicKey         string    `json:"public_key"` // authorized_keys line
}

// Describe returns the description of an item.
func Describe(it Item) Info {
	info := Info{Kind: it.Kind, Format: it.Format, Comment: it.Comment, Options: it.Options, Encrypted: it.Encrypted}
	pub := it.Public
	if pub == nil {
		info.Type = "unknown (encrypted legacy PEM key; public key not stored in the file)"
		info.Strength = "unknown"
		return info
	}
	if it.Cert != nil {
		ci := DescribeCert(it.Cert)
		info.Certificate = &ci
		pub = it.Cert.Key
	}
	info.Type = pub.Type()
	info.FingerprintSHA256 = ssh.FingerprintSHA256(pub)
	info.FingerprintMD5 = ssh.FingerprintLegacyMD5(pub)
	info.PublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	info.Bits, info.Strength, info.Notes = keyStrength(pub)
	return info
}

func keyStrength(pub ssh.PublicKey) (int, string, []string) {
	cpk, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		if strings.HasPrefix(pub.Type(), "sk-") {
			return 256, "modern", []string{"hardware security key (FIDO2)"}
		}
		return 0, "unknown", nil
	}
	switch k := cpk.CryptoPublicKey().(type) {
	case *rsa.PublicKey:
		b := k.N.BitLen()
		switch {
		case b < 2048:
			return b, "weak", []string{"RSA keys below 2048 bits are rejected by current OpenSSH"}
		case b < 3072:
			return b, "acceptable", nil
		}
		return b, "modern", nil
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize, "modern", nil
	case ed25519.PublicKey:
		return 256, "modern", nil
	}
	if pub.Type() == "ssh-dss" {
		return 1024, "insecure", []string{"DSA keys are disabled by default since OpenSSH 7.0"}
	}
	return 0, "unknown", nil
}

// CertInfo describes an OpenSSH certificate.
type CertInfo struct {
	CertType        string            `json:"cert_type"` // user or host
	KeyID           string            `json:"key_id"`
	Serial          uint64            `json:"serial"`
	Principals      []string          `json:"principals"`
	ValidAfter      *time.Time        `json:"valid_after,omitempty"`
	ValidBefore     *time.Time        `json:"valid_before,omitempty"` // nil = forever
	Status          string            `json:"status"`                 // valid, expired, not_yet_valid
	CriticalOptions map[string]string `json:"critical_options"`
	Extensions      []string          `json:"extensions"`
	CAType          string            `json:"ca_type"`
	CAFingerprint   string            `json:"ca_fingerprint_sha256"`
	SignatureAlgo   string            `json:"signature_algorithm"`
	KeyFingerprint  string            `json:"key_fingerprint_sha256"`
}

// DescribeCert describes c at the current time.
func DescribeCert(c *ssh.Certificate) CertInfo {
	ci := CertInfo{KeyID: c.KeyId, Serial: c.Serial, Principals: c.ValidPrincipals, CriticalOptions: c.CriticalOptions,
		CAType: c.SignatureKey.Type(), CAFingerprint: ssh.FingerprintSHA256(c.SignatureKey), KeyFingerprint: ssh.FingerprintSHA256(c.Key)}
	if ci.Principals == nil {
		ci.Principals = []string{}
	}
	if ci.CriticalOptions == nil {
		ci.CriticalOptions = map[string]string{}
	}
	for e := range c.Extensions {
		ci.Extensions = append(ci.Extensions, e)
	}
	sort.Strings(ci.Extensions)
	if ci.Extensions == nil {
		ci.Extensions = []string{}
	}
	ci.CertType = "user"
	if c.CertType == ssh.HostCert {
		ci.CertType = "host"
	}
	if c.Signature != nil {
		ci.SignatureAlgo = c.Signature.Format
	}
	now := time.Now()
	if c.ValidAfter != 0 {
		t := time.Unix(int64(c.ValidAfter), 0).UTC()
		ci.ValidAfter = &t
	}
	if c.ValidBefore != ssh.CertTimeInfinity {
		t := time.Unix(int64(c.ValidBefore), 0).UTC()
		ci.ValidBefore = &t
	}
	switch {
	case ci.ValidAfter != nil && now.Before(*ci.ValidAfter):
		ci.Status = "not_yet_valid"
	case ci.ValidBefore != nil && now.After(*ci.ValidBefore):
		ci.Status = "expired"
	default:
		ci.Status = "valid"
	}
	return ci
}

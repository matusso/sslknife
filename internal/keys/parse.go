package keys

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Private key container formats.
const (
	FormatPKCS8          = "PKCS#8"
	FormatPKCS8Encrypted = "PKCS#8 (encrypted)"
	FormatPKCS1          = "PKCS#1"
	FormatSEC1           = "SEC1"
	FormatLegacyPEM      = "PEM (legacy encryption)"
	FormatOpenSSH        = "OpenSSH"
	FormatPKIX           = "PKIX SubjectPublicKeyInfo"
	FormatPKCS1Public    = "PKCS#1 public"
	FormatAuthorizedKey  = "OpenSSH authorized_keys"
	FormatRFC4716        = "RFC 4716"
)

// PasswordFunc supplies a password when an encrypted key is encountered. It
// is only called if needed.
type PasswordFunc func() ([]byte, error)

// ErrNoKey means the input did not contain a key of the requested kind.
var ErrNoKey = errors.New("no key found")

// ErrPasswordRequired means the key is encrypted and no password was given.
var ErrPasswordRequired = errors.New("key is encrypted and requires a password")

// PrivateKey is a parsed private key and where it came from.
type PrivateKey struct {
	Key       crypto.PrivateKey
	Format    string
	Encrypted bool
	Comment   string
}

// Public returns the public key.
func (p *PrivateKey) Public() crypto.PublicKey {
	pub, _ := Public(p.Key)
	return pub
}

// PublicKey is a parsed public key.
type PublicKey struct {
	Key     crypto.PublicKey
	Format  string
	Comment string
}

// IsPrivateKeyBlock reports whether a PEM block type holds private key material.
func IsPrivateKeyBlock(t string) bool {
	return strings.HasSuffix(t, "PRIVATE KEY")
}

// ParsePrivateKeys returns every private key in data (PEM or DER).
func ParsePrivateKeys(data []byte, password PasswordFunc) ([]*PrivateKey, error) {
	if !bytes.Contains(data, []byte("-----BEGIN")) {
		k, err := parsePrivateDER(data)
		if err != nil {
			return nil, err
		}
		return []*PrivateKey{k}, nil
	}
	var out []*PrivateKey
	var pw []byte
	getPW := func() ([]byte, error) {
		if pw != nil {
			return pw, nil
		}
		if password == nil {
			return nil, ErrPasswordRequired
		}
		p, err := password()
		if err != nil {
			return nil, err
		}
		pw = p
		return pw, nil
	}
	defer func() { clear(pw) }()
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if !IsPrivateKeyBlock(block.Type) {
			continue
		}
		k, err := parsePrivateBlock(block, getPW)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	if len(out) == 0 {
		return nil, ErrNoKey
	}
	return out, nil
}

// ParsePrivateKey returns the first private key in data.
func ParsePrivateKey(data []byte, password PasswordFunc) (*PrivateKey, error) {
	ks, err := ParsePrivateKeys(data, password)
	if err != nil {
		return nil, err
	}
	return ks[0], nil
}

func parsePrivateBlock(block *pem.Block, password PasswordFunc) (*PrivateKey, error) {
	switch block.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 key: %w", err)
		}
		return &PrivateKey{Key: k, Format: FormatPKCS8}, nil
	case "ENCRYPTED PRIVATE KEY":
		pw, err := password()
		if err != nil {
			return nil, err
		}
		der, err := DecryptPKCS8(block.Bytes, pw)
		if err != nil {
			return nil, err
		}
		k, err := x509.ParsePKCS8PrivateKey(der)
		clear(der)
		if err != nil {
			return nil, ErrIncorrectPassword
		}
		return &PrivateKey{Key: k, Format: FormatPKCS8Encrypted, Encrypted: true}, nil
	case "RSA PRIVATE KEY", "EC PRIVATE KEY":
		der := block.Bytes
		format := FormatPKCS1
		if block.Type == "EC PRIVATE KEY" {
			format = FormatSEC1
		}
		encrypted := false
		//lint:ignore SA1019 legacy encrypted PEM is read-only for compatibility.
		if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck
			pw, err := password()
			if err != nil {
				return nil, err
			}
			//lint:ignore SA1019 see above.
			der, err = x509.DecryptPEMBlock(block, pw) //nolint:staticcheck
			if err != nil {
				return nil, ErrIncorrectPassword
			}
			format, encrypted = FormatLegacyPEM, true
		}
		var k crypto.PrivateKey
		var err error
		if block.Type == "RSA PRIVATE KEY" {
			k, err = x509.ParsePKCS1PrivateKey(der)
		} else {
			k, err = x509.ParseECPrivateKey(der)
		}
		if err != nil {
			if encrypted {
				return nil, ErrIncorrectPassword
			}
			return nil, fmt.Errorf("parse %s: %w", block.Type, err)
		}
		return &PrivateKey{Key: k, Format: format, Encrypted: encrypted}, nil
	case "OPENSSH PRIVATE KEY":
		raw := pem.EncodeToMemory(block)
		k, err := ssh.ParseRawPrivateKey(raw)
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			pw, perr := password()
			if perr != nil {
				return nil, perr
			}
			k, err = ssh.ParseRawPrivateKeyWithPassphrase(raw, pw)
			if err != nil {
				if errors.Is(err, x509.IncorrectPasswordError) {
					return nil, ErrIncorrectPassword
				}
				return nil, err
			}
			return &PrivateKey{Key: normalizeSSHKey(k), Format: FormatOpenSSH, Encrypted: true}, nil
		}
		if err != nil {
			return nil, fmt.Errorf("parse OpenSSH key: %w", err)
		}
		return &PrivateKey{Key: normalizeSSHKey(k), Format: FormatOpenSSH}, nil
	}
	return nil, fmt.Errorf("unsupported private key block %q", block.Type)
}

// normalizeSSHKey converts the *ed25519.PrivateKey returned by x/crypto/ssh
// into the value type used by crypto/x509.
func normalizeSSHKey(k any) crypto.PrivateKey {
	if p, ok := k.(*ed25519.PrivateKey); ok {
		return *p
	}
	return k
}

func parsePrivateDER(der []byte) (*PrivateKey, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return &PrivateKey{Key: k, Format: FormatPKCS8}, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return &PrivateKey{Key: k, Format: FormatPKCS1}, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return &PrivateKey{Key: k, Format: FormatSEC1}, nil
	}
	return nil, ErrNoKey
}

// ParsePublicKey parses a PKIX or PKCS#1 public key (PEM or DER), an OpenSSH
// authorized_keys line, or an RFC 4716 SSH2 public key.
func ParsePublicKey(data []byte) (*PublicKey, error) {
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("---- BEGIN SSH2 PUBLIC KEY ----")) {
		return parseRFC4716(trimmed)
	}
	if block, _ := pem.Decode(trimmed); block != nil {
		switch block.Type {
		case "PUBLIC KEY":
			k, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			return &PublicKey{Key: k, Format: FormatPKIX}, nil
		case "RSA PUBLIC KEY":
			k, err := x509.ParsePKCS1PublicKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			return &PublicKey{Key: k, Format: FormatPKCS1Public}, nil
		}
		return nil, ErrNoKey
	}
	if pk, comment, _, _, err := ssh.ParseAuthorizedKey(trimmed); err == nil {
		k, err := sshToCrypto(pk)
		if err != nil {
			return nil, err
		}
		return &PublicKey{Key: k, Format: FormatAuthorizedKey, Comment: comment}, nil
	}
	if k, err := x509.ParsePKIXPublicKey(data); err == nil {
		return &PublicKey{Key: k, Format: FormatPKIX}, nil
	}
	if k, err := x509.ParsePKCS1PublicKey(data); err == nil {
		return &PublicKey{Key: k, Format: FormatPKCS1Public}, nil
	}
	return nil, ErrNoKey
}

func sshToCrypto(pk ssh.PublicKey) (crypto.PublicKey, error) {
	cpk, ok := pk.(ssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported SSH key type %s", pk.Type())
	}
	return cpk.CryptoPublicKey(), nil
}

func parseRFC4716(data []byte) (*PublicKey, error) {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	var b64 strings.Builder
	comment := ""
	inHeader := false
	for _, l := range lines[1:] {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "---- END SSH2 PUBLIC KEY") {
			break
		}
		if inHeader {
			inHeader = strings.HasSuffix(l, `\`)
			continue
		}
		if k, v, ok := strings.Cut(l, ":"); ok && !strings.ContainsAny(k, " +/=") {
			if strings.EqualFold(strings.TrimSpace(k), "Comment") {
				comment = strings.Trim(strings.TrimSpace(v), `"`)
			}
			inHeader = strings.HasSuffix(l, `\`)
			continue
		}
		b64.WriteString(l)
	}
	raw, err := base64.StdEncoding.DecodeString(b64.String())
	if err != nil {
		return nil, fmt.Errorf("RFC 4716 key: %w", err)
	}
	pk, err := ssh.ParsePublicKey(raw)
	if err != nil {
		return nil, err
	}
	k, err := sshToCrypto(pk)
	if err != nil {
		return nil, err
	}
	return &PublicKey{Key: k, Format: FormatRFC4716, Comment: comment}, nil
}

// MarshalPrivateKeyPEM encodes priv as PKCS#8, encrypted when password is
// non-empty.
func MarshalPrivateKeyPEM(priv crypto.PrivateKey, password []byte) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	defer clear(der)
	if len(password) == 0 {
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
	}
	enc, err := EncryptPKCS8(der, password)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: enc}), nil
}

// MarshalPublicKeyPEM encodes pub as a PKIX "PUBLIC KEY" block.
func MarshalPublicKeyPEM(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

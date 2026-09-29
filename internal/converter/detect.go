// Package converter detects certificate/key container formats, decodes
// them into a common Bundle of objects, and encodes bundles into target
// formats. When a target cannot represent the bundle, encoding fails with
// an explanation instead of dropping data.
package converter

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"strings"

	"github.com/matusso/sslknife/internal/certificate"
)

// Format identifies a container format.
type Format string

const (
	FormatPEM       Format = "pem"
	FormatDER       Format = "der"
	FormatPKCS7     Format = "pkcs7"
	FormatPKCS8     Format = "pkcs8"
	FormatPKCS1     Format = "pkcs1"
	FormatSEC1      Format = "sec1"
	FormatSPKI      Format = "spki"
	FormatCSR       Format = "csr"
	FormatPKCS12    Format = "pkcs12"
	FormatJKS       Format = "jks"
	FormatJCEKS     Format = "jceks"
	FormatOpenSSH   Format = "openssh"
	FormatSSHPublic Format = "ssh"
	FormatRFC4716   Format = "rfc4716"
	FormatUnknown   Format = "unknown"
)

// Description is a human-readable name for a detected format.
func (f Format) Description() string {
	switch f {
	case FormatPEM:
		return "PEM"
	case FormatDER:
		return "DER X.509 certificate"
	case FormatPKCS7:
		return "PKCS#7 certificate bundle"
	case FormatPKCS8:
		return "PKCS#8 private key (DER)"
	case FormatPKCS1:
		return "PKCS#1 RSA key (DER)"
	case FormatSEC1:
		return "SEC1 EC private key (DER)"
	case FormatSPKI:
		return "SubjectPublicKeyInfo public key (DER)"
	case FormatCSR:
		return "PKCS#10 certificate request (DER)"
	case FormatPKCS12:
		return "PKCS#12"
	case FormatJKS:
		return "Java KeyStore (JKS)"
	case FormatJCEKS:
		return "Java JCEKS keystore"
	case FormatOpenSSH:
		return "OpenSSH private key"
	case FormatSSHPublic:
		return "OpenSSH public key (authorized_keys)"
	case FormatRFC4716:
		return "RFC 4716 SSH public key"
	}
	return "unknown"
}

var oidPKCS7Data = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}

// Detect identifies the format of data from its content, not its name.
func Detect(data []byte) Format {
	trimmed := bytes.TrimSpace(data)
	switch {
	case len(data) >= 4 && binary.BigEndian.Uint32(data) == 0xFEEDFEED:
		return FormatJKS
	case len(data) >= 4 && binary.BigEndian.Uint32(data) == 0xCECECECE:
		return FormatJCEKS
	case bytes.HasPrefix(trimmed, []byte("---- BEGIN SSH2 PUBLIC KEY")):
		return FormatRFC4716
	case bytes.HasPrefix(trimmed, []byte("-----BEGIN OPENSSH PRIVATE KEY")):
		return FormatOpenSSH
	case certificate.IsPEM(trimmed):
		return FormatPEM
	case isSSHPublic(trimmed):
		return FormatSSHPublic
	}
	if len(data) < 2 || data[0] != 0x30 {
		return FormatUnknown
	}
	if _, err := x509.ParseCertificate(data); err == nil {
		return FormatDER
	}
	if certs, err := x509.ParseCertificates(data); err == nil && len(certs) > 0 {
		return FormatDER
	}
	if _, err := certificate.ParsePKCS7(data); err == nil {
		return FormatPKCS7
	}
	if isPKCS12(data) {
		return FormatPKCS12
	}
	if _, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		return FormatPKCS8
	}
	if isEncryptedPKCS8(data) {
		return FormatPKCS8
	}
	if _, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return FormatPKCS1
	}
	if _, err := x509.ParsePKCS1PublicKey(data); err == nil {
		return FormatPKCS1
	}
	if _, err := x509.ParseECPrivateKey(data); err == nil {
		return FormatSEC1
	}
	if _, err := x509.ParsePKIXPublicKey(data); err == nil {
		return FormatSPKI
	}
	if _, err := x509.ParseCertificateRequest(data); err == nil {
		return FormatCSR
	}
	return FormatUnknown
}

func isSSHPublic(b []byte) bool {
	line := string(b)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	for _, p := range []string{"ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-", "sk-ssh-ed25519@", "sk-ecdsa-sha2-", "ssh-dss ", "ssh-ed25519-cert-", "ssh-rsa-cert-"} {
		if strings.Contains(line, p) {
			return true
		}
	}
	return false
}

// isPKCS12 recognises a PFX: SEQUENCE { version INTEGER 3, authSafe ContentInfo, ... }.
func isPKCS12(b []byte) bool {
	var pfx struct {
		Version  int
		AuthSafe struct {
			ContentType asn1.ObjectIdentifier
			Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
		}
		MacData asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(b, &pfx); err != nil {
		return false
	}
	return pfx.Version == 3 && (pfx.AuthSafe.ContentType.Equal(oidPKCS7Data) ||
		pfx.AuthSafe.ContentType.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}))
}

func isEncryptedPKCS8(b []byte) bool {
	var epki struct {
		Algo struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		Data []byte
	}
	rest, err := asn1.Unmarshal(b, &epki)
	return err == nil && len(rest) == 0 && len(epki.Algo.Algorithm) > 0 && len(epki.Data) > 0 &&
		epki.Algo.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13})
}

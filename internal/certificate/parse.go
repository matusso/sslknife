// Package certificate parses, describes, creates, lints and compares X.509
// certificates.
package certificate

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
)

// ErrNoCertificate means the input contained no certificate.
var ErrNoCertificate = errors.New("no certificate found")

// certificate PEM block types accepted on input.
var certBlockTypes = map[string]bool{
	"CERTIFICATE":         true,
	"X509 CERTIFICATE":    true,
	"TRUSTED CERTIFICATE": true, // OpenSSL trusted cert; trailing aux data is ignored
}

// IsPEM reports whether data looks like PEM.
func IsPEM(data []byte) bool { return bytes.Contains(data, []byte("-----BEGIN ")) }

// Parse returns every certificate in data: PEM (any number of blocks,
// non-certificate blocks are skipped), DER, or PKCS#7 in either encoding.
func Parse(data []byte) ([]*x509.Certificate, error) {
	if IsPEM(data) {
		var out []*x509.Certificate
		rest := data
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			switch {
			case certBlockTypes[block.Type]:
				der := block.Bytes
				if block.Type == "TRUSTED CERTIFICATE" {
					der = firstDER(der)
				}
				c, err := x509.ParseCertificate(der)
				if err != nil {
					return nil, fmt.Errorf("certificate %d: %w", len(out)+1, err)
				}
				out = append(out, c)
			case block.Type == "PKCS7" || block.Type == "CMS":
				certs, err := ParsePKCS7(block.Bytes)
				if err != nil {
					return nil, err
				}
				out = append(out, certs...)
			}
		}
		if len(out) == 0 {
			return nil, ErrNoCertificate
		}
		return out, nil
	}
	if certs, err := x509.ParseCertificates(data); err == nil && len(certs) > 0 {
		return certs, nil
	}
	if certs, err := ParsePKCS7(data); err == nil && len(certs) > 0 {
		return certs, nil
	}
	return nil, ErrNoCertificate
}

// firstDER returns the first complete DER element of b.
func firstDER(b []byte) []byte {
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(b, &raw); err != nil {
		return b
	}
	return raw.FullBytes
}

var oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	ContentInfo      asn1.RawValue
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue
}

// ParsePKCS7 extracts certificates from a PKCS#7 / CMS SignedData
// structure (typically a .p7b "certs-only" bundle).
func ParsePKCS7(der []byte) ([]*x509.Certificate, error) {
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("not PKCS#7: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("unsupported PKCS#7 content type %v", ci.ContentType)
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("malformed PKCS#7 SignedData: %w", err)
	}
	if len(sd.Certificates.Bytes) == 0 {
		return nil, ErrNoCertificate
	}
	return x509.ParseCertificates(sd.Certificates.Bytes)
}

// EncodePEM encodes certificates as concatenated PEM blocks.
func EncodePEM(certs ...*x509.Certificate) []byte {
	var b bytes.Buffer
	for _, c := range certs {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return b.Bytes()
}

// ParseCSR parses a PKCS#10 request in PEM or DER.
func ParseCSR(data []byte) (*x509.CertificateRequest, error) {
	if IsPEM(data) {
		rest := data
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				return nil, errors.New("no certificate request found")
			}
			if block.Type == "CERTIFICATE REQUEST" || block.Type == "NEW CERTIFICATE REQUEST" {
				data = block.Bytes
				break
			}
		}
	}
	csr, err := x509.ParseCertificateRequest(data)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("certificate request signature invalid: %w", err)
	}
	return csr, nil
}

// EncodeCSRPEM encodes a certificate request.
func EncodeCSRPEM(csr *x509.CertificateRequest) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
}

// EncodePKCS7 builds a degenerate ("certs-only") PKCS#7 SignedData, the
// format of .p7b files.
func EncodePKCS7(certs []*x509.Certificate) ([]byte, error) {
	var raw []byte
	for _, c := range certs {
		raw = append(raw, c.Raw...)
	}
	sd, err := asn1.Marshal(struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      struct{ Type asn1.ObjectIdentifier }
		Certificates     asn1.RawValue
		SignerInfos      asn1.RawValue
	}{
		Version:          1,
		DigestAlgorithms: asn1.RawValue{Tag: asn1.TagSet, IsCompound: true},
		ContentInfo:      struct{ Type asn1.ObjectIdentifier }{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}},
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: raw},
		SignerInfos:      asn1.RawValue{Tag: asn1.TagSet, IsCompound: true},
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue
	}{oidSignedData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sd}})
}

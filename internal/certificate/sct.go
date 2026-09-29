package certificate

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"
)

var oidSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// SCT is a Signed Certificate Timestamp embedded in a certificate (RFC 6962 §3.3).
type SCT struct {
	Version            int       `json:"version"`
	LogID              string    `json:"log_id"` // base64, as published in CT log lists
	Timestamp          time.Time `json:"timestamp"`
	HashAlgorithm      string    `json:"hash_algorithm"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
}

// EmbeddedSCTs returns the SCTs in the certificate's SCT list extension.
func EmbeddedSCTs(c *x509.Certificate) ([]SCT, error) {
	for _, ext := range c.Extensions {
		if ext.Id.Equal(oidSCTList) {
			var octets []byte
			if _, err := asn1.Unmarshal(ext.Value, &octets); err != nil {
				return nil, errors.New("malformed SCT list extension")
			}
			return ParseSCTList(octets)
		}
	}
	return nil, nil
}

var errSCT = errors.New("malformed SCT list")

// ParseSCTList decodes a TLS-encoded SignedCertificateTimestampList, as found
// in the certificate extension, the TLS extension, or an OCSP response.
func ParseSCTList(b []byte) ([]SCT, error) {
	if len(b) < 2 {
		return nil, errSCT
	}
	total := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if total != len(b) {
		return nil, errSCT
	}
	var out []SCT
	for len(b) > 0 {
		if len(b) < 2 {
			return nil, errSCT
		}
		n := int(binary.BigEndian.Uint16(b))
		b = b[2:]
		if n > len(b) {
			return nil, errSCT
		}
		s, err := parseSCT(b[:n])
		if err != nil {
			return nil, err
		}
		out = append(out, s)
		b = b[n:]
	}
	return out, nil
}

func parseSCT(b []byte) (SCT, error) {
	// version(1) log_id(32) timestamp(8) extensions<0..2^16-1> hash(1) sig(1) signature<0..2^16-1>
	if len(b) < 1+32+8+2 {
		return SCT{}, errSCT
	}
	s := SCT{Version: int(b[0]) + 1}
	s.LogID = base64.StdEncoding.EncodeToString(b[1:33])
	ms := binary.BigEndian.Uint64(b[33:41])
	s.Timestamp = time.UnixMilli(int64(ms)).UTC()
	extLen := int(binary.BigEndian.Uint16(b[41:43]))
	rest := b[43:]
	if extLen > len(rest) {
		return SCT{}, errSCT
	}
	rest = rest[extLen:]
	if len(rest) < 4 {
		return SCT{}, errSCT
	}
	s.HashAlgorithm = hashName(rest[0])
	s.SignatureAlgorithm = sigName(rest[1])
	sigLen := int(binary.BigEndian.Uint16(rest[2:4]))
	if sigLen != len(rest[4:]) {
		return SCT{}, errSCT
	}
	return s, nil
}

func hashName(b byte) string {
	switch b {
	case 2:
		return "SHA-1"
	case 4:
		return "SHA-256"
	case 5:
		return "SHA-384"
	case 6:
		return "SHA-512"
	}
	return "unknown"
}

func sigName(b byte) string {
	switch b {
	case 1:
		return "RSA"
	case 3:
		return "ECDSA"
	}
	return "unknown"
}

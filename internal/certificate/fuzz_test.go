package certificate

import (
	"crypto/x509"
	"testing"
	"time"
)

func FuzzParse(f *testing.F) {
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"))
	f.Add([]byte{0x30, 0x82, 0x01, 0x00})
	f.Add([]byte("-----BEGIN PKCS7-----\nMAA=\n-----END PKCS7-----\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		certs, err := Parse(data)
		if err != nil {
			return
		}
		for _, c := range certs {
			_ = Describe(c, Options{Now: time.Unix(0, 0)})
			_ = Lint([]*x509.Certificate{c}, LintOptions{})
		}
	})
}

func FuzzSCTList(f *testing.F) {
	f.Add([]byte{0, 0})
	f.Add([]byte{0, 4, 0, 2, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = ParseSCTList(data) })
}

func FuzzParseCSR(f *testing.F) {
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----\nMAA=\n-----END CERTIFICATE REQUEST-----\n"))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = ParseCSR(data) })
}

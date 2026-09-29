package converter

import "github.com/matusso/sslknife/internal/certificate"

// Contents counts what a bundle holds, classifying certificates by role.
type Contents struct {
	PrivateKeys   int `json:"private_keys"`
	PublicKeys    int `json:"public_keys"`
	CSRs          int `json:"certificate_requests"`
	Leaf          int `json:"leaf_certificates"`
	Intermediates int `json:"intermediate_certificates"`
	Roots         int `json:"root_certificates"`
}

// Summarize classifies the bundle's objects.
func (b *Bundle) Summarize() Contents {
	var c Contents
	for _, o := range b.Objects {
		switch o.Kind {
		case KindPrivateKey:
			c.PrivateKeys++
		case KindPublicKey:
			c.PublicKeys++
		case KindCSR:
			c.CSRs++
		case KindCertificate:
			switch {
			case o.Cert.IsCA && certificate.IsSelfSigned(o.Cert):
				c.Roots++
			case o.Cert.IsCA:
				c.Intermediates++
			default:
				c.Leaf++
			}
		}
	}
	return c
}

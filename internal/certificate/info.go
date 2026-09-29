package certificate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"

	"github.com/matusso/sslknife/internal/keys"
)

// Info is the public, stable description of a certificate used for text,
// JSON and YAML output.
type Info struct {
	Version            int                `json:"version"`
	Serial             string             `json:"serial"`
	Subject            Name               `json:"subject"`
	Issuer             Name               `json:"issuer"`
	SANs               SANs               `json:"sans"`
	Validity           Validity           `json:"validity"`
	PublicKey          keys.PublicKeyInfo `json:"public_key"`
	SignatureAlgorithm string             `json:"signature_algorithm"`
	SignatureStrength  string             `json:"signature_strength"`
	Fingerprints       Fingerprints       `json:"fingerprints"`
	SelfSigned         bool               `json:"self_signed"`
	IsCA               bool               `json:"is_ca"`
	BasicConstraints   *BasicConstraints  `json:"basic_constraints,omitempty"`
	KeyUsage           []string           `json:"key_usage,omitempty"`
	ExtKeyUsage        []string           `json:"extended_key_usage,omitempty"`
	SubjectKeyID       string             `json:"subject_key_id,omitempty"`
	AuthorityKeyID     string             `json:"authority_key_id,omitempty"`
	CRLDistribution    []string           `json:"crl_distribution_points,omitempty"`
	OCSPServers        []string           `json:"ocsp_servers,omitempty"`
	CAIssuers          []string           `json:"ca_issuers,omitempty"`
	Policies           []Policy           `json:"policies,omitempty"`
	NameConstraints    *NameConstraints   `json:"name_constraints,omitempty"`
	MustStaple         bool               `json:"must_staple"`
	SCTs               []SCT              `json:"scts,omitempty"`
	Extensions         []Extension        `json:"extensions"`
	DERSize            int                `json:"der_size"`
	Warnings           []string           `json:"warnings,omitempty"`
	PEM                string             `json:"pem,omitempty"`
}

// Name is a distinguished name.
type Name struct {
	DN                 string   `json:"dn"`
	CommonName         string   `json:"common_name,omitempty"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizational_unit,omitempty"`
	Country            []string `json:"country,omitempty"`
	Province           []string `json:"province,omitempty"`
	Locality           []string `json:"locality,omitempty"`
}

// SANs groups subject alternative names by type.
type SANs struct {
	DNS   []string `json:"dns"`
	IP    []string `json:"ip"`
	Email []string `json:"email"`
	URI   []string `json:"uri"`
}

// All returns every SAN value in DNS, IP, email, URI order.
func (s SANs) All() []string {
	var out []string
	out = append(out, s.DNS...)
	out = append(out, s.IP...)
	out = append(out, s.Email...)
	return append(out, s.URI...)
}

// Validity describes the validity period relative to the evaluation time.
type Validity struct {
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	LifetimeDays  int       `json:"lifetime_days"`
	DaysRemaining int       `json:"days_remaining"`
	Status        string    `json:"status"` // valid, expiring, expired, not_yet_valid
}

// BasicConstraints mirrors the extension.
type BasicConstraints struct {
	CA       bool `json:"ca"`
	PathLen  *int `json:"path_len,omitempty"`
	Critical bool `json:"critical"`
}

// Policy is one certificate policy.
type Policy struct {
	OID  string `json:"oid"`
	Name string `json:"name,omitempty"`
}

// NameConstraints mirrors the extension.
type NameConstraints struct {
	Critical       bool     `json:"critical"`
	PermittedDNS   []string `json:"permitted_dns,omitempty"`
	ExcludedDNS    []string `json:"excluded_dns,omitempty"`
	PermittedIP    []string `json:"permitted_ip,omitempty"`
	ExcludedIP     []string `json:"excluded_ip,omitempty"`
	PermittedEmail []string `json:"permitted_email,omitempty"`
	ExcludedEmail  []string `json:"excluded_email,omitempty"`
	PermittedURI   []string `json:"permitted_uri,omitempty"`
	ExcludedURI    []string `json:"excluded_uri,omitempty"`
}

// Extension is one raw extension entry.
type Extension struct {
	OID      string `json:"oid"`
	Name     string `json:"name,omitempty"`
	Critical bool   `json:"critical"`
	Known    bool   `json:"known"`
	Size     int    `json:"size"`
}

// Options control Describe.
type Options struct {
	Now         time.Time // evaluation time; zero means time.Now()
	WarningDays int       // days before expiry that count as "expiring"; 0 means 30
	IncludePEM  bool
}

var (
	oidTLSFeature = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	oidBasicCons  = asn1.ObjectIdentifier{2, 5, 29, 19}
)

// NewName converts a pkix.Name.
func NewName(n pkix.Name) Name {
	return Name{
		DN:                 n.String(),
		CommonName:         n.CommonName,
		Organization:       n.Organization,
		OrganizationalUnit: n.OrganizationalUnit,
		Country:            n.Country,
		Province:           n.Province,
		Locality:           n.Locality,
	}
}

// DisplayName is the common name, or the full DN when there is none.
func (n Name) DisplayName() string {
	if n.CommonName != "" {
		return n.CommonName
	}
	return n.DN
}

// CertSANs extracts the SANs of c.
func CertSANs(c *x509.Certificate) SANs {
	s := SANs{DNS: nonNil(c.DNSNames), Email: nonNil(c.EmailAddresses), IP: []string{}, URI: []string{}}
	for _, ip := range c.IPAddresses {
		s.IP = append(s.IP, ip.String())
	}
	for _, u := range c.URIs {
		s.URI = append(s.URI, u.String())
	}
	return s
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// ComputeValidity evaluates the validity window at now.
func ComputeValidity(nb, na, now time.Time, warningDays int) Validity {
	if warningDays <= 0 {
		warningDays = 30
	}
	v := Validity{
		NotBefore:     nb.UTC(),
		NotAfter:      na.UTC(),
		LifetimeDays:  int(math.Round(na.Sub(nb).Hours() / 24)),
		DaysRemaining: int(math.Floor(na.Sub(now).Hours() / 24)),
	}
	switch {
	case now.Before(nb):
		v.Status = "not_yet_valid"
	case !now.Before(na):
		v.Status = "expired"
	case na.Sub(now) < time.Duration(warningDays)*24*time.Hour:
		v.Status = "expiring"
	default:
		v.Status = "valid"
	}
	return v
}

// IsSelfSigned reports whether c's subject equals its issuer and its
// signature verifies with its own key.
func IsSelfSigned(c *x509.Certificate) bool {
	if !bytesEqual(c.RawSubject, c.RawIssuer) {
		return false
	}
	return c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

func bytesEqual(a, b []byte) bool { return string(a) == string(b) }

// SerialHex formats a serial as colon-separated hex, preserving the sign.
func SerialHex(c *x509.Certificate) string {
	if c.SerialNumber == nil {
		return ""
	}
	sign := ""
	n := c.SerialNumber
	if n.Sign() < 0 {
		sign = "-"
		n = new(big.Int).Neg(n)
	}
	h := n.Text(16)
	if len(h)%2 == 1 {
		h = "0" + h
	}
	return sign + Colon(h)
}

// Describe builds an Info for c.
func Describe(c *x509.Certificate, opts Options) Info {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	info := Info{
		Version:            c.Version,
		Serial:             SerialHex(c),
		Subject:            NewName(c.Subject),
		Issuer:             NewName(c.Issuer),
		SANs:               CertSANs(c),
		Validity:           ComputeValidity(c.NotBefore, c.NotAfter, now, opts.WarningDays),
		PublicKey:          keys.Describe(c.PublicKey),
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		SignatureStrength:  SignatureStrength(c.SignatureAlgorithm),
		Fingerprints:       Fingerprint(c),
		SelfSigned:         IsSelfSigned(c),
		IsCA:               c.BasicConstraintsValid && c.IsCA,
		KeyUsage:           KeyUsageNames(c.KeyUsage),
		CRLDistribution:    c.CRLDistributionPoints,
		OCSPServers:        c.OCSPServer,
		CAIssuers:          c.IssuingCertificateURL,
		DERSize:            len(c.Raw),
	}
	if len(c.SubjectKeyId) > 0 {
		info.SubjectKeyID = Colon(hex.EncodeToString(c.SubjectKeyId))
	}
	if len(c.AuthorityKeyId) > 0 {
		info.AuthorityKeyID = Colon(hex.EncodeToString(c.AuthorityKeyId))
	}
	for _, u := range c.ExtKeyUsage {
		info.ExtKeyUsage = append(info.ExtKeyUsage, ExtKeyUsageName(u))
	}
	for _, oid := range c.UnknownExtKeyUsage {
		info.ExtKeyUsage = append(info.ExtKeyUsage, UnknownExtKeyUsageName(oid))
	}
	if c.BasicConstraintsValid {
		bc := &BasicConstraints{CA: c.IsCA}
		if c.IsCA && (c.MaxPathLen > 0 || c.MaxPathLenZero) {
			pl := c.MaxPathLen
			bc.PathLen = &pl
		}
		for _, e := range c.Extensions {
			if e.Id.Equal(oidBasicCons) {
				bc.Critical = e.Critical
			}
		}
		info.BasicConstraints = bc
	}
	for _, p := range c.Policies {
		s := p.String()
		info.Policies = append(info.Policies, Policy{OID: s, Name: PolicyName(s)})
	}
	if len(c.Policies) == 0 {
		for _, p := range c.PolicyIdentifiers {
			s := p.String()
			info.Policies = append(info.Policies, Policy{OID: s, Name: PolicyName(s)})
		}
	}
	info.NameConstraints = nameConstraints(c)
	for _, e := range c.Extensions {
		name := ExtensionName(e.Id)
		info.Extensions = append(info.Extensions, Extension{
			OID: e.Id.String(), Name: name, Critical: e.Critical, Known: name != "", Size: len(e.Value),
		})
		if e.Id.Equal(oidTLSFeature) {
			info.MustStaple = hasStatusRequest(e.Value)
		}
	}
	if info.Extensions == nil {
		info.Extensions = []Extension{}
	}
	if scts, err := EmbeddedSCTs(c); err == nil {
		info.SCTs = scts
	} else {
		info.Warnings = append(info.Warnings, "SCT list extension is malformed")
	}
	info.Warnings = append(info.Warnings, warnings(c, &info)...)
	if opts.IncludePEM {
		info.PEM = string(EncodePEM(c))
	}
	return info
}

func nameConstraints(c *x509.Certificate) *NameConstraints {
	if len(c.PermittedDNSDomains)+len(c.ExcludedDNSDomains)+len(c.PermittedIPRanges)+len(c.ExcludedIPRanges)+
		len(c.PermittedEmailAddresses)+len(c.ExcludedEmailAddresses)+len(c.PermittedURIDomains)+len(c.ExcludedURIDomains) == 0 {
		return nil
	}
	nc := &NameConstraints{
		Critical:       c.PermittedDNSDomainsCritical,
		PermittedDNS:   c.PermittedDNSDomains,
		ExcludedDNS:    c.ExcludedDNSDomains,
		PermittedEmail: c.PermittedEmailAddresses,
		ExcludedEmail:  c.ExcludedEmailAddresses,
		PermittedURI:   c.PermittedURIDomains,
		ExcludedURI:    c.ExcludedURIDomains,
	}
	for _, r := range c.PermittedIPRanges {
		nc.PermittedIP = append(nc.PermittedIP, r.String())
	}
	for _, r := range c.ExcludedIPRanges {
		nc.ExcludedIP = append(nc.ExcludedIP, r.String())
	}
	return nc
}

// hasStatusRequest checks a TLS Feature extension (RFC 7633) for
// status_request (5), i.e. OCSP Must-Staple.
func hasStatusRequest(v []byte) bool {
	var features []int
	if _, err := asn1.Unmarshal(v, &features); err != nil {
		return false
	}
	for _, f := range features {
		if f == 5 {
			return true
		}
	}
	return false
}

// warnings lists unusual or deprecated characteristics. They are short
// observations; `cert lint` gives full explanations.
func warnings(c *x509.Certificate, info *Info) []string {
	var w []string
	switch info.SignatureStrength {
	case "insecure":
		w = append(w, fmt.Sprintf("signature algorithm %s is broken", info.SignatureAlgorithm))
	case "deprecated":
		if !info.SelfSigned {
			w = append(w, fmt.Sprintf("signature algorithm %s is deprecated (SHA-1 collisions are practical)", info.SignatureAlgorithm))
		}
	}
	switch info.PublicKey.Strength {
	case "weak", "insecure":
		w = append(w, fmt.Sprintf("public key %s is %s", info.PublicKey.Description, info.PublicKey.Strength))
	}
	if c.Version < 3 {
		w = append(w, fmt.Sprintf("X.509 version %d certificate (v3 is required for extensions)", c.Version))
	}
	if len(c.UnhandledCriticalExtensions) > 0 {
		var oids []string
		for _, o := range c.UnhandledCriticalExtensions {
			oids = append(oids, o.String())
		}
		w = append(w, "unrecognised critical extensions: "+strings.Join(oids, ", "))
	}
	if !info.IsCA && len(info.SANs.All()) == 0 && info.Subject.CommonName != "" {
		w = append(w, "no Subject Alternative Name: modern TLS clients ignore the Common Name")
	}
	switch info.Validity.Status {
	case "expired":
		w = append(w, "certificate has expired")
	case "not_yet_valid":
		w = append(w, "certificate is not yet valid")
	}
	return w
}

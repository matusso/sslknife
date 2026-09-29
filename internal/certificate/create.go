package certificate

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Profile selects key usages and constraints for a new certificate.
type Profile string

const (
	ProfileServer         Profile = "server"
	ProfileClient         Profile = "client"
	ProfileServerClient   Profile = "server-client"
	ProfileCodeSigning    Profile = "code-signing"
	ProfileEmail          Profile = "email"
	ProfileRootCA         Profile = "root-ca"
	ProfileIntermediateCA Profile = "intermediate-ca"
)

// Profiles lists profiles in the order shown by the wizard.
var Profiles = []Profile{ProfileServer, ProfileClient, ProfileServerClient, ProfileCodeSigning, ProfileEmail, ProfileRootCA, ProfileIntermediateCA}

// Label is a human-readable profile name.
func (p Profile) Label() string {
	switch p {
	case ProfileServer:
		return "TLS Server"
	case ProfileClient:
		return "TLS Client"
	case ProfileServerClient:
		return "TLS Server + Client"
	case ProfileCodeSigning:
		return "Code Signing"
	case ProfileEmail:
		return "S/MIME E-mail"
	case ProfileRootCA:
		return "Root CA"
	case ProfileIntermediateCA:
		return "Intermediate CA"
	}
	return string(p)
}

// IsCA reports whether the profile produces a CA certificate.
func (p Profile) IsCA() bool { return p == ProfileRootCA || p == ProfileIntermediateCA }

// ParseProfile accepts profile names and a few aliases.
func ParseProfile(s string) (Profile, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "server", "tls-server", "web":
		return ProfileServer, nil
	case "client", "tls-client":
		return ProfileClient, nil
	case "server-client", "mtls", "both":
		return ProfileServerClient, nil
	case "code-signing", "codesign", "code":
		return ProfileCodeSigning, nil
	case "email", "smime":
		return ProfileEmail, nil
	case "root-ca", "root", "ca":
		return ProfileRootCA, nil
	case "intermediate-ca", "intermediate", "sub-ca", "subca":
		return ProfileIntermediateCA, nil
	}
	return "", fmt.Errorf("unknown certificate type %q (use server, client, server-client, code-signing, email, root-ca, intermediate-ca)", s)
}

// Request describes a certificate to create.
type Request struct {
	Profile   Profile
	Subject   pkix.Name
	SANs      []string // DNS names, IPs, e-mail addresses and URIs, auto-detected
	NotBefore time.Time
	Validity  time.Duration
	// PathLen constrains CA path length; negative means unconstrained.
	PathLen int
	// Key is the subject key. PublicKey may be set instead when signing a CSR.
	Key       crypto.Signer
	PublicKey crypto.PublicKey
	// Issuer and IssuerKey sign the certificate; both nil means self-signed.
	Issuer    *x509.Certificate
	IssuerKey crypto.Signer
}

// SplitSANs sorts SAN strings into DNS names, IPs, e-mails and URIs.
func SplitSANs(sans []string) (dns []string, ips []net.IP, emails []string, uris []*url.URL, err error) {
	for _, s := range sans {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		switch {
		case net.ParseIP(strings.Trim(s, "[]")) != nil:
			ips = append(ips, net.ParseIP(strings.Trim(s, "[]")))
		case strings.Contains(s, "://"):
			u, perr := url.Parse(s)
			if perr != nil || u.Scheme == "" {
				return nil, nil, nil, nil, fmt.Errorf("invalid URI SAN %q", s)
			}
			uris = append(uris, u)
		case strings.Contains(s, "@"):
			if _, perr := mail.ParseAddress(s); perr != nil {
				return nil, nil, nil, nil, fmt.Errorf("invalid e-mail SAN %q", s)
			}
			emails = append(emails, s)
		default:
			d := strings.ToLower(strings.TrimSuffix(s, "."))
			if err := ValidateDNSName(d); err != nil {
				return nil, nil, nil, nil, err
			}
			dns = append(dns, d)
		}
	}
	return dns, ips, emails, uris, nil
}

// ValidateDNSName checks LDH syntax with an optional leading wildcard label.
func ValidateDNSName(d string) error {
	if len(d) == 0 || len(d) > 253 {
		return fmt.Errorf("invalid DNS name %q: length", d)
	}
	labels := strings.Split(d, ".")
	for i, l := range labels {
		if l == "*" && i == 0 && len(labels) > 2 {
			continue
		}
		if l == "" || len(l) > 63 {
			return fmt.Errorf("invalid DNS name %q: empty or oversized label", d)
		}
		for j, r := range l {
			ok := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' && j > 0 && j < len(l)-1 || r == '_'
			if !ok {
				return fmt.Errorf("invalid DNS name %q: character %q (wildcards must be the whole left-most label)", d, r)
			}
		}
	}
	return nil
}

func randomSerial() (*big.Int, error) {
	// 128 random bits, positive, well above the 64-bit minimum of CA/B BR §7.1.
	max := new(big.Int).Lsh(big.NewInt(1), 127)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	return n.Add(n, big.NewInt(1)), nil
}

// subjectKeyID implements RFC 7093 §2 method 1: the leftmost 160 bits of
// the SHA-256 hash of the subjectPublicKey BIT STRING.
func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(spki.PublicKey.Bytes)
	return sum[:20], nil
}

// Create issues a certificate and returns it parsed.
func Create(req Request) (*x509.Certificate, error) {
	pub := req.PublicKey
	if req.Key != nil {
		pub = req.Key.Public()
	}
	if pub == nil {
		return nil, errors.New("no subject key")
	}
	if (req.Issuer == nil) != (req.IssuerKey == nil) {
		return nil, errors.New("issuer certificate and issuer key must be given together")
	}
	if req.Profile == ProfileIntermediateCA && req.Issuer == nil {
		return nil, errors.New("an intermediate CA must be signed by an issuer (--ca-cert and --ca-key)")
	}
	if req.Issuer == nil && req.Key == nil {
		return nil, errors.New("self-signed certificates need the private key")
	}
	if req.Validity <= 0 {
		return nil, errors.New("validity must be positive")
	}
	notBefore := req.NotBefore
	if notBefore.IsZero() {
		// Backdate slightly to tolerate clock skew on relying parties.
		notBefore = time.Now().Add(-5 * time.Minute)
	}
	notBefore = notBefore.UTC().Truncate(time.Second)
	notAfter := notBefore.Add(req.Validity)

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	dns, ips, emails, uris, err := SplitSANs(req.SANs)
	if err != nil {
		return nil, err
	}
	// Modern clients only match SANs, and the CA/B BRs require a CN to be
	// one of them: add the CN to the SANs when it is a hostname or IP.
	if (req.Profile == ProfileServer || req.Profile == ProfileServerClient) && req.Subject.CommonName != "" {
		cn := strings.ToLower(req.Subject.CommonName)
		if ip := net.ParseIP(cn); ip != nil {
			if !slices.ContainsFunc(ips, ip.Equal) {
				ips = append([]net.IP{ip}, ips...)
			}
		} else if ValidateDNSName(cn) == nil && !slices.Contains(dns, cn) {
			dns = append([]string{cn}, dns...)
		}
	}
	if req.Profile == ProfileEmail && len(emails) == 0 {
		return nil, errors.New("an e-mail certificate needs at least one e-mail SAN")
	}
	if (req.Profile == ProfileServer || req.Profile == ProfileServerClient) && len(dns)+len(ips) == 0 {
		return nil, errors.New("a TLS server certificate needs at least one DNS or IP SAN")
	}
	ski, err := subjectKeyID(pub)
	if err != nil {
		return nil, fmt.Errorf("unsupported public key: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:   serial,
		Subject:        req.Subject,
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		DNSNames:       dns,
		IPAddresses:    ips,
		EmailAddresses: emails,
		URIs:           uris,
		SubjectKeyId:   ski,
	}
	_, isRSA := pub.(*rsa.PublicKey)
	switch req.Profile {
	case ProfileRootCA, ProfileIntermediateCA:
		tmpl.IsCA = true
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
		if req.PathLen >= 0 {
			tmpl.MaxPathLen = req.PathLen
			tmpl.MaxPathLenZero = req.PathLen == 0
		} else {
			tmpl.MaxPathLen = -1
		}
	case ProfileServer, ProfileClient, ProfileServerClient, ProfileEmail:
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		if isRSA {
			// Needed only for RSA key transport (TLS 1.2 static RSA, S/MIME).
			tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
		}
		switch req.Profile {
		case ProfileServer:
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		case ProfileClient:
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		case ProfileServerClient:
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		case ProfileEmail:
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
		}
	case ProfileCodeSigning:
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	default:
		return nil, fmt.Errorf("unknown profile %q", req.Profile)
	}

	parent, signer := tmpl, req.Key
	if req.Issuer != nil {
		if err := checkIssuer(req.Issuer, req.IssuerKey, notAfter); err != nil {
			return nil, err
		}
		parent, signer = req.Issuer, req.IssuerKey
		tmpl.AuthorityKeyId = req.Issuer.SubjectKeyId
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func checkIssuer(issuer *x509.Certificate, key crypto.Signer, notAfter time.Time) error {
	if !issuer.IsCA || !issuer.BasicConstraintsValid {
		return errors.New("issuer certificate is not a CA (basicConstraints CA:TRUE missing)")
	}
	if issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("issuer certificate lacks the keyCertSign key usage")
	}
	if pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool }); !ok || !pub.Equal(issuer.PublicKey) {
		return errors.New("issuer key does not match the issuer certificate")
	}
	if notAfter.After(issuer.NotAfter) {
		return fmt.Errorf("requested validity ends %s, after the issuer expires (%s); shorten --validity",
			notAfter.Format(time.DateOnly), issuer.NotAfter.UTC().Format(time.DateOnly))
	}
	if time.Now().After(issuer.NotAfter) {
		return errors.New("issuer certificate has expired")
	}
	return nil
}

// CreateCSR creates a PKCS#10 certificate signing request.
func CreateCSR(subject pkix.Name, sans []string, key crypto.Signer) (*x509.CertificateRequest, error) {
	dns, ips, emails, uris, err := SplitSANs(sans)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: subject, DNSNames: dns, IPAddresses: ips, EmailAddresses: emails, URIs: uris,
	}, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificateRequest(der)
}

// RequestFromCSR builds a Request that copies subject and SANs from csr.
// The CSR's signature must already have been verified (ParseCSR does this).
func RequestFromCSR(csr *x509.CertificateRequest, profile Profile) Request {
	var sans []string
	sans = append(sans, csr.DNSNames...)
	for _, ip := range csr.IPAddresses {
		sans = append(sans, ip.String())
	}
	sans = append(sans, csr.EmailAddresses...)
	for _, u := range csr.URIs {
		sans = append(sans, u.String())
	}
	return Request{Profile: profile, Subject: csr.Subject, SANs: sans, PublicKey: csr.PublicKey, PathLen: -1}
}

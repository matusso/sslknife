package certificate

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/matusso/sslknife/internal/keys"
)

type pki struct {
	root, inter, leaf          *x509.Certificate
	rootKey, interKey, leafKey crypto.Signer
}

func mustKey(t *testing.T, a keys.Algorithm) crypto.Signer {
	t.Helper()
	k, err := keys.Generate(a)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	p := &pki{rootKey: mustKey(t, keys.ECDSAP384), interKey: mustKey(t, keys.ECDSAP256), leafKey: mustKey(t, keys.ECDSAP256)}
	var err error
	p.root, err = Create(Request{Profile: ProfileRootCA, Subject: pkix.Name{CommonName: "Test Root"}, Validity: 10 * 365 * 24 * time.Hour, Key: p.rootKey, PathLen: 1})
	if err != nil {
		t.Fatal(err)
	}
	p.inter, err = Create(Request{Profile: ProfileIntermediateCA, Subject: pkix.Name{CommonName: "Test Intermediate"}, Validity: 5 * 365 * 24 * time.Hour,
		Key: p.interKey, Issuer: p.root, IssuerKey: p.rootKey, PathLen: 0})
	if err != nil {
		t.Fatal(err)
	}
	p.leaf, err = Create(Request{Profile: ProfileServer, Subject: pkix.Name{CommonName: "api.example.com"}, SANs: []string{"api.example.com", "10.0.0.1", "*.api.example.com"},
		Validity: 90 * 24 * time.Hour, Key: p.leafKey, Issuer: p.inter, IssuerKey: p.interKey, PathLen: -1})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCreateAndDescribe(t *testing.T) {
	p := newPKI(t)
	info := Describe(p.leaf, Options{})
	if info.Subject.CommonName != "api.example.com" || info.Issuer.CommonName != "Test Intermediate" {
		t.Fatalf("names: %+v", info)
	}
	if !slices.Equal(info.SANs.DNS, []string{"api.example.com", "*.api.example.com"}) || info.SANs.IP[0] != "10.0.0.1" {
		t.Fatalf("sans: %+v", info.SANs)
	}
	if info.IsCA || info.SelfSigned || info.PublicKey.Description != "ECDSA P-256" || info.Validity.Status != "valid" {
		t.Fatalf("flags: %+v", info)
	}
	if !slices.Contains(info.ExtKeyUsage, "TLS Web Server Authentication") || slices.Contains(info.KeyUsage, "Key Encipherment") {
		t.Fatalf("usage: %v %v", info.KeyUsage, info.ExtKeyUsage)
	}
	if info.AuthorityKeyID == "" || info.SubjectKeyID == "" || len(info.Fingerprints.SHA256) != 64 {
		t.Fatalf("ids: %+v", info)
	}
	if len(info.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", info.Warnings)
	}
	rootInfo := Describe(p.root, Options{})
	if !rootInfo.IsCA || !rootInfo.SelfSigned || rootInfo.BasicConstraints == nil || *rootInfo.BasicConstraints.PathLen != 1 || !rootInfo.BasicConstraints.Critical {
		t.Fatalf("root: %+v", rootInfo.BasicConstraints)
	}
	interInfo := Describe(p.inter, Options{})
	if interInfo.BasicConstraints.PathLen == nil || *interInfo.BasicConstraints.PathLen != 0 {
		t.Fatalf("pathlen 0 lost")
	}
}

func TestCreateValidation(t *testing.T) {
	p := newPKI(t)
	k := mustKey(t, keys.Ed25519)
	cases := []Request{
		{Profile: ProfileIntermediateCA, Subject: pkix.Name{CommonName: "x"}, Validity: time.Hour, Key: k},
		{Profile: ProfileServer, Subject: pkix.Name{CommonName: "Not a host!"}, Validity: time.Hour, Key: k},
		{Profile: ProfileServer, SANs: []string{"a.example.com"}, Validity: 20 * 365 * 24 * time.Hour, Key: k, Issuer: p.inter, IssuerKey: p.interKey},
		{Profile: ProfileServer, SANs: []string{"a.example.com"}, Validity: time.Hour, Key: k, Issuer: p.leaf, IssuerKey: p.leafKey},
		{Profile: ProfileServer, SANs: []string{"a.example.com"}, Validity: time.Hour, Key: k, Issuer: p.inter, IssuerKey: p.rootKey},
		{Profile: ProfileServer, SANs: []string{"foo.*.example.com"}, Validity: time.Hour, Key: k},
		{Profile: ProfileEmail, Validity: time.Hour, Key: k},
	}
	for i, r := range cases {
		if r.PathLen == 0 {
			r.PathLen = -1
		}
		if _, err := Create(r); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
	// CN is copied into SANs for servers; Ed25519 has no keyEncipherment.
	c, err := Create(Request{Profile: ProfileServer, Subject: pkix.Name{CommonName: "Host.Example.com"}, Validity: time.Hour, Key: k, PathLen: -1})
	if err != nil || !slices.Equal(c.DNSNames, []string{"host.example.com"}) || c.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		t.Fatal(err, c.DNSNames)
	}
	// RSA server certificates get keyEncipherment.
	rk := mustKey(t, keys.RSA2048)
	c, err = Create(Request{Profile: ProfileServer, SANs: []string{"rsa.example.com"}, Validity: time.Hour, Key: rk, PathLen: -1})
	if err != nil || c.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Fatal(err)
	}
}

func TestMLDSACertificate(t *testing.T) {
	k := mustKey(t, keys.MLDSA65)
	c, err := Create(Request{Profile: ProfileRootCA, Subject: pkix.Name{CommonName: "PQ Root"}, Validity: time.Hour, Key: k, PathLen: -1})
	if err != nil {
		t.Fatal(err)
	}
	info := Describe(c, Options{})
	if info.PublicKey.Algorithm != "ML-DSA" || !info.SelfSigned {
		t.Fatalf("%+v", info.PublicKey)
	}
}

func TestCSR(t *testing.T) {
	p := newPKI(t)
	k := mustKey(t, keys.ECDSAP256)
	csr, err := CreateCSR(pkix.Name{CommonName: "svc.example.com"}, []string{"svc.example.com", "ops@example.com"}, k)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCSR(EncodeCSRPEM(csr))
	if err != nil {
		t.Fatal(err)
	}
	req := RequestFromCSR(parsed, ProfileServer)
	req.Validity, req.Issuer, req.IssuerKey = 24*time.Hour, p.inter, p.interKey
	c, err := Create(req)
	if err != nil {
		t.Fatal(err)
	}
	if !keys.Equal(c.PublicKey, k.Public()) || c.EmailAddresses[0] != "ops@example.com" {
		t.Fatal("csr fields not copied")
	}
}

func TestParseFormats(t *testing.T) {
	p := newPKI(t)
	pemBundle := EncodePEM(p.leaf, p.inter)
	pemBundle = append([]byte("junk before\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), pemBundle...)
	certs, err := Parse(pemBundle)
	if err != nil || len(certs) != 2 {
		t.Fatal(err, len(certs))
	}
	certs, err = Parse(p.leaf.Raw)
	if err != nil || len(certs) != 1 {
		t.Fatal(err)
	}
	// Minimal degenerate PKCS#7 SignedData with two certificates.
	p7 := buildPKCS7(t, p.leaf, p.root)
	certs, err = Parse(p7)
	if err != nil || len(certs) != 2 {
		t.Fatal("pkcs7:", err)
	}
	if _, err := Parse([]byte("not a cert")); !errors.Is(err, ErrNoCertificate) {
		t.Fatal(err)
	}
}

func buildPKCS7(t *testing.T, certs ...*x509.Certificate) []byte {
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
		DigestAlgorithms: asn1.RawValue{Class: 0, Tag: 17, IsCompound: true},
		ContentInfo:      struct{ Type asn1.ObjectIdentifier }{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}},
		Certificates:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: raw},
		SignerInfos:      asn1.RawValue{Class: 0, Tag: 17, IsCompound: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := asn1.Marshal(struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue
	}{oidSignedData, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: sd}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestChainOrder(t *testing.T) {
	p := newPKI(t)
	bundle := []*x509.Certificate{p.root, p.leaf, p.inter}
	if FindLeaf(bundle) != p.leaf {
		t.Fatal("leaf detection")
	}
	ordered := Order(p.leaf, bundle)
	if len(ordered) != 3 || ordered[1] != p.inter || ordered[2] != p.root {
		t.Fatal("order")
	}
	roots := x509.NewCertPool()
	roots.AddCert(p.root)
	res := Verify(p.leaf, VerifyOptions{Roots: roots, Intermediates: []*x509.Certificate{p.inter}, Hostname: "x.api.example.com"})
	if !res.Trusted || len(res.Chain) != 3 {
		t.Fatalf("%+v", res)
	}
	res = Verify(p.leaf, VerifyOptions{Roots: roots, Intermediates: []*x509.Certificate{p.inter}, Hostname: "other.example.com"})
	if res.Trusted || res.Reason != "hostname_mismatch" {
		t.Fatalf("%+v", res)
	}
	res = Verify(p.leaf, VerifyOptions{Roots: roots})
	if res.Trusted || res.Reason != "unknown_authority" {
		t.Fatalf("%+v", res)
	}
}

func ids(f []Finding) []string {
	var out []string
	for _, x := range f {
		out = append(out, x.ID)
	}
	return out
}

func TestLintCleanChain(t *testing.T) {
	p := newPKI(t)
	roots := x509.NewCertPool()
	roots.AddCert(p.root)
	f := Lint([]*x509.Certificate{p.leaf, p.inter}, LintOptions{Hostname: "api.example.com", Roots: roots, CheckTrust: true})
	for _, x := range f {
		if x.Severity != SevNotice {
			t.Errorf("unexpected finding: %+v", x)
		}
	}
}

func TestLintProblems(t *testing.T) {
	p := newPKI(t)
	now := time.Now()

	f := Lint([]*x509.Certificate{p.leaf}, LintOptions{Hostname: "evil.example.org", Now: now.Add(100 * 24 * time.Hour)})
	for _, want := range []string{"hostname_mismatch", "expired"} {
		if !slices.Contains(ids(f), want) {
			t.Errorf("missing %s in %v", want, ids(f))
		}
	}

	// Misordered, incomplete bundle.
	f = Lint([]*x509.Certificate{p.inter, p.leaf}, LintOptions{})
	for _, want := range []string{"leaf_not_first", "missing_intermediate"} {
		if !slices.Contains(ids(f), want) {
			t.Errorf("missing %s in %v", want, ids(f))
		}
	}

	// Hand-made bad leaf: CA-less keyCertSign, no SAN, long lifetime, ECDSA keyEncipherment.
	k := mustKey(t, keys.ECDSAP256)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(5),
		Subject:      pkix.Name{CommonName: "bad.example.com"},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(900 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"Foo.example.com", "1.2.3.4", "a*.example.com", "*.com", "under_score.example.com"},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.inter, k.Public(), p.interKey)
	if err != nil {
		t.Fatal(err)
	}
	bad, _ := x509.ParseCertificate(der)
	f = Lint([]*x509.Certificate{bad}, LintOptions{})
	for _, want := range []string{"certsign_without_ca", "excessive_lifetime", "keyencipherment_non_rsa", "cn_not_in_san",
		"ip_in_dns_san", "bad_wildcard", "wildcard_too_broad", "uppercase_san", "underscore_san", "serial_low_entropy"} {
		if !slices.Contains(ids(f), want) {
			t.Errorf("missing %s in %v", want, ids(f))
		}
	}
	for _, x := range f {
		if x.What == "" || x.Why == "" || x.Evidence == "" {
			t.Errorf("incomplete finding %+v", x)
		}
	}
	if !HasErrors(f) {
		t.Error("expected errors")
	}
}

func TestMaxTLSLifetime(t *testing.T) {
	cases := map[string]int{"2019-01-01": 825, "2021-01-01": 398, "2026-03-15": 200, "2027-06-01": 100, "2030-01-01": 47}
	for d, want := range cases {
		tm, _ := time.Parse(time.DateOnly, d)
		if got := MaxTLSLifetimeDays(tm); got != want {
			t.Errorf("%s: %d want %d", d, got, want)
		}
	}
}

func TestDiff(t *testing.T) {
	p := newPKI(t)
	k := mustKey(t, keys.ECDSAP256)
	other, err := Create(Request{Profile: ProfileServer, Subject: pkix.Name{CommonName: "api.example.com"},
		SANs: []string{"api.example.com", "new.example.com"}, Validity: 30 * 24 * time.Hour, Key: k, Issuer: p.inter, IssuerKey: p.interKey, PathLen: -1})
	if err != nil {
		t.Fatal(err)
	}
	changes := Diff(Describe(p.leaf, Options{}), Describe(other, Options{}))
	byField := map[string]Change{}
	for _, c := range changes {
		byField[c.Field] = c
	}
	if byField["Subject"].Changed || !byField["Public Key"].Changed || !byField["Expiration"].Changed {
		t.Fatalf("%+v", changes)
	}
	san := byField["SAN"]
	if !slices.Equal(san.Added, []string{"new.example.com"}) || !slices.Contains(san.Removed, "10.0.0.1") {
		t.Fatalf("%+v", san)
	}
	if Identical(changes) || !Identical(Diff(Describe(p.leaf, Options{}), Describe(p.leaf, Options{}))) {
		t.Fatal("Identical")
	}
	if got := FormatChange(san); got[0] != "- *.api.example.com" && !strings.HasPrefix(got[0], "- ") {
		t.Fatal(got)
	}
}

func TestSCTList(t *testing.T) {
	sct := []byte{0}                       // v1
	sct = append(sct, make([]byte, 32)...) // log id
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, 1700000000000)
	sct = append(sct, ts...)
	sct = append(sct, 0, 0)       // no extensions
	sct = append(sct, 4, 3, 0, 2) // sha256 ecdsa, 2-byte sig
	sct = append(sct, 0xAA, 0xBB)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(sct)+2))
	list = binary.BigEndian.AppendUint16(list, uint16(len(sct)))
	list = append(list, sct...)
	got, err := ParseSCTList(list)
	if err != nil || len(got) != 1 || got[0].HashAlgorithm != "SHA-256" || got[0].SignatureAlgorithm != "ECDSA" || got[0].Timestamp.Unix() != 1700000000 {
		t.Fatal(got, err)
	}
	for i := range list {
		// Truncations must fail cleanly, never panic.
		_, _ = ParseSCTList(list[:i])
	}
}

func TestSplitSANs(t *testing.T) {
	dns, ips, emails, uris, err := SplitSANs([]string{"A.Example.com.", "::1", "x@example.com", "spiffe://cluster/ns/app", ""})
	if err != nil || dns[0] != "a.example.com" || len(ips) != 1 || len(emails) != 1 || len(uris) != 1 {
		t.Fatal(dns, ips, emails, uris, err)
	}
	if _, _, _, _, err := SplitSANs([]string{"bad host"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestCNAddedToSANs(t *testing.T) {
	k := mustKey(t, keys.ECDSAP256)
	c, err := Create(Request{Profile: ProfileServer, Subject: pkix.Name{CommonName: "api.example.com"}, SANs: []string{"www.api.example.com"},
		Validity: time.Hour, Key: k, PathLen: -1})
	if err != nil || !slices.Equal(c.DNSNames, []string{"api.example.com", "www.api.example.com"}) {
		t.Fatal(err, c.DNSNames)
	}
}

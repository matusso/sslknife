package inventory

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"path/filepath"
	"testing"
	"time"

	"github.com/matusso/sslknife/internal/certificate"
	skcrypto "github.com/matusso/sslknife/internal/crypto"
	"github.com/matusso/sslknife/internal/database"
	"github.com/matusso/sslknife/internal/keys"
)

func newService(t *testing.T) *Service {
	t.Helper()
	db, err := database.Create(context.Background(), filepath.Join(t.TempDir(), "inv.db"), skcrypto.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return New(db)
}

func issue(t *testing.T, p certificate.Profile, cn string, validity time.Duration, issuer *x509.Certificate, issuerKey crypto.Signer) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	k, _ := keys.Generate(keys.ECDSAP256)
	var sans []string
	if !p.IsCA() {
		sans = []string{cn}
	}
	c, err := certificate.Create(certificate.Request{Profile: p, Subject: pkix.Name{CommonName: cn}, SANs: sans, Validity: validity,
		Key: k, Issuer: issuer, IssuerKey: issuerKey, PathLen: -1})
	if err != nil {
		t.Fatal(err)
	}
	return c, k
}

func TestImportLinksChainAndKey(t *testing.T) {
	s := newService(t)
	ctx := context.Background()
	root, rootKey := issue(t, certificate.ProfileRootCA, "Root", 3650*24*time.Hour, nil, nil)
	inter, interKey := issue(t, certificate.ProfileIntermediateCA, "Inter", 1800*24*time.Hour, root, rootKey)
	leaf, leafKey := issue(t, certificate.ProfileServer, "api.example.com", 20*24*time.Hour, inter, interKey)

	// Import leaf first, then root, then intermediate: links must be made
	// in both directions.
	res, err := s.ImportCertificates(ctx, []*x509.Certificate{leaf, root, inter}, ImportOptions{Name: "api-prod", Tags: []string{"production"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 3 || !res[0].Created || res[0].Cert.Name != "api-prod" || res[1].Cert.Name != "" {
		t.Fatalf("%+v", res)
	}
	row, _, err := s.Certificate(ctx, "api-prod")
	if err != nil {
		t.Fatal(err)
	}
	chain, err := s.Chain(ctx, row)
	if err != nil || len(chain) != 3 || chain[1].SubjectCN != "Inter" || chain[2].SubjectCN != "Root" {
		t.Fatalf("chain %v %v", len(chain), err)
	}

	// Re-import is de-duplicated and adds tags.
	again, err := s.ImportCertificate(ctx, leaf, ImportOptions{Tags: []string{"k8s"}})
	if err != nil || again.Created || len(again.Cert.Tags) != 2 {
		t.Fatalf("%+v %v", again, err)
	}

	kr, err := s.ImportPrivateKey(ctx, leafKey, ImportOptions{Name: "api-key"})
	if err != nil || !kr.Created || kr.LinkedCerts != 1 || !kr.Key.HasPrivate() {
		t.Fatalf("%+v %v", kr, err)
	}
	row, _, _ = s.Certificate(ctx, "api-prod")
	if row.KeyID != kr.Key.ID {
		t.Fatal("key not linked")
	}
	priv, err := s.PrivateKey(ctx, kr.Key)
	if err != nil || !keys.Equal(priv.(crypto.Signer).Public(), leafKey.Public()) {
		t.Fatal(err)
	}

	// Public-only import then private upgrade.
	_, otherKey := issue(t, certificate.ProfileClient, "client.example.com", time.Hour, inter, interKey)
	pr, err := s.ImportPublicKey(ctx, otherKey.Public(), ImportOptions{})
	if err != nil || pr.Key.HasPrivate() {
		t.Fatal(err)
	}
	up, err := s.ImportPrivateKey(ctx, otherKey, ImportOptions{})
	if err != nil || up.Created || !up.Upgraded || !up.Key.HasPrivate() {
		t.Fatalf("%+v %v", up, err)
	}

	exp, err := s.Expiring(ctx, 30*24*time.Hour, false)
	if err != nil || len(exp) != 1 || exp[0].ID != row.ID {
		t.Fatalf("expiring %v %v", exp, err)
	}
	sr, err := s.Search(ctx, "tag:production type:cert")
	if err != nil || len(sr.Certificates) != 3 || len(sr.Keys) != 0 {
		t.Fatalf("search %+v %v", sr, err)
	}
	sr, _ = s.Search(ctx, "api.example.com")
	if len(sr.Certificates) != 1 {
		t.Fatalf("bare search: %d", len(sr.Certificates))
	}
	sr, _ = s.Search(ctx, "type:key algorithm:p256")
	if len(sr.Keys) != 2 {
		t.Fatalf("key search: %d", len(sr.Keys))
	}
	st, err := s.Stats(ctx, 30)
	if err != nil || st.Certificates != 3 || st.PrivateKeys != 2 || st.Expiring != 1 {
		t.Fatalf("%+v %v", st, err)
	}
	children, _ := s.Children(ctx, chain[1])
	if len(children) != 1 {
		t.Fatal("children")
	}
}

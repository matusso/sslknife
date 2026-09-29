// Package inventory implements the certificate and key inventory use cases
// on top of the encrypted database: import with de-duplication and automatic
// linking (issuer ↔ subject, certificate ↔ private key), chains, search and
// expiry.
package inventory

import (
	"context"
	"crypto"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/matusso/sslknife/internal/certificate"
	skcrypto "github.com/matusso/sslknife/internal/crypto"
	"github.com/matusso/sslknife/internal/database"
	"github.com/matusso/sslknife/internal/keys"
	"github.com/matusso/sslknife/internal/search"
	"github.com/matusso/sslknife/internal/sshkeys"
)

// Service is the inventory API used by the CLI and the server.
type Service struct {
	DB  *database.DB
	Now func() time.Time
}

// New creates a service.
func New(db *database.DB) *Service { return &Service{DB: db, Now: time.Now} }

// ImportOptions apply to imported objects.
type ImportOptions struct {
	Name    string
	Tags    []string
	Source  string
	Comment string
}

// CertResult reports what happened to one imported certificate.
type CertResult struct {
	Cert    *database.Certificate
	Created bool // false when the certificate was already stored
}

// CertRow converts a parsed certificate into a database row (without ID).
func CertRow(c *x509.Certificate) *database.Certificate {
	fp := certificate.Fingerprint(c)
	pk := keys.Describe(c.PublicKey)
	row := &database.Certificate{
		SHA256: fp.SHA256, SHA1: fp.SHA1, SPKISHA256: fp.SPKISHA256,
		Serial:             certificate.SerialHex(c),
		Subject:            c.Subject.String(),
		SubjectCN:          c.Subject.CommonName,
		Issuer:             c.Issuer.String(),
		IssuerCN:           c.Issuer.CommonName,
		NotBefore:          c.NotBefore.UTC(),
		NotAfter:           c.NotAfter.UTC(),
		KeyAlgorithm:       pk.Algorithm,
		KeyBits:            pk.Bits,
		KeyDescription:     pk.Description,
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		IsCA:               c.BasicConstraintsValid && c.IsCA,
		SelfSigned:         certificate.IsSelfSigned(c),
		SubjectKeyID:       hex.EncodeToString(c.SubjectKeyId),
		AuthorityKeyID:     hex.EncodeToString(c.AuthorityKeyId),
		DER:                c.Raw,
	}
	sans := certificate.CertSANs(c)
	for _, v := range sans.DNS {
		row.SANs = append(row.SANs, database.SAN{Type: "dns", Value: v})
	}
	for _, v := range sans.IP {
		row.SANs = append(row.SANs, database.SAN{Type: "ip", Value: v})
	}
	for _, v := range sans.Email {
		row.SANs = append(row.SANs, database.SAN{Type: "email", Value: v})
	}
	for _, v := range sans.URI {
		row.SANs = append(row.SANs, database.SAN{Type: "uri", Value: v})
	}
	return row
}

// ImportCertificates stores certs. The name applies to the first new
// certificate only (names are unique). Tags apply to all.
func (s *Service) ImportCertificates(ctx context.Context, certs []*x509.Certificate, opts ImportOptions) ([]CertResult, error) {
	var out []CertResult
	name := opts.Name
	for _, c := range certs {
		o := opts
		o.Name = name
		r, err := s.ImportCertificate(ctx, c, o)
		if err != nil {
			return out, err
		}
		if r.Created {
			name = ""
		}
		out = append(out, r)
	}
	return out, nil
}

// ImportCertificate stores one certificate, or returns the existing row
// (adding any new tags) when it is already present.
func (s *Service) ImportCertificate(ctx context.Context, c *x509.Certificate, opts ImportOptions) (CertResult, error) {
	fp := certificate.Fingerprint(c)
	existing, err := s.DB.CertificateBySHA256(ctx, fp.SHA256)
	if err == nil {
		if len(opts.Tags) > 0 {
			if err := s.DB.AddTags(ctx, "cert", existing.ID, opts.Tags); err != nil {
				return CertResult{}, err
			}
			existing, _ = s.DB.GetCertificate(ctx, existing.ID)
		}
		return CertResult{Cert: existing}, nil
	}
	if !errors.Is(err, database.ErrNotFound) {
		return CertResult{}, err
	}
	row := CertRow(c)
	row.ID = skcrypto.NewID()
	row.Name = opts.Name
	row.Tags = opts.Tags
	row.Source = opts.Source
	row.Comment = opts.Comment
	row.ImportedAt = s.Now().UTC().Truncate(time.Second)
	if row.Source == "" {
		row.Source = "import"
	}

	issuerID, err := s.findIssuer(ctx, c)
	if err != nil {
		return CertResult{}, err
	}
	row.IssuerID = issuerID
	if k, err := s.DB.KeyBySPKI(ctx, fp.SPKISHA256); err == nil {
		row.KeyID = k.ID
	}
	children, err := s.findChildren(ctx, c)
	if err != nil {
		return CertResult{}, err
	}
	err = s.DB.Tx(ctx, func(tx *sql.Tx) error {
		if err := s.DB.InsertCertificate(ctx, tx, row); err != nil {
			return err
		}
		for _, child := range children {
			if err := s.DB.LinkCertificate(ctx, tx, child, row.ID, ""); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return CertResult{}, err
	}
	stored, err := s.DB.GetCertificate(ctx, row.ID)
	return CertResult{Cert: stored, Created: true}, err
}

// findIssuer returns the ID of a stored certificate that signed c.
func (s *Service) findIssuer(ctx context.Context, c *x509.Certificate) (string, error) {
	if certificate.IsSelfSigned(c) {
		return "", nil
	}
	cands, err := s.DB.QueryCertificates(ctx, "c.subject = ?", []any{c.Issuer.String()}, "")
	if err != nil {
		return "", err
	}
	for _, cand := range cands {
		pc, err := x509.ParseCertificate(cand.DER)
		if err == nil && certificate.Issues(pc, c) {
			return cand.ID, nil
		}
	}
	return "", nil
}

// findChildren returns stored, unlinked certificates issued by c.
func (s *Service) findChildren(ctx context.Context, c *x509.Certificate) ([]string, error) {
	cands, err := s.DB.QueryCertificates(ctx, "c.issuer = ? AND c.issuer_id IS NULL AND c.self_signed = 0", []any{c.Subject.String()}, "")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, cand := range cands {
		child, err := x509.ParseCertificate(cand.DER)
		if err == nil && certificate.Issues(c, child) {
			out = append(out, cand.ID)
		}
	}
	return out, nil
}

// Certificate loads a stored certificate and parses its DER.
func (s *Service) Certificate(ctx context.Context, ref string) (*database.Certificate, *x509.Certificate, error) {
	row, err := s.DB.GetCertificate(ctx, ref)
	if err != nil {
		return nil, nil, err
	}
	c, err := x509.ParseCertificate(row.DER)
	if err != nil {
		return nil, nil, fmt.Errorf("stored certificate %s is unparseable: %w", row.ID, err)
	}
	return row, c, nil
}

// Chain follows issuer links from row up to the top-most stored issuer.
func (s *Service) Chain(ctx context.Context, row *database.Certificate) ([]*database.Certificate, error) {
	chain := []*database.Certificate{row}
	seen := map[string]bool{row.ID: true}
	cur := row
	for cur.IssuerID != "" && len(chain) < 16 {
		next, err := s.DB.GetCertificate(ctx, cur.IssuerID)
		if err != nil {
			if errors.Is(err, database.ErrNotFound) {
				break
			}
			return nil, err
		}
		if seen[next.ID] {
			break
		}
		seen[next.ID] = true
		chain = append(chain, next)
		cur = next
	}
	return chain, nil
}

// Children returns certificates directly issued by row.
func (s *Service) Children(ctx context.Context, row *database.Certificate) ([]*database.Certificate, error) {
	return s.DB.QueryCertificates(ctx, "c.issuer_id = ? AND c.id != ?", []any{row.ID, row.ID}, "")
}

// ListFilter narrows certificate listings.
type ListFilter struct {
	Query string // search language, may be empty
}

// ListCertificates returns certificates matching the filter, soonest expiry first.
func (s *Service) ListCertificates(ctx context.Context, f ListFilter) ([]*database.Certificate, error) {
	q, err := search.Compile(f.Query, s.Now())
	if err != nil {
		return nil, err
	}
	if q.Certs == nil {
		return nil, nil
	}
	return s.DB.QueryCertificates(ctx, q.Certs.Where, q.Certs.Args, "")
}

// Expiring returns certificates that expire within d (and have not yet
// expired unless includeExpired is set).
func (s *Service) Expiring(ctx context.Context, d time.Duration, includeExpired bool) ([]*database.Certificate, error) {
	now := s.Now()
	if includeExpired {
		return s.DB.QueryCertificates(ctx, "c.not_after <= ?", []any{now.Add(d).Unix()}, "")
	}
	return s.DB.QueryCertificates(ctx, "c.not_after <= ? AND c.not_after > ?", []any{now.Add(d).Unix(), now.Unix()}, "")
}

// SearchResult holds matches of each kind.
type SearchResult struct {
	Certificates []*database.Certificate
	Keys         []*database.Key
	SSHKeys      []*database.SSHKey
}

// Search runs a query against all object kinds.
func (s *Service) Search(ctx context.Context, query string) (*SearchResult, error) {
	q, err := search.Compile(query, s.Now())
	if err != nil {
		return nil, err
	}
	res := &SearchResult{}
	if q.Certs != nil {
		if res.Certificates, err = s.DB.QueryCertificates(ctx, q.Certs.Where, q.Certs.Args, ""); err != nil {
			return nil, err
		}
	}
	if q.Keys != nil {
		if res.Keys, err = s.DB.QueryKeys(ctx, q.Keys.Where, q.Keys.Args); err != nil {
			return nil, err
		}
	}
	if q.SSH != nil {
		if res.SSHKeys, err = s.DB.QuerySSHKeys(ctx, q.SSH.Where, q.SSH.Args); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// KeyResult reports what happened to an imported key.
type KeyResult struct {
	Key     *database.Key
	Created bool
	// Upgraded is set when private material was added to a stored public key.
	Upgraded bool
	// LinkedCerts counts certificates newly linked to this key.
	LinkedCerts int
}

// ImportPrivateKey seals priv (as PKCS#8) into the vault.
func (s *Service) ImportPrivateKey(ctx context.Context, priv crypto.PrivateKey, opts ImportOptions) (KeyResult, error) {
	pub, err := keys.Public(priv)
	if err != nil {
		return KeyResult{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return KeyResult{}, fmt.Errorf("cannot encode key as PKCS#8: %w", err)
	}
	defer skcrypto.Zero(der)
	return s.importKey(ctx, pub, der, opts)
}

// ImportPublicKey stores a public key without private material.
func (s *Service) ImportPublicKey(ctx context.Context, pub crypto.PublicKey, opts ImportOptions) (KeyResult, error) {
	return s.importKey(ctx, pub, nil, opts)
}

func (s *Service) importKey(ctx context.Context, pub crypto.PublicKey, private []byte, opts ImportOptions) (KeyResult, error) {
	spki, err := keys.SPKI(pub)
	if err != nil {
		return KeyResult{}, err
	}
	info := keys.Describe(pub)
	var res KeyResult
	existing, err := s.DB.KeyBySPKI(ctx, info.SPKISHA256)
	switch {
	case err == nil:
		res.Key = existing
		if private != nil && !existing.HasPrivate() {
			if err := s.DB.Tx(ctx, func(tx *sql.Tx) error { return s.DB.AttachPrivate(ctx, tx, existing.ID, private) }); err != nil {
				return res, err
			}
			res.Upgraded = true
		}
		if len(opts.Tags) > 0 {
			if err := s.DB.AddTags(ctx, "key", existing.ID, opts.Tags); err != nil {
				return res, err
			}
		}
	case errors.Is(err, database.ErrNotFound):
		k := &database.Key{
			ID: skcrypto.NewID(), Name: opts.Name, Algorithm: info.Algorithm, Bits: info.Bits, Description: info.Description,
			SPKISHA256: info.SPKISHA256, PublicDER: spki, Source: opts.Source, Comment: opts.Comment,
			ImportedAt: s.Now().UTC().Truncate(time.Second), Tags: opts.Tags,
		}
		if k.Source == "" {
			k.Source = "import"
		}
		if err := s.DB.Tx(ctx, func(tx *sql.Tx) error { return s.DB.InsertKey(ctx, tx, k, private) }); err != nil {
			return res, err
		}
		res.Key, res.Created = k, true
	default:
		return res, err
	}
	// Link certificates that carry this public key.
	certs, err := s.DB.QueryCertificates(ctx, "c.spki_sha256 = ? AND c.key_id IS NULL", []any{info.SPKISHA256}, "")
	if err != nil {
		return res, err
	}
	if len(certs) > 0 {
		err = s.DB.Tx(ctx, func(tx *sql.Tx) error {
			for _, c := range certs {
				if err := s.DB.LinkCertificate(ctx, tx, c.ID, "", res.Key.ID); err != nil {
					return err
				}
			}
			return nil
		})
		res.LinkedCerts = len(certs)
	}
	if err != nil {
		return res, err
	}
	res.Key, err = s.DB.GetKey(ctx, res.Key.ID)
	return res, err
}

// PrivateKey decrypts a stored private key.
func (s *Service) PrivateKey(ctx context.Context, k *database.Key) (crypto.PrivateKey, error) {
	der, err := s.DB.PrivateKeyDER(ctx, k)
	if err != nil {
		return nil, err
	}
	defer skcrypto.Zero(der)
	return x509.ParsePKCS8PrivateKey(der)
}

// PublicKey parses a stored key's public half.
func (s *Service) PublicKey(k *database.Key) (crypto.PublicKey, error) {
	return x509.ParsePKIXPublicKey(k.PublicDER)
}

// Counts summarises the inventory.
type Counts struct {
	Certificates int `json:"certificates"`
	PrivateKeys  int `json:"private_keys"`
	PublicKeys   int `json:"public_keys"`
	SSHKeys      int `json:"ssh_keys"`
	Expiring     int `json:"expiring"`
	Expired      int `json:"expired"`
	TLSEndpoints int `json:"tls_endpoints"`
	CTWatches    int `json:"ct_watches"`
}

// Stats counts stored objects; expiring uses warnDays.
func (s *Service) Stats(ctx context.Context, warnDays int) (Counts, error) {
	var c Counts
	var err error
	if c.Certificates, err = s.DB.CountCertificates(ctx); err != nil {
		return c, err
	}
	ks, err := s.DB.QueryKeys(ctx, "", nil)
	if err != nil {
		return c, err
	}
	for _, k := range ks {
		if k.HasPrivate() {
			c.PrivateKeys++
		} else {
			c.PublicKeys++
		}
	}
	exp, err := s.Expiring(ctx, time.Duration(warnDays)*24*time.Hour, false)
	if err != nil {
		return c, err
	}
	c.Expiring = len(exp)
	expired, err := s.DB.QueryCertificates(ctx, "c.not_after <= ?", []any{s.Now().Unix()}, "")
	if err != nil {
		return c, err
	}
	c.Expired = len(expired)
	ssh, err := s.DB.QuerySSHKeys(ctx, "", nil)
	if err != nil {
		return c, err
	}
	c.SSHKeys = len(ssh)
	if c.TLSEndpoints, err = s.DB.CountEndpoints(ctx); err != nil {
		return c, err
	}
	ws, err := s.DB.CTWatches(ctx)
	c.CTWatches = len(ws)
	return c, err
}

// ImportSSHKey stores an SSH key. The private key file is stored exactly as
// given (so a passphrase-protected key stays protected) when withPrivate is
// set and the item carries one.
func (s *Service) ImportSSHKey(ctx context.Context, it sshkeys.Item, opts ImportOptions, withPrivate bool) (*database.SSHKey, bool, error) {
	info := sshkeys.Describe(it)
	if info.FingerprintSHA256 == "" {
		return nil, false, errors.New("the public key cannot be determined without decrypting this legacy PEM key")
	}
	comment := it.Comment
	if opts.Comment != "" {
		comment = opts.Comment
	}
	k := &database.SSHKey{
		Name: opts.Name, Type: info.Type, Bits: info.Bits, FingerprintSHA256: info.FingerprintSHA256, PublicKey: info.PublicKey,
		Comment: comment, PassphraseProtected: it.Encrypted, Source: opts.Source, ImportedAt: s.Now().UTC().Truncate(time.Second), Tags: opts.Tags,
	}
	if k.Source == "" {
		k.Source = "import"
	}
	var private []byte
	if withPrivate && it.Kind == sshkeys.KindPrivate {
		private = it.Raw
	}
	return s.DB.UpsertSSHKey(ctx, k, private)
}

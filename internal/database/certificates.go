package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SAN is one subject alternative name.
type SAN struct {
	Type  string // dns, ip, email, uri
	Value string
}

// Certificate is a stored certificate row with its SANs and tags.
type Certificate struct {
	ID                 string
	Name               string
	SHA256             string
	SHA1               string
	SPKISHA256         string
	Serial             string
	Subject            string
	SubjectCN          string
	Issuer             string
	IssuerCN           string
	NotBefore          time.Time
	NotAfter           time.Time
	KeyAlgorithm       string
	KeyBits            int
	KeyDescription     string
	SignatureAlgorithm string
	IsCA               bool
	SelfSigned         bool
	SubjectKeyID       string
	AuthorityKeyID     string
	DER                []byte
	Source             string
	Comment            string
	IssuerID           string
	KeyID              string
	CTMonitored        bool
	ImportedAt         time.Time

	SANs []SAN
	Tags []string
}

const certColumns = `id, name, sha256, sha1, spki_sha256, serial, subject, subject_cn, issuer, issuer_cn,
	not_before, not_after, key_algorithm, key_bits, key_description, signature_algorithm, is_ca, self_signed,
	subject_key_id, authority_key_id, der, source, comment, issuer_id, key_id, ct_monitored, imported_at`

// InsertCertificate stores c and its SANs. c.ID must be set.
func (db *DB) InsertCertificate(ctx context.Context, tx *sql.Tx, c *Certificate) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO certificates(`+certColumns+`)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.ID, nullString(c.Name), c.SHA256, c.SHA1, c.SPKISHA256, c.Serial, c.Subject, c.SubjectCN, c.Issuer, c.IssuerCN,
		unix(c.NotBefore), unix(c.NotAfter), c.KeyAlgorithm, c.KeyBits, c.KeyDescription, c.SignatureAlgorithm,
		boolInt(c.IsCA), boolInt(c.SelfSigned), c.SubjectKeyID, c.AuthorityKeyID, c.DER, c.Source, c.Comment,
		nullString(c.IssuerID), nullString(c.KeyID), boolInt(c.CTMonitored), unix(c.ImportedAt))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: certificates.name") {
			return fmt.Errorf("a certificate named %q already exists", c.Name)
		}
		return err
	}
	for _, s := range c.SANs {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO certificate_sans(cert_id, type, value) VALUES (?,?,?)`,
			c.ID, s.Type, strings.ToLower(s.Value)); err != nil {
			return err
		}
	}
	for _, t := range c.Tags {
		if err := addTag(ctx, tx, "cert", c.ID, t); err != nil {
			return err
		}
	}
	return nil
}

func scanCertificate(row interface{ Scan(...any) error }) (*Certificate, error) {
	var c Certificate
	var name, issuerID, keyID sql.NullString
	var nb, na, imp int64
	var isCA, self, ct int
	err := row.Scan(&c.ID, &name, &c.SHA256, &c.SHA1, &c.SPKISHA256, &c.Serial, &c.Subject, &c.SubjectCN,
		&c.Issuer, &c.IssuerCN, &nb, &na, &c.KeyAlgorithm, &c.KeyBits, &c.KeyDescription, &c.SignatureAlgorithm,
		&isCA, &self, &c.SubjectKeyID, &c.AuthorityKeyID, &c.DER, &c.Source, &c.Comment, &issuerID, &keyID, &ct, &imp)
	if err != nil {
		return nil, err
	}
	c.Name, c.IssuerID, c.KeyID = name.String, issuerID.String, keyID.String
	c.NotBefore, c.NotAfter, c.ImportedAt = fromUnix(nb), fromUnix(na), fromUnix(imp)
	c.IsCA, c.SelfSigned, c.CTMonitored = isCA != 0, self != 0, ct != 0
	return &c, nil
}

// ResolveCertificate turns an ID, name, ID prefix or fingerprint prefix into an ID.
func (db *DB) ResolveCertificate(ctx context.Context, ref string) (string, error) {
	return resolveRef(ctx, db.sql, "certificates", ref, true)
}

// GetCertificate loads one certificate by reference.
func (db *DB) GetCertificate(ctx context.Context, ref string) (*Certificate, error) {
	id, err := db.ResolveCertificate(ctx, ref)
	if err != nil {
		return nil, err
	}
	certs, err := db.QueryCertificates(ctx, "c.id = ?", []any{id}, "")
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, ErrNotFound
	}
	return certs[0], nil
}

// CertificateBySHA256 returns the certificate with the exact fingerprint, or ErrNotFound.
func (db *DB) CertificateBySHA256(ctx context.Context, sha string) (*Certificate, error) {
	certs, err := db.QueryCertificates(ctx, "c.sha256 = ?", []any{sha}, "")
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, ErrNotFound
	}
	return certs[0], nil
}

// QueryCertificates returns certificates matching a WHERE clause over alias
// "c". where must be built from constants with args bound as parameters.
// order defaults to expiry.
func (db *DB) QueryCertificates(ctx context.Context, where string, args []any, order string) ([]*Certificate, error) {
	if where == "" {
		where = "1=1"
	}
	if order == "" {
		order = "c.not_after ASC, c.subject_cn ASC"
	}
	cols := prefixColumns(certColumns, "c")
	rows, err := db.sql.QueryContext(ctx, `SELECT `+cols+` FROM certificates c WHERE `+where+` ORDER BY `+order, args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []*Certificate
	byID := map[string]*Certificate{}
	for rows.Next() {
		c, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
		byID[c.ID] = c
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	if len(out) == 0 {
		return out, nil
	}
	if err := db.loadSANs(ctx, byID); err != nil {
		return nil, err
	}
	tags, err := db.tagsFor(ctx, "cert", keysOf(byID))
	if err != nil {
		return nil, err
	}
	for id, t := range tags {
		byID[id].Tags = t
	}
	return out, nil
}

func keysOf[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func anySlice(ids []string) []any {
	out := make([]any, len(ids))
	for i, v := range ids {
		out[i] = v
	}
	return out
}

func (db *DB) loadSANs(ctx context.Context, byID map[string]*Certificate) error {
	ids := keysOf(byID)
	for len(ids) > 0 {
		batch := ids[:min(len(ids), 500)]
		ids = ids[len(batch):]
		rows, err := db.sql.QueryContext(ctx, `SELECT cert_id, type, value FROM certificate_sans
			WHERE cert_id IN (`+placeholders(len(batch))+`) ORDER BY cert_id, rowid`, anySlice(batch)...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id string
			var s SAN
			if err := rows.Scan(&id, &s.Type, &s.Value); err != nil {
				rows.Close()
				return err
			}
			byID[id].SANs = append(byID[id].SANs, s)
		}
		rows.Close()
	}
	return nil
}

// LinkCertificate sets the issuer and/or key links. Empty values leave the
// column unchanged.
func (db *DB) LinkCertificate(ctx context.Context, tx *sql.Tx, id, issuerID, keyID string) error {
	if issuerID != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE certificates SET issuer_id = ? WHERE id = ?`, issuerID, id); err != nil {
			return err
		}
	}
	if keyID != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE certificates SET key_id = ? WHERE id = ?`, keyID, id); err != nil {
			return err
		}
	}
	return nil
}

// UpdateCertificateMeta changes the friendly name and/or comment. nil leaves a field unchanged.
func (db *DB) UpdateCertificateMeta(ctx context.Context, id string, name, comment *string) error {
	return db.Tx(ctx, func(tx *sql.Tx) error {
		if name != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE certificates SET name = ? WHERE id = ?`, nullString(*name), id); err != nil {
				if strings.Contains(err.Error(), "UNIQUE") {
					return fmt.Errorf("a certificate named %q already exists", *name)
				}
				return err
			}
		}
		if comment != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE certificates SET comment = ? WHERE id = ?`, *comment, id); err != nil {
				return err
			}
		}
		return nil
	})
}

// DeleteCertificate removes a certificate, its SANs, tags and notes.
func (db *DB) DeleteCertificate(ctx context.Context, id string) error {
	return db.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM certificates WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return deleteObjectMeta(ctx, tx, "cert", id)
	})
}

// CountCertificates returns the number of stored certificates.
func (db *DB) CountCertificates(ctx context.Context) (int, error) {
	var n int
	err := db.sql.QueryRowContext(ctx, `SELECT count(*) FROM certificates`).Scan(&n)
	return n, err
}

// IsNotFound reports whether err is ErrNotFound.
func IsNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

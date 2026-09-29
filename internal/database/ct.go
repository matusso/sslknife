package database

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	skcrypto "github.com/matusso/sslknife/internal/crypto"
)

// CTWatch is a domain monitored in Certificate Transparency.
type CTWatch struct {
	ID                string
	Domain            string
	IncludeSubdomains bool
	Source            string
	CreatedAt         time.Time
	LastCheckedAt     time.Time
	Cursor            string
}

// Pattern renders the watch as the user wrote it.
func (w CTWatch) Pattern() string {
	if w.IncludeSubdomains {
		return "*." + w.Domain
	}
	return w.Domain
}

// CTObservation is one issuance seen for a watch.
type CTObservation struct {
	ID           string
	WatchID      string
	Provider     string
	ExternalID   string
	Identity     string
	CertSHA256   string
	PubkeySHA256 string
	Serial       string
	Issuer       string
	IssuerName   string
	DNSNames     []string
	NotBefore    time.Time
	NotAfter     time.Time
	Revoked      *bool
	Status       string
	Reason       string
	KnownCertID  string
	Acknowledged bool
	FirstSeen    time.Time
}

// AddCTWatch creates a watch, returning the existing one if present.
func (db *DB) AddCTWatch(ctx context.Context, domain string, subdomains bool, source string) (*CTWatch, bool, error) {
	if w, err := db.findCTWatch(ctx, domain, subdomains); err == nil {
		return w, false, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, false, err
	}
	w := &CTWatch{ID: skcrypto.NewID(), Domain: domain, IncludeSubdomains: subdomains, Source: source, CreatedAt: time.Now().UTC().Truncate(time.Second)}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO ct_watches(id, domain, include_subdomains, source, created_at) VALUES (?,?,?,?,?)`,
		w.ID, w.Domain, boolInt(subdomains), source, unix(w.CreatedAt))
	return w, true, mapErr(err)
}

func (db *DB) findCTWatch(ctx context.Context, domain string, subdomains bool) (*CTWatch, error) {
	ws, err := db.queryCTWatches(ctx, `domain = ? AND include_subdomains = ?`, domain, boolInt(subdomains))
	if err != nil {
		return nil, err
	}
	if len(ws) == 0 {
		return nil, ErrNotFound
	}
	return &ws[0], nil
}

// CTWatches lists all watches.
func (db *DB) CTWatches(ctx context.Context) ([]CTWatch, error) { return db.queryCTWatches(ctx, "1=1") }

// CTWatchesFor returns watches for a domain (both exact and subdomain).
func (db *DB) CTWatchesFor(ctx context.Context, domain string) ([]CTWatch, error) {
	return db.queryCTWatches(ctx, `domain = ?`, domain)
}

func (db *DB) queryCTWatches(ctx context.Context, where string, args ...any) ([]CTWatch, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT id, domain, include_subdomains, source, created_at, last_checked_at, cursor
		FROM ct_watches WHERE `+where+` ORDER BY domain, include_subdomains`, args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []CTWatch
	for rows.Next() {
		var w CTWatch
		var sub int
		var created int64
		var checked sql.NullInt64
		if err := rows.Scan(&w.ID, &w.Domain, &sub, &w.Source, &created, &checked, &w.Cursor); err != nil {
			return nil, err
		}
		w.IncludeSubdomains, w.CreatedAt = sub != 0, fromUnix(created)
		if checked.Valid {
			w.LastCheckedAt = fromUnix(checked.Int64)
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// DeleteCTWatch removes a watch and its observations.
func (db *DB) DeleteCTWatch(ctx context.Context, id string) error {
	res, err := db.sql.ExecContext(ctx, `DELETE FROM ct_watches WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateCTWatchCheck records a completed poll.
func (db *DB) UpdateCTWatchCheck(ctx context.Context, id, cursor string, at time.Time) error {
	_, err := db.sql.ExecContext(ctx, `UPDATE ct_watches SET last_checked_at = ?, cursor = ? WHERE id = ?`, unix(at), cursor, id)
	return err
}

// InsertCTObservation stores o unless an observation with the same identity
// exists for the watch. It reports whether a row was added.
func (db *DB) InsertCTObservation(ctx context.Context, o *CTObservation) (bool, error) {
	if o.ID == "" {
		o.ID = skcrypto.NewID()
	}
	var revoked any
	if o.Revoked != nil {
		revoked = boolInt(*o.Revoked)
	}
	res, err := db.sql.ExecContext(ctx, `INSERT OR IGNORE INTO ct_observations(id, watch_id, provider, external_id, identity, cert_sha256,
		pubkey_sha256, serial, issuer, issuer_name, dns_names, not_before, not_after, revoked, status, reason, known_cert_id, first_seen)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		o.ID, o.WatchID, o.Provider, o.ExternalID, o.Identity, o.CertSHA256, o.PubkeySHA256, o.Serial, o.Issuer, o.IssuerName,
		strings.Join(o.DNSNames, "\n"), unix(o.NotBefore), unix(o.NotAfter), revoked, o.Status, o.Reason, nullString(o.KnownCertID), unix(o.FirstSeen))
	if err != nil {
		return false, mapErr(err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// CTObservationFilter narrows CTObservations.
type CTObservationFilter struct {
	WatchIDs []string
	Status   string
	Since    time.Time
	Limit    int
}

// CTObservations lists observations, newest first.
func (db *DB) CTObservations(ctx context.Context, f CTObservationFilter) ([]CTObservation, error) {
	where := []string{"1=1"}
	var args []any
	if len(f.WatchIDs) > 0 {
		where = append(where, "watch_id IN ("+placeholders(len(f.WatchIDs))+")")
		args = append(args, anySlice(f.WatchIDs)...)
	}
	if f.Status != "" {
		where = append(where, "status = ?")
		args = append(args, f.Status)
	}
	if !f.Since.IsZero() {
		where = append(where, "first_seen >= ?")
		args = append(args, unix(f.Since))
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 1000
	}
	args = append(args, limit)
	rows, err := db.sql.QueryContext(ctx, `SELECT id, watch_id, provider, external_id, identity, cert_sha256, pubkey_sha256, serial,
		issuer, issuer_name, dns_names, not_before, not_after, revoked, status, reason, known_cert_id, acknowledged, first_seen
		FROM ct_observations WHERE `+strings.Join(where, " AND ")+` ORDER BY first_seen DESC, not_before DESC LIMIT ?`, args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []CTObservation
	for rows.Next() {
		var o CTObservation
		var names string
		var nb, na, fs int64
		var revoked sql.NullInt64
		var known sql.NullString
		var ack int
		if err := rows.Scan(&o.ID, &o.WatchID, &o.Provider, &o.ExternalID, &o.Identity, &o.CertSHA256, &o.PubkeySHA256, &o.Serial,
			&o.Issuer, &o.IssuerName, &names, &nb, &na, &revoked, &o.Status, &o.Reason, &known, &ack, &fs); err != nil {
			return nil, err
		}
		if names != "" {
			o.DNSNames = strings.Split(names, "\n")
		}
		o.NotBefore, o.NotAfter, o.FirstSeen = fromUnix(nb), fromUnix(na), fromUnix(fs)
		if revoked.Valid {
			r := revoked.Int64 != 0
			o.Revoked = &r
		}
		o.KnownCertID, o.Acknowledged = known.String, ack != 0
		out = append(out, o)
	}
	return out, rows.Err()
}

// AcknowledgeCTObservation marks an observation as expected.
func (db *DB) AcknowledgeCTObservation(ctx context.Context, ref string) (string, error) {
	id, err := resolve(ctx, db.sql, "ct_observations", ref, false, false)
	if err != nil {
		return "", err
	}
	_, err = db.sql.ExecContext(ctx, `UPDATE ct_observations SET acknowledged = 1 WHERE id = ?`, id)
	return id, err
}

// CountCTObservations counts observations by status (all when empty).
func (db *DB) CountCTObservations(ctx context.Context, status string, since time.Time) (int, error) {
	q := `SELECT count(*) FROM ct_observations WHERE first_seen >= ?`
	args := []any{unix(since)}
	if status != "" {
		q += ` AND status = ?`
		args = append(args, status)
	}
	var n int
	err := db.sql.QueryRowContext(ctx, q, args...).Scan(&n)
	return n, err
}

// CertIndex holds inventory facts used to classify CT observations.
type CertIndex struct {
	BySHA256 map[string]string // cert sha256 -> cert id
	BySPKI   map[string]string // spki sha256 -> cert id (or key id)
	BySerial map[string]string // normalised serial -> cert id
	Issuers  map[string]bool   // CAKey of issuers of stored certificates
	NameSets map[string]string // sorted SAN set -> cert id
	SANs     []string          // all stored DNS SANs
}

// CTCertIndex builds the classification index from stored certificates and keys.
func (db *DB) CTCertIndex(ctx context.Context) (*CertIndex, error) {
	idx := &CertIndex{BySHA256: map[string]string{}, BySPKI: map[string]string{}, BySerial: map[string]string{},
		Issuers: map[string]bool{}, NameSets: map[string]string{}}
	certs, err := db.QueryCertificates(ctx, "", nil, "")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, c := range certs {
		idx.BySHA256[c.SHA256] = c.ID
		idx.BySPKI[c.SPKISHA256] = c.ID
		idx.BySerial[NormalizeSerial(c.Serial)] = c.ID
		idx.Issuers[CAKey(c.Issuer)] = true
		var names []string
		for _, s := range c.SANs {
			if s.Type == "dns" {
				names = append(names, s.Value)
				if !seen[s.Value] {
					seen[s.Value] = true
					idx.SANs = append(idx.SANs, s.Value)
				}
			}
		}
		if len(names) > 0 {
			idx.NameSets[NameSetKey(names)] = c.ID
		}
	}
	ks, err := db.QueryKeys(ctx, "", nil)
	if err != nil {
		return nil, err
	}
	for _, k := range ks {
		if _, ok := idx.BySPKI[k.SPKISHA256]; !ok {
			idx.BySPKI[k.SPKISHA256] = ""
		}
	}
	return idx, nil
}

// NormalizeSerial strips separators and leading zeros from a hex serial.
func NormalizeSerial(s string) string {
	s = strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(s))
	return strings.TrimLeft(s, "0")
}

// NormalizeDN makes DNs from different sources comparable ("C=US, O=X" vs "O=X,C=US").
func NormalizeDN(dn string) string {
	parts := strings.Split(dn, ",")
	for i, p := range parts {
		parts[i] = strings.ToLower(strings.TrimSpace(p))
	}
	sortStrings(parts)
	return strings.Join(parts, ",")
}

// CAKey identifies the CA behind an issuer DN. CAs rotate intermediates
// (Let's Encrypt R10, R11, E5, ...), so the organisation is used when the
// DN has one; otherwise the normalised DN.
func CAKey(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "O") {
			return "o=" + strings.ToLower(strings.TrimSpace(v))
		}
	}
	return NormalizeDN(dn)
}

// NameSetKey is an order-independent key for a set of DNS names.
func NameSetKey(names []string) string {
	n := make([]string, len(names))
	for i, x := range names {
		n[i] = strings.ToLower(x)
	}
	sortStrings(n)
	return strings.Join(n, "\n")
}

// MarkCTMonitored flags certificates whose DNS names are watched.
func (db *DB) MarkCTMonitored(ctx context.Context) error {
	_, err := db.sql.ExecContext(ctx, `UPDATE certificates SET ct_monitored = 1 WHERE EXISTS (
		SELECT 1 FROM certificate_sans s JOIN ct_watches w
		ON s.value = w.domain OR (w.include_subdomains = 1 AND (s.value = w.domain OR s.value LIKE '%.' || w.domain OR s.value = '*.' || w.domain))
		WHERE s.cert_id = certificates.id AND s.type = 'dns')`)
	return err
}

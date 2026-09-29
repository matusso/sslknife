package database

import (
	"context"
	"database/sql"
	"errors"
	"time"

	skcrypto "github.com/matusso/sslknife/internal/crypto"
)

// Endpoint is a remote TLS service that has been inspected or scanned.
type Endpoint struct {
	ID        string
	Host      string
	Port      int
	SNI       string
	Protocol  string
	FirstSeen time.Time
	LastSeen  time.Time
}

// Scan is one stored observation of an endpoint.
type Scan struct {
	ID         string
	EndpointID string
	Kind       string
	ScannedAt  time.Time
	LeafSHA256 string
	Snapshot   []byte
	Result     []byte
}

// RecordScan upserts the endpoint and stores the observation.
func (db *DB) RecordScan(ctx context.Context, ep Endpoint, s *Scan) error {
	return db.Tx(ctx, func(tx *sql.Tx) error {
		now := unix(s.ScannedAt)
		var id string
		err := tx.QueryRowContext(ctx, `SELECT id FROM tls_endpoints WHERE host=? AND port=? AND sni=?`, ep.Host, ep.Port, ep.SNI).Scan(&id)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			id = skcrypto.NewID()
			if _, err := tx.ExecContext(ctx, `INSERT INTO tls_endpoints(id, host, port, sni, protocol, first_seen, last_seen) VALUES (?,?,?,?,?,?,?)`,
				id, ep.Host, ep.Port, ep.SNI, ep.Protocol, now, now); err != nil {
				return err
			}
		case err != nil:
			return err
		default:
			if _, err := tx.ExecContext(ctx, `UPDATE tls_endpoints SET last_seen=?, protocol=? WHERE id=?`, now, ep.Protocol, id); err != nil {
				return err
			}
		}
		s.ID, s.EndpointID = skcrypto.NewID(), id
		_, err = tx.ExecContext(ctx, `INSERT INTO tls_scans(id, endpoint_id, kind, scanned_at, leaf_sha256, snapshot, result) VALUES (?,?,?,?,?,?,?)`,
			s.ID, id, s.Kind, now, s.LeafSHA256, string(s.Snapshot), s.Result)
		return err
	})
}

// Endpoints lists known endpoints, most recently seen first.
func (db *DB) Endpoints(ctx context.Context) ([]Endpoint, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT id, host, port, sni, protocol, first_seen, last_seen FROM tls_endpoints ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Endpoint
	for rows.Next() {
		var e Endpoint
		var fs, ls int64
		if err := rows.Scan(&e.ID, &e.Host, &e.Port, &e.SNI, &e.Protocol, &fs, &ls); err != nil {
			return nil, err
		}
		e.FirstSeen, e.LastSeen = fromUnix(fs), fromUnix(ls)
		out = append(out, e)
	}
	return out, rows.Err()
}

// FindEndpoints returns endpoints for host (and port when non-zero).
func (db *DB) FindEndpoints(ctx context.Context, host string, port int) ([]Endpoint, error) {
	all, err := db.Endpoints(ctx)
	if err != nil {
		return nil, err
	}
	var out []Endpoint
	for _, e := range all {
		if e.Host == host && (port == 0 || e.Port == port) {
			out = append(out, e)
		}
	}
	return out, nil
}

// Scans lists observations of an endpoint, newest first. withResult loads
// the full JSON.
func (db *DB) Scans(ctx context.Context, endpointID string, limit int, withResult bool) ([]Scan, error) {
	cols := `id, endpoint_id, kind, scanned_at, leaf_sha256, snapshot`
	if withResult {
		cols += `, result`
	}
	if limit <= 0 {
		limit = 1000
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT `+cols+` FROM tls_scans WHERE endpoint_id=? ORDER BY scanned_at DESC, rowid DESC LIMIT ?`, endpointID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Scan
	for rows.Next() {
		var s Scan
		var ts int64
		var snap string
		dest := []any{&s.ID, &s.EndpointID, &s.Kind, &ts, &s.LeafSHA256, &snap}
		if withResult {
			dest = append(dest, &s.Result)
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		s.ScannedAt, s.Snapshot = fromUnix(ts), []byte(snap)
		out = append(out, s)
	}
	return out, rows.Err()
}

// GetScan loads one observation by ID or ID prefix.
func (db *DB) GetScan(ctx context.Context, ref string) (*Scan, error) {
	id, err := resolve(ctx, db.sql, "tls_scans", ref, false, false)
	if err != nil {
		return nil, err
	}
	var s Scan
	var ts int64
	var snap string
	err = db.sql.QueryRowContext(ctx, `SELECT id, endpoint_id, kind, scanned_at, leaf_sha256, snapshot, result FROM tls_scans WHERE id=?`, id).
		Scan(&s.ID, &s.EndpointID, &s.Kind, &ts, &s.LeafSHA256, &snap, &s.Result)
	if err != nil {
		return nil, err
	}
	s.ScannedAt, s.Snapshot = fromUnix(ts), []byte(snap)
	return &s, nil
}

// CountEndpoints returns the number of known endpoints.
func (db *DB) CountEndpoints(ctx context.Context) (int, error) {
	var n int
	err := db.sql.QueryRowContext(ctx, `SELECT count(*) FROM tls_endpoints`).Scan(&n)
	return n, err
}

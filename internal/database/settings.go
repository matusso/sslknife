package database

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// GetSetting returns a setting value, decrypting it when it was stored as a
// secret. ErrNotFound when absent.
func (db *DB) GetSetting(ctx context.Context, key string) ([]byte, error) {
	var value []byte
	var sid sql.NullString
	err := db.sql.QueryRowContext(ctx, `SELECT value, secret_id FROM settings WHERE key = ?`, key).Scan(&value, &sid)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, mapErr(err)
	}
	if sid.Valid {
		return db.GetSecret(ctx, sid.String)
	}
	return value, nil
}

// SetSetting stores a value; secret values are sealed in the secrets table.
func (db *DB) SetSetting(ctx context.Context, key string, value []byte, secret bool) error {
	return db.Tx(ctx, func(tx *sql.Tx) error {
		var old sql.NullString
		_ = tx.QueryRowContext(ctx, `SELECT secret_id FROM settings WHERE key = ?`, key).Scan(&old)
		var plain []byte
		var sid any
		if secret {
			id, err := db.PutSecret(ctx, tx, value)
			if err != nil {
				return err
			}
			sid = id
		} else {
			plain = value
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO settings(key, value, secret_id, updated_at) VALUES (?,?,?,?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value, secret_id = excluded.secret_id, updated_at = excluded.updated_at`,
			key, plain, sid, time.Now().Unix()); err != nil {
			return err
		}
		if old.Valid {
			return deleteSecret(ctx, tx, old.String)
		}
		return nil
	})
}

// RecentScan is a stored observation with its endpoint.
type RecentScan struct {
	Scan
	Host string
	Port int
}

// RecentScans returns the newest observations across endpoints.
func (db *DB) RecentScans(ctx context.Context, limit int, withResult bool) ([]RecentScan, error) {
	cols := `s.id, s.endpoint_id, s.kind, s.scanned_at, s.leaf_sha256, s.snapshot, e.host, e.port`
	if withResult {
		cols += `, s.result`
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT `+cols+` FROM tls_scans s JOIN tls_endpoints e ON e.id = s.endpoint_id
		ORDER BY s.scanned_at DESC, s.rowid DESC LIMIT ?`, limit)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []RecentScan
	for rows.Next() {
		var r RecentScan
		var ts int64
		var snap string
		dest := []any{&r.ID, &r.EndpointID, &r.Kind, &ts, &r.LeafSHA256, &snap, &r.Host, &r.Port}
		if withResult {
			dest = append(dest, &r.Result)
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		r.ScannedAt, r.Snapshot = fromUnix(ts), []byte(snap)
		out = append(out, r)
	}
	return out, rows.Err()
}

// RecentCertificates returns the most recently imported certificates.
func (db *DB) RecentCertificates(ctx context.Context, limit int) ([]*Certificate, error) {
	certs, err := db.QueryCertificates(ctx, "", nil, "c.imported_at DESC, c.id")
	if err != nil {
		return nil, err
	}
	if len(certs) > limit {
		certs = certs[:limit]
	}
	return certs, nil
}

package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// SyncKey identifies an object in remote sync state.
type SyncKey struct {
	Kind  string // cert, key, ssh
	Ident string
}

// SyncStates returns the last agreed digest of every object synced with remote.
func (db *DB) SyncStates(ctx context.Context, remote string) (map[SyncKey]string, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT kind, ident, digest FROM remote_sync WHERE remote = ?`, remote)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := map[SyncKey]string{}
	for rows.Next() {
		var k SyncKey
		var d string
		if err := rows.Scan(&k.Kind, &k.Ident, &d); err != nil {
			return nil, err
		}
		out[k] = d
	}
	return out, rows.Err()
}

// ReplaceSyncStates atomically replaces the sync state for remote. Keys with
// an empty digest are dropped.
func (db *DB) ReplaceSyncStates(ctx context.Context, remote string, states map[SyncKey]string) error {
	return db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM remote_sync WHERE remote = ?`, remote); err != nil {
			return err
		}
		for k, d := range states {
			if d == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO remote_sync(remote, kind, ident, digest) VALUES (?,?,?,?)`,
				remote, k.Kind, k.Ident, d); err != nil {
				return err
			}
		}
		return nil
	})
}

// ForgetRemote removes all sync state for remote, so the next sync merges
// both sides as if they had never met.
func (db *DB) ForgetRemote(ctx context.Context, remote string) error {
	_, err := db.sql.ExecContext(ctx, `DELETE FROM remote_sync WHERE remote = ?`, remote)
	return err
}

// PutNote stores a note with a known ID (from another device). An existing
// note with the same ID is left unchanged.
func (db *DB) PutNote(ctx context.Context, objType, id string, n Note) error {
	_, err := db.sql.ExecContext(ctx, `INSERT OR IGNORE INTO notes(id, object_type, object_id, body, created_at) VALUES (?,?,?,?,?)`,
		n.ID, objType, id, n.Body, unix(n.CreatedAt))
	return err
}

// UpdateSSHKeyMeta changes an SSH key's name and/or comment. nil leaves a field unchanged.
func (db *DB) UpdateSSHKeyMeta(ctx context.Context, id string, name, comment *string) error {
	return db.Tx(ctx, func(tx *sql.Tx) error {
		if name != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE ssh_keys SET name = ? WHERE id = ?`, nullString(*name), id); err != nil {
				if strings.Contains(err.Error(), "UNIQUE") {
					return fmt.Errorf("an SSH key named %q already exists", *name)
				}
				return err
			}
		}
		if comment != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE ssh_keys SET comment = ? WHERE id = ?`, *comment, id); err != nil {
				return err
			}
		}
		return nil
	})
}

// AttachSSHPrivate stores private key file bytes for a public-only SSH key.
func (db *DB) AttachSSHPrivate(ctx context.Context, id string, private []byte, passphraseProtected bool) error {
	return db.Tx(ctx, func(tx *sql.Tx) error {
		sid, err := db.PutSecret(ctx, tx, private)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE ssh_keys SET secret_id = ?, passphrase_protected = ? WHERE id = ? AND secret_id IS NULL`,
			sid, boolInt(passphraseProtected), id)
		return err
	})
}

// TotalChanges returns the number of rows changed through this handle since
// it was opened. The CLI compares it before and after a command to decide
// whether there is anything to push.
func (db *DB) TotalChanges(ctx context.Context) (int64, error) {
	var n int64
	err := db.sql.QueryRowContext(ctx, `SELECT total_changes()`).Scan(&n)
	return n, err
}

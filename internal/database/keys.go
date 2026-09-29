package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Key is a stored key. Private key material lives in the secrets table and
// is only reachable through PrivateKeyDER.
type Key struct {
	ID          string
	Name        string
	Algorithm   string
	Bits        int
	Description string
	SPKISHA256  string
	PublicDER   []byte
	SecretID    string
	Source      string
	Comment     string
	ImportedAt  time.Time

	Tags []string
}

// HasPrivate reports whether private material is stored.
func (k *Key) HasPrivate() bool { return k.SecretID != "" }

const keyColumns = `id, name, algorithm, bits, description, spki_sha256, public_der, secret_id, source, comment, imported_at`

// InsertKey stores k. When private is non-nil it is sealed into the secrets
// table first and linked.
func (db *DB) InsertKey(ctx context.Context, tx *sql.Tx, k *Key, private []byte) error {
	if private != nil {
		sid, err := db.PutSecret(ctx, tx, private)
		if err != nil {
			return err
		}
		k.SecretID = sid
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO keys(`+keyColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		k.ID, nullString(k.Name), k.Algorithm, k.Bits, k.Description, k.SPKISHA256, k.PublicDER,
		nullString(k.SecretID), k.Source, k.Comment, unix(k.ImportedAt))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: keys.name") {
			return fmt.Errorf("a key named %q already exists", k.Name)
		}
		return err
	}
	for _, t := range k.Tags {
		if err := addTag(ctx, tx, "key", k.ID, t); err != nil {
			return err
		}
	}
	return nil
}

// AttachPrivate adds private material to an existing public-only key.
func (db *DB) AttachPrivate(ctx context.Context, tx *sql.Tx, keyID string, private []byte) error {
	sid, err := db.PutSecret(ctx, tx, private)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE keys SET secret_id = ? WHERE id = ? AND secret_id IS NULL`, sid, keyID)
	return err
}

func scanKey(row interface{ Scan(...any) error }) (*Key, error) {
	var k Key
	var name, sid sql.NullString
	var imp int64
	if err := row.Scan(&k.ID, &name, &k.Algorithm, &k.Bits, &k.Description, &k.SPKISHA256, &k.PublicDER,
		&sid, &k.Source, &k.Comment, &imp); err != nil {
		return nil, err
	}
	k.Name, k.SecretID, k.ImportedAt = name.String, sid.String, fromUnix(imp)
	return &k, nil
}

// QueryKeys returns keys matching where (alias "k").
func (db *DB) QueryKeys(ctx context.Context, where string, args []any) ([]*Key, error) {
	if where == "" {
		where = "1=1"
	}
	cols := prefixColumns(keyColumns, "k")
	rows, err := db.sql.QueryContext(ctx, `SELECT `+cols+` FROM keys k WHERE `+where+` ORDER BY k.imported_at, k.id`, args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []*Key
	byID := map[string]*Key{}
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
		byID[k.ID] = k
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) > 0 {
		tags, err := db.tagsFor(ctx, "key", keysOf(byID))
		if err != nil {
			return nil, err
		}
		for id, t := range tags {
			byID[id].Tags = t
		}
	}
	return out, nil
}

// ResolveKey turns an ID, name or ID prefix into an ID.
func (db *DB) ResolveKey(ctx context.Context, ref string) (string, error) {
	return resolveRef(ctx, db.sql, "keys", ref, false)
}

// GetKey loads one key by reference.
func (db *DB) GetKey(ctx context.Context, ref string) (*Key, error) {
	id, err := db.ResolveKey(ctx, ref)
	if err != nil {
		return nil, err
	}
	keys, err := db.QueryKeys(ctx, "k.id = ?", []any{id})
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, ErrNotFound
	}
	return keys[0], nil
}

// KeyBySPKI returns the key with the given SPKI fingerprint, or ErrNotFound.
func (db *DB) KeyBySPKI(ctx context.Context, spki string) (*Key, error) {
	keys, err := db.QueryKeys(ctx, "k.spki_sha256 = ?", []any{spki})
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, ErrNotFound
	}
	return keys[0], nil
}

// PrivateKeyDER returns the decrypted private key (PKCS#8 DER). The caller
// must Zero the result when done.
func (db *DB) PrivateKeyDER(ctx context.Context, k *Key) ([]byte, error) {
	if k.SecretID == "" {
		return nil, fmt.Errorf("key %s has no private material stored", k.ID)
	}
	return db.GetSecret(ctx, k.SecretID)
}

// DeleteKey removes a key and its sealed private material. Certificates that
// referenced the key keep existing with the link cleared.
func (db *DB) DeleteKey(ctx context.Context, id string) error {
	return db.Tx(ctx, func(tx *sql.Tx) error {
		var sid sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT secret_id FROM keys WHERE id = ?`, id).Scan(&sid); err != nil {
			if err == sql.ErrNoRows {
				return ErrNotFound
			}
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM keys WHERE id = ?`, id); err != nil {
			return err
		}
		if sid.Valid {
			if err := deleteSecret(ctx, tx, sid.String); err != nil {
				return err
			}
		}
		return deleteObjectMeta(ctx, tx, "key", id)
	})
}

// UpdateKeyMeta changes the friendly name and/or comment.
func (db *DB) UpdateKeyMeta(ctx context.Context, id string, name, comment *string) error {
	return db.Tx(ctx, func(tx *sql.Tx) error {
		if name != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE keys SET name = ? WHERE id = ?`, nullString(*name), id); err != nil {
				if strings.Contains(err.Error(), "UNIQUE") {
					return fmt.Errorf("a key named %q already exists", *name)
				}
				return err
			}
		}
		if comment != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE keys SET comment = ? WHERE id = ?`, *comment, id); err != nil {
				return err
			}
		}
		return nil
	})
}

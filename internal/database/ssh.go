package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	skcrypto "github.com/matusso/sslknife/internal/crypto"
)

// SSHKey is a stored SSH key.
type SSHKey struct {
	ID                  string
	Name                string
	Type                string
	Bits                int
	FingerprintSHA256   string
	PublicKey           string
	Comment             string
	PassphraseProtected bool
	SecretID            string
	Source              string
	ImportedAt          time.Time
	Tags                []string
}

// HasPrivate reports whether the private key is stored.
func (k *SSHKey) HasPrivate() bool { return k.SecretID != "" }

const sshColumns = `id, name, type, bits, fingerprint_sha256, public_key, comment, passphrase_protected, secret_id, source, imported_at`

// UpsertSSHKey stores k; when a key with the same fingerprint exists it
// attaches private material if newly available. It returns the stored row
// and whether it was created.
func (db *DB) UpsertSSHKey(ctx context.Context, k *SSHKey, private []byte) (*SSHKey, bool, error) {
	existing, err := db.querySSHKeys(ctx, "s.fingerprint_sha256 = ?", k.FingerprintSHA256)
	if err != nil {
		return nil, false, err
	}
	if len(existing) == 1 {
		e := existing[0]
		if private != nil && !e.HasPrivate() {
			err := db.Tx(ctx, func(tx *sql.Tx) error {
				sid, err := db.PutSecret(ctx, tx, private)
				if err != nil {
					return err
				}
				_, err = tx.ExecContext(ctx, `UPDATE ssh_keys SET secret_id = ?, passphrase_protected = ? WHERE id = ?`, sid, boolInt(k.PassphraseProtected), e.ID)
				return err
			})
			if err != nil {
				return nil, false, err
			}
		}
		if len(k.Tags) > 0 {
			if err := db.AddTags(ctx, "ssh", e.ID, k.Tags); err != nil {
				return nil, false, err
			}
		}
		got, err := db.GetSSHKey(ctx, e.ID)
		return got, false, err
	}
	k.ID = skcrypto.NewID()
	err = db.Tx(ctx, func(tx *sql.Tx) error {
		if private != nil {
			sid, err := db.PutSecret(ctx, tx, private)
			if err != nil {
				return err
			}
			k.SecretID = sid
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO ssh_keys(`+sshColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			k.ID, nullString(k.Name), k.Type, k.Bits, k.FingerprintSHA256, k.PublicKey, k.Comment, boolInt(k.PassphraseProtected),
			nullString(k.SecretID), k.Source, unix(k.ImportedAt))
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed: ssh_keys.name") {
				return fmt.Errorf("an SSH key named %q already exists", k.Name)
			}
			return err
		}
		for _, t := range k.Tags {
			if err := addTag(ctx, tx, "ssh", k.ID, t); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	got, err := db.GetSSHKey(ctx, k.ID)
	return got, true, err
}

// QuerySSHKeys returns keys matching where (alias "s").
func (db *DB) QuerySSHKeys(ctx context.Context, where string, args []any) ([]*SSHKey, error) {
	if where == "" {
		where = "1=1"
	}
	return db.querySSHKeys(ctx, where, args...)
}

func (db *DB) querySSHKeys(ctx context.Context, where string, args ...any) ([]*SSHKey, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT `+prefixColumns(sshColumns, "s")+` FROM ssh_keys s WHERE `+where+` ORDER BY s.imported_at, s.id`, args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []*SSHKey
	byID := map[string]*SSHKey{}
	for rows.Next() {
		var k SSHKey
		var name, sid sql.NullString
		var prot int
		var imp int64
		if err := rows.Scan(&k.ID, &name, &k.Type, &k.Bits, &k.FingerprintSHA256, &k.PublicKey, &k.Comment, &prot, &sid, &k.Source, &imp); err != nil {
			return nil, err
		}
		k.Name, k.SecretID, k.PassphraseProtected, k.ImportedAt = name.String, sid.String, prot != 0, fromUnix(imp)
		out = append(out, &k)
		byID[k.ID] = &k
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) > 0 {
		tags, err := db.tagsFor(ctx, "ssh", keysOf(byID))
		if err != nil {
			return nil, err
		}
		for id, t := range tags {
			byID[id].Tags = t
		}
	}
	return out, nil
}

// GetSSHKey loads a key by ID, name, ID prefix or fingerprint.
func (db *DB) GetSSHKey(ctx context.Context, ref string) (*SSHKey, error) {
	if strings.HasPrefix(ref, "SHA256:") {
		ks, err := db.querySSHKeys(ctx, "s.fingerprint_sha256 = ?", ref)
		if err != nil {
			return nil, err
		}
		if len(ks) == 0 {
			return nil, fmt.Errorf("%w: %q", ErrNotFound, ref)
		}
		return ks[0], nil
	}
	id, err := resolveRef(ctx, db.sql, "ssh_keys", ref, false)
	if err != nil {
		return nil, err
	}
	ks, err := db.querySSHKeys(ctx, "s.id = ?", id)
	if err != nil {
		return nil, err
	}
	if len(ks) == 0 {
		return nil, ErrNotFound
	}
	return ks[0], nil
}

// SSHPrivateKey returns the stored private key file bytes. Zero them after use.
func (db *DB) SSHPrivateKey(ctx context.Context, k *SSHKey) ([]byte, error) {
	if k.SecretID == "" {
		return nil, fmt.Errorf("SSH key %s has no private key stored", k.ID)
	}
	return db.GetSecret(ctx, k.SecretID)
}

// DeleteSSHKey removes a key and its sealed private material.
func (db *DB) DeleteSSHKey(ctx context.Context, id string) error {
	return db.Tx(ctx, func(tx *sql.Tx) error {
		var sid sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT secret_id FROM ssh_keys WHERE id = ?`, id).Scan(&sid); err != nil {
			if err == sql.ErrNoRows {
				return ErrNotFound
			}
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM ssh_keys WHERE id = ?`, id); err != nil {
			return err
		}
		if sid.Valid {
			if err := deleteSecret(ctx, tx, sid.String); err != nil {
				return err
			}
		}
		return deleteObjectMeta(ctx, tx, "ssh", id)
	})
}

// UpdateSSHKeyName renames a key.
func (db *DB) UpdateSSHKeyName(ctx context.Context, id, name string) error {
	_, err := db.sql.ExecContext(ctx, `UPDATE ssh_keys SET name = ? WHERE id = ?`, nullString(name), id)
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return fmt.Errorf("an SSH key named %q already exists", name)
	}
	return err
}

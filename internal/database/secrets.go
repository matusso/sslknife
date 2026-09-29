package database

import (
	"context"
	"database/sql"
	"errors"
	"time"

	skcrypto "github.com/matusso/sslknife/internal/crypto"
)

func secretAAD(id string) []byte { return []byte("sslknife-secret-v1|" + id) }

// PutSecret seals plaintext with AES-256-GCM and stores it, returning its ID.
func (db *DB) PutSecret(ctx context.Context, tx *sql.Tx, plaintext []byte) (string, error) {
	id := skcrypto.NewID()
	nonce, ct, err := skcrypto.Seal(db.secretKey, plaintext, secretAAD(id))
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO secrets(id, nonce, ciphertext, created_at) VALUES (?, ?, ?, ?)`,
		id, nonce, ct, time.Now().Unix())
	return id, err
}

// GetSecret loads and authenticates a secret. The caller should Zero it.
func (db *DB) GetSecret(ctx context.Context, id string) ([]byte, error) {
	var nonce, ct []byte
	err := db.sql.QueryRowContext(ctx, `SELECT nonce, ciphertext FROM secrets WHERE id = ?`, id).Scan(&nonce, &ct)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, mapErr(err)
	}
	return skcrypto.Open(db.secretKey, nonce, ct, secretAAD(id))
}

func deleteSecret(ctx context.Context, tx *sql.Tx, id string) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM secrets WHERE id = ?`, id)
	return err
}

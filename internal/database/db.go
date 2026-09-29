// Package database stores the SSLKnife inventory in an encrypted SQLite
// database (see docs/DESIGN.md §5 for the construction).
package database

import (
	"context"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/vfs/adiantum" // registers the "adiantum" VFS

	skcrypto "github.com/matusso/sslknife/internal/crypto"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// HKDF labels for the two subkeys derived from the vault root key.
const (
	infoPageKey   = "sslknife/v1/db-page"
	infoSecretKey = "sslknife/v1/secrets"
)

// ErrIntegrity means a page failed to decrypt or verify: the file was
// modified outside SQLite, or it belongs to a different key.
var ErrIntegrity = errors.New("database integrity check failed: file is corrupted, tampered with, or encrypted with a different key")

// ErrNotFound is returned when a looked-up object does not exist.
var ErrNotFound = errors.New("not found")

// ErrAmbiguous is returned when an ID prefix matches several objects.
var ErrAmbiguous = errors.New("ambiguous identifier")

// DB is an open, unlocked inventory database.
type DB struct {
	sql       *sql.DB
	secretKey []byte
	path      string
}

// KeyFilePath returns the keyslot file path for a database path.
func KeyFilePath(dbPath string) string { return dbPath + ".keys" }

// Exists reports whether a database file exists at path.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Create initialises a new, empty encrypted database. It fails if the file
// already exists.
func Create(ctx context.Context, path string, root []byte) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// Create the file first so SQLite (and its journals, which inherit the
	// database file mode) never exist with permissive permissions.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("database %s already exists", path)
		}
		return nil, err
	}
	f.Close()
	db, err := open(ctx, path, root, true)
	if err != nil {
		os.Remove(path)
		return nil, err
	}
	return db, nil
}

// Open opens an existing database with the vault root key and applies any
// pending migrations.
func Open(ctx context.Context, path string, root []byte) (*DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	return open(ctx, path, root, false)
}

func open(ctx context.Context, path string, root []byte, fresh bool) (*DB, error) {
	pageKey, err := skcrypto.Derive(root, infoPageKey)
	if err != nil {
		return nil, err
	}
	secretKey, err := skcrypto.Derive(root, infoSecretKey)
	if err != nil {
		return nil, err
	}
	hexKey := hex.EncodeToString(pageKey)
	skcrypto.Zero(pageKey)

	uri := "file:" + filepath.ToSlash(path) + "?vfs=adiantum&_txlock=immediate"
	sqldb, err := driver.Open(uri, func(c *sqlite3.Conn) error {
		// The key is set with a PRAGMA rather than a URI parameter so it is
		// not retrievable through the connection's filename.
		if err := c.Exec("PRAGMA hexkey='" + hexKey + "'"); err != nil {
			return err
		}
		// Page checksums inside the wide-block cipher give per-page
		// authenticity (encode-then-encipher).
		if err := c.EnableChecksums("main"); err != nil {
			return err
		}
		return c.Exec(`PRAGMA foreign_keys=ON; PRAGMA busy_timeout=10000;
			PRAGMA journal_mode=DELETE; PRAGMA temp_store=MEMORY; PRAGMA secure_delete=ON`)
	})
	if err != nil {
		return nil, mapErr(err)
	}
	// One connection: the CLI is single-threaded and the server serialises
	// access; cross-process concurrency is handled by SQLite file locks.
	sqldb.SetMaxOpenConns(1)
	db := &DB{sql: sqldb, secretKey: secretKey, path: path}
	if err := sqldb.PingContext(ctx); err != nil {
		sqldb.Close()
		return nil, mapErr(err)
	}
	if err := db.migrate(ctx); err != nil {
		sqldb.Close()
		return nil, mapErr(err)
	}
	if fresh {
		_ = os.Chmod(path, 0o600)
	}
	return db, nil
}

func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sqlite3.IOERR) || errors.Is(err, sqlite3.NOTADB) || errors.Is(err, sqlite3.CORRUPT) {
		return fmt.Errorf("%w (%w)", ErrIntegrity, err)
	}
	return err
}

// Close closes the database and forgets the secret key.
func (db *DB) Close() error {
	skcrypto.Zero(db.secretKey)
	return db.sql.Close()
}

// Path returns the database file path.
func (db *DB) Path() string { return db.path }

// SQL exposes the underlying handle for packages in this module that add
// their own tables (later phases).
func (db *DB) SQL() *sql.DB { return db.sql }

// Tx runs fn in a write transaction.
func (db *DB) Tx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return mapErr(err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return mapErr(err)
	}
	return mapErr(tx.Commit())
}

// SchemaVersion returns the highest applied migration.
func (db *DB) SchemaVersion(ctx context.Context) (int, error) {
	var v sql.NullInt64
	err := db.sql.QueryRowContext(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&v)
	return int(v.Int64), err
}

func (db *DB) migrate(ctx context.Context) error {
	if _, err := db.sql.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL DEFAULT (unixepoch()))`); err != nil {
		return err
	}
	current, err := db.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		var version int
		if _, err := fmt.Sscanf(e.Name(), "%04d_", &version); err != nil {
			return fmt.Errorf("bad migration name %q", e.Name())
		}
		if version <= current {
			continue
		}
		body, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(e.Name(), ".sql")
		err = db.Tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, string(body)); err != nil {
				return fmt.Errorf("migration %s: %w", name, err)
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, name) VALUES (?, ?)`, version, name)
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

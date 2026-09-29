package database

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"time"

	skcrypto "github.com/matusso/sslknife/internal/crypto"
)

var tagRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{0,62}$`)

// NormalizeTag lower-cases a tag and checks its syntax.
func NormalizeTag(tag string) (string, error) {
	t := strings.ToLower(strings.TrimSpace(tag))
	if !tagRE.MatchString(t) {
		return "", fmt.Errorf("invalid tag %q: use letters, digits and . _ : / - (max 63)", tag)
	}
	return t, nil
}

func addTag(ctx context.Context, q querier, objType, id, tag string) error {
	t, err := NormalizeTag(tag)
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `INSERT OR IGNORE INTO tags(object_type, object_id, tag) VALUES (?,?,?)`, objType, id, t)
	return err
}

// AddTags adds tags to an object.
func (db *DB) AddTags(ctx context.Context, objType, id string, tags []string) error {
	return db.Tx(ctx, func(tx *sql.Tx) error {
		for _, t := range tags {
			if err := addTag(ctx, tx, objType, id, t); err != nil {
				return err
			}
		}
		return nil
	})
}

// RemoveTags removes tags from an object.
func (db *DB) RemoveTags(ctx context.Context, objType, id string, tags []string) error {
	return db.Tx(ctx, func(tx *sql.Tx) error {
		for _, t := range tags {
			if _, err := tx.ExecContext(ctx, `DELETE FROM tags WHERE object_type=? AND object_id=? AND tag=?`,
				objType, id, strings.ToLower(strings.TrimSpace(t))); err != nil {
				return err
			}
		}
		return nil
	})
}

func (db *DB) tagsFor(ctx context.Context, objType string, ids []string) (map[string][]string, error) {
	out := map[string][]string{}
	for len(ids) > 0 {
		batch := ids[:min(len(ids), 500)]
		ids = ids[len(batch):]
		args := append([]any{objType}, anySlice(batch)...)
		rows, err := db.sql.QueryContext(ctx, `SELECT object_id, tag FROM tags WHERE object_type = ?
			AND object_id IN (`+placeholders(len(batch))+`) ORDER BY tag`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id, tag string
			if err := rows.Scan(&id, &tag); err != nil {
				rows.Close()
				return nil, err
			}
			out[id] = append(out[id], tag)
		}
		rows.Close()
	}
	return out, nil
}

// AllTags returns every tag in use with its object count.
func (db *DB) AllTags(ctx context.Context) (map[string]int, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT tag, count(*) FROM tags GROUP BY tag`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var t string
		var n int
		if err := rows.Scan(&t, &n); err != nil {
			return nil, err
		}
		out[t] = n
	}
	return out, rows.Err()
}

// Note is a free-text note attached to an object.
type Note struct {
	ID        string
	Body      string
	CreatedAt time.Time
}

// AddNote attaches a note to an object.
func (db *DB) AddNote(ctx context.Context, objType, id, body string) (*Note, error) {
	n := &Note{ID: skcrypto.NewID(), Body: body, CreatedAt: time.Now().UTC().Truncate(time.Second)}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO notes(id, object_type, object_id, body, created_at) VALUES (?,?,?,?,?)`,
		n.ID, objType, id, body, unix(n.CreatedAt))
	return n, err
}

// Notes lists notes for an object, oldest first.
func (db *DB) Notes(ctx context.Context, objType, id string) ([]Note, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT id, body, created_at FROM notes WHERE object_type=? AND object_id=? ORDER BY created_at, id`, objType, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Note
	for rows.Next() {
		var n Note
		var ts int64
		if err := rows.Scan(&n.ID, &n.Body, &ts); err != nil {
			return nil, err
		}
		n.CreatedAt = fromUnix(ts)
		out = append(out, n)
	}
	return out, rows.Err()
}

func deleteObjectMeta(ctx context.Context, tx *sql.Tx, objType, id string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM tags WHERE object_type=? AND object_id=?`, objType, id); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM notes WHERE object_type=? AND object_id=?`, objType, id)
	return err
}

package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func nullString(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func unix(t time.Time) int64 { return t.Unix() }

func fromUnix(v int64) time.Time { return time.Unix(v, 0).UTC() }

// resolveRef resolves a user-supplied reference (exact ID, exact name, ID
// prefix or SHA-256 fingerprint prefix) to a single ID in table.
func resolveRef(ctx context.Context, q querier, table, ref string, hasSHA bool) (string, error) {
	return resolve(ctx, q, table, ref, hasSHA, true)
}

// resolve is resolveRef for tables that may lack a name column.
func resolve(ctx context.Context, q querier, table, ref string, hasSHA, hasName bool) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", fmt.Errorf("%w: empty identifier", ErrNotFound)
	}
	var id string
	exact := `SELECT id FROM ` + table + ` WHERE id = ?1`
	if hasName {
		exact += ` OR name = ?1`
	}
	err := q.QueryRowContext(ctx, exact, ref).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	norm := strings.ToLower(strings.ReplaceAll(ref, ":", ""))
	cond := `id LIKE ? ESCAPE '\'`
	args := []any{escapeLike(norm) + "%"}
	if hasSHA && len(norm) >= 8 {
		cond += ` OR sha256 LIKE ? ESCAPE '\'`
		args = append(args, escapeLike(norm)+"%")
	}
	if len(norm) < 4 {
		return "", fmt.Errorf("%w: %q (use at least 4 characters of an ID)", ErrNotFound, ref)
	}
	rows, err := q.QueryContext(ctx, `SELECT id FROM `+table+` WHERE `+cond+` LIMIT 2`, args...)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return "", err
		}
		ids = append(ids, s)
	}
	switch len(ids) {
	case 0:
		return "", fmt.Errorf("%w: %q", ErrNotFound, ref)
	case 1:
		return ids[0], nil
	}
	return "", fmt.Errorf("%w: %q matches several objects", ErrAmbiguous, ref)
}

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// EscapeLike escapes LIKE wildcards for use with ESCAPE '\'.
func EscapeLike(s string) string { return escapeLike(s) }

// prefixColumns qualifies a comma-separated column list with a table alias.
func prefixColumns(cols, alias string) string {
	parts := strings.Split(cols, ",")
	for i, p := range parts {
		parts[i] = alias + "." + strings.TrimSpace(p)
	}
	return strings.Join(parts, ", ")
}

func sortStrings(s []string) { sort.Strings(s) }

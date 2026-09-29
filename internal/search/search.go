// Package search compiles the inventory query language into parameterised
// SQL. Queries are whitespace-separated terms that must all match:
//
//	example.com            substring of name, CN, subject, issuer or a SAN
//	issuer:DigiCert        field substring match
//	expires:<30d           expires within 30 days (also >, <=, >=, dates)
//	algorithm:rsa          key algorithm
//	tag:production         exact tag
//	type:cert|key|ca|leaf  object kind
//	-tag:legacy            negation
//
// Values may be quoted: subject:"Example Org".
package search

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/matusso/sslknife/internal/config"
)

// Compiled holds SQL fragments for each object kind. A nil Where for a kind
// means that kind cannot match the query.
type Compiled struct {
	Certs *Clause
	Keys  *Clause
	SSH   *Clause
}

// Clause is a WHERE fragment with bound arguments.
type Clause struct {
	Where string
	Args  []any
}

// Fields lists the supported field names for help and completion.
var Fields = []string{"name", "cn", "subject", "issuer", "san", "serial", "fingerprint", "spki", "algorithm",
	"key", "tag", "type", "expires", "status", "ca", "source", "id"}

type term struct {
	neg   bool
	field string
	value string
}

// Tokenize splits a query into terms, honouring double quotes.
func tokenize(q string) ([]term, error) {
	var terms []term
	var cur strings.Builder
	inQuote := false
	flush := func() error {
		s := cur.String()
		cur.Reset()
		if s == "" {
			return nil
		}
		t := term{}
		if strings.HasPrefix(s, "-") && len(s) > 1 {
			t.neg, s = true, s[1:]
		}
		if f, v, ok := strings.Cut(s, ":"); ok && isField(f) {
			t.field, t.value = strings.ToLower(f), v
		} else {
			t.value = s
		}
		t.value = strings.Trim(t.value, `"`)
		if t.value == "" {
			return fmt.Errorf("empty value for %q", s)
		}
		terms = append(terms, t)
		return nil
	}
	for _, r := range q {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case unicode.IsSpace(r) && !inQuote:
			if err := flush(); err != nil {
				return nil, err
			}
		default:
			cur.WriteRune(r)
		}
	}
	if inQuote {
		return nil, errors.New("unterminated quote")
	}
	return terms, flush()
}

func isField(f string) bool {
	f = strings.ToLower(f)
	for _, x := range append(Fields, "fp", "sha256", "alg", "is") {
		if f == x {
			return true
		}
	}
	return false
}

func like(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(strings.ToLower(v)) + "%"
}

// Compile parses q. now is used for relative expiry expressions.
func Compile(q string, now time.Time) (*Compiled, error) {
	terms, err := tokenize(q)
	if err != nil {
		return nil, err
	}
	certs := &builder{}
	keys := &builder{}
	sshb := &builder{}
	onlySSH := false
	for _, t := range terms {
		cw, cargs, kw, kargs, err := compileTerm(t, now)
		if err != nil {
			return nil, err
		}
		certs.add(cw, cargs, t.neg)
		keys.add(kw, kargs, t.neg)
		sw, sargs := compileSSHTerm(t)
		sshb.add(sw, sargs, t.neg)
		if (t.field == "type" || t.field == "is") && strings.EqualFold(t.value, "ssh") && !t.neg {
			onlySSH = true
		}
	}
	c := &Compiled{Certs: certs.clause(), Keys: keys.clause(), SSH: sshb.clause()}
	if onlySSH {
		c.Certs, c.Keys = nil, nil
	}
	return c, nil
}

type builder struct {
	parts []string
	args  []any
	never bool
}

// add appends a condition. where == "" means the term cannot apply to this
// kind: a positive term then excludes the kind entirely, a negated one is a no-op.
func (b *builder) add(where string, args []any, neg bool) {
	if where == "" {
		if !neg {
			b.never = true
		}
		return
	}
	if neg {
		where = "NOT (" + where + ")"
	}
	b.parts = append(b.parts, "("+where+")")
	b.args = append(b.args, args...)
}

func (b *builder) clause() *Clause {
	if b.never {
		return nil
	}
	if len(b.parts) == 0 {
		return &Clause{Where: "1=1"}
	}
	return &Clause{Where: strings.Join(b.parts, " AND "), Args: b.args}
}

// compileSSHTerm maps a term onto the ssh_keys table (alias "s"). An empty
// clause means the term cannot match SSH keys.
func compileSSHTerm(t term) (string, []any) {
	lv := like(t.value)
	switch t.field {
	case "":
		return `lower(coalesce(s.name,'')) LIKE ? ESCAPE '\' OR lower(s.comment) LIKE ? ESCAPE '\' OR lower(s.type) LIKE ? ESCAPE '\'`, []any{lv, lv, lv}
	case "name":
		return `lower(coalesce(s.name,'')) LIKE ? ESCAPE '\'`, []any{lv}
	case "algorithm", "alg", "key":
		n := strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(t.value))
		n = strings.NewReplacer("p256", "nistp256", "p384", "nistp384", "p521", "nistp521").Replace(n)
		return `replace(lower(s.type), '-', '') LIKE ?`, []any{"%" + n + "%"}
	case "tag":
		return tagExists("s", "ssh"), []any{strings.ToLower(t.value)}
	case "fingerprint", "fp", "sha256":
		return `s.fingerprint_sha256 LIKE ?`, []any{"%" + strings.TrimPrefix(t.value, "SHA256:") + "%"}
	case "source":
		return `lower(s.source) LIKE ? ESCAPE '\'`, []any{lv}
	case "id":
		return `s.id LIKE ?`, []any{strings.ToLower(t.value) + "%"}
	case "type", "is":
		switch strings.ToLower(t.value) {
		case "ssh":
			return "1=1", nil
		case "private":
			return "s.secret_id IS NOT NULL", nil
		case "public":
			return "s.secret_id IS NULL", nil
		}
	}
	return "", nil
}

const sanExists = `EXISTS (SELECT 1 FROM certificate_sans s WHERE s.cert_id = c.id AND s.value LIKE ? ESCAPE '\')`

func tagExists(alias, objType string) string {
	return `EXISTS (SELECT 1 FROM tags t WHERE t.object_type = '` + objType + `' AND t.object_id = ` + alias + `.id AND t.tag = ?)`
}

func compileTerm(t term, now time.Time) (cw string, cargs []any, kw string, kargs []any, err error) {
	v := t.value
	lv := like(v)
	switch t.field {
	case "":
		cw = `lower(coalesce(c.name,'')) LIKE ? ESCAPE '\' OR lower(c.subject) LIKE ? ESCAPE '\' OR lower(c.issuer) LIKE ? ESCAPE '\' OR ` + sanExists
		cargs = []any{lv, lv, lv, lv}
		kw = `lower(coalesce(k.name,'')) LIKE ? ESCAPE '\' OR lower(k.description) LIKE ? ESCAPE '\' OR lower(k.comment) LIKE ? ESCAPE '\'`
		kargs = []any{lv, lv, lv}
	case "name":
		cw, cargs = `lower(coalesce(c.name,'')) LIKE ? ESCAPE '\'`, []any{lv}
		kw, kargs = `lower(coalesce(k.name,'')) LIKE ? ESCAPE '\'`, []any{lv}
	case "cn":
		cw, cargs = `lower(c.subject_cn) LIKE ? ESCAPE '\'`, []any{lv}
	case "subject":
		cw, cargs = `lower(c.subject) LIKE ? ESCAPE '\'`, []any{lv}
	case "issuer":
		cw, cargs = `lower(c.issuer) LIKE ? ESCAPE '\'`, []any{lv}
	case "san":
		cw, cargs = sanExists, []any{lv}
	case "serial":
		s := strings.ToUpper(strings.ReplaceAll(v, ":", ""))
		cw, cargs = `replace(c.serial, ':', '') LIKE ?`, []any{"%" + s + "%"}
	case "fingerprint", "fp", "sha256":
		s := strings.ToLower(strings.ReplaceAll(v, ":", ""))
		cw, cargs = `c.sha256 LIKE ? OR c.sha1 LIKE ?`, []any{s + "%", s + "%"}
	case "spki":
		s := strings.ToLower(strings.ReplaceAll(v, ":", ""))
		cw, cargs = `c.spki_sha256 LIKE ?`, []any{s + "%"}
		kw, kargs = `k.spki_sha256 LIKE ?`, []any{s + "%"}
	case "algorithm", "alg", "key":
		n := strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(v))
		ln := "%" + n + "%"
		cw, cargs = `replace(replace(lower(c.key_description), '-', ''), ' ', '') LIKE ? OR lower(c.signature_algorithm) LIKE ?`, []any{ln, ln}
		kw, kargs = `replace(replace(lower(k.description), '-', ''), ' ', '') LIKE ?`, []any{ln}
	case "tag":
		tag := strings.ToLower(v)
		cw, cargs = tagExists("c", "cert"), []any{tag}
		kw, kargs = tagExists("k", "key"), []any{tag}
	case "source":
		cw, cargs = `lower(c.source) LIKE ? ESCAPE '\'`, []any{lv}
		kw, kargs = `lower(k.source) LIKE ? ESCAPE '\'`, []any{lv}
	case "id":
		cw, cargs = `c.id LIKE ?`, []any{strings.ToLower(v) + "%"}
		kw, kargs = `k.id LIKE ?`, []any{strings.ToLower(v) + "%"}
	case "type", "is":
		switch strings.ToLower(v) {
		case "cert", "certificate", "certs":
			cw = "1=1"
		case "key", "keys":
			kw = "1=1"
		case "private":
			kw = "k.secret_id IS NOT NULL"
		case "public":
			kw = "k.secret_id IS NULL"
		case "ca":
			cw = "c.is_ca = 1"
		case "leaf":
			cw = "c.is_ca = 0"
		case "root", "self-signed", "selfsigned":
			cw = "c.self_signed = 1"
		case "ssh":
			// Handled by compileSSHTerm; certificates and keys never match.
		default:
			return "", nil, "", nil, fmt.Errorf("unknown type %q (use cert, key, private, public, ca, leaf, root, ssh)", v)
		}
	case "ca":
		switch strings.ToLower(v) {
		case "true", "yes", "1":
			cw = "c.is_ca = 1"
		case "false", "no", "0":
			cw = "c.is_ca = 0"
		default:
			return "", nil, "", nil, fmt.Errorf("ca: expects true or false")
		}
	case "status":
		n := now.Unix()
		switch strings.ToLower(v) {
		case "expired":
			cw, cargs = "c.not_after <= ?", []any{n}
		case "valid":
			cw, cargs = "c.not_after > ? AND c.not_before <= ?", []any{n, n}
		case "expiring":
			cw, cargs = "c.not_after > ? AND c.not_after <= ?", []any{n, now.Add(30 * 24 * time.Hour).Unix()}
		case "notyetvalid", "not_yet_valid", "future":
			cw, cargs = "c.not_before > ?", []any{n}
		default:
			return "", nil, "", nil, fmt.Errorf("unknown status %q (use expired, expiring, valid, future)", v)
		}
	case "expires":
		w, a, err := compileExpires(v, now)
		if err != nil {
			return "", nil, "", nil, err
		}
		cw, cargs = w, a
	default:
		return "", nil, "", nil, fmt.Errorf("unknown field %q", t.field)
	}
	return cw, cargs, kw, kargs, nil
}

// compileExpires handles "<30d", ">=1y", "<2027-01-01", "30d" (= "<30d") and "expired".
func compileExpires(v string, now time.Time) (string, []any, error) {
	if strings.EqualFold(v, "expired") {
		return "c.not_after <= ?", []any{now.Unix()}, nil
	}
	op := "<"
	for _, p := range []string{"<=", ">=", "<", ">", "="} {
		if strings.HasPrefix(v, p) {
			op, v = p, strings.TrimSpace(v[len(p):])
			break
		}
	}
	var at time.Time
	if d, err := time.Parse(time.DateOnly, v); err == nil {
		at = d
	} else if dur, err := config.ParseDuration(v); err == nil {
		at = now.Add(dur)
	} else {
		return "", nil, fmt.Errorf("expires: %q is neither a duration (30d) nor a date (2027-01-31)", v)
	}
	switch op {
	case "<", "<=":
		// "expires within": exclude certificates that are already expired.
		return "c.not_after " + op + " ? AND c.not_after > ?", []any{at.Unix(), now.Unix()}, nil
	case "=":
		day := at.Truncate(24 * time.Hour)
		return "c.not_after >= ? AND c.not_after < ?", []any{day.Unix(), day.Add(24 * time.Hour).Unix()}, nil
	}
	return "c.not_after " + op + " ?", []any{at.Unix()}, nil
}

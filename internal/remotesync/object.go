// Package remotesync keeps the local encrypted inventory in step with a
// shared remote store (HashiCorp Vault KV v2), so several devices running
// SSLKnife see the same certificates, keys and SSH keys.
//
// The local database stays the working copy: search, TLS history and CT
// monitoring keep running on SQLite. A sync is a three-way merge between the
// local inventory, the remote manifest and the state both sides last agreed
// on (database table remote_sync). See docs/DESIGN.md §13.
package remotesync

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/matusso/sslknife/internal/database"
)

// Object kinds. They double as the tags/notes object type in the database.
const (
	KindKey  = "key"
	KindCert = "cert"
	KindSSH  = "ssh"
)

// kindOrder applies keys before certificates so imported certificates link
// to their private keys straight away.
var kindOrder = map[string]int{KindKey: 0, KindCert: 1, KindSSH: 2}

// Key identifies an object across devices by content, never by local ID.
type Key = database.SyncKey

// Note is a synced note.
type Note struct {
	ID        string    `json:"id"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

// Meta is the part of an object that can change after import. Its digest
// decides whether a side changed since the last sync.
type Meta struct {
	Name       string   `json:"name"`
	Comment    string   `json:"comment"`
	Tags       []string `json:"tags"`
	Notes      []Note   `json:"notes"`
	HasPrivate bool     `json:"has_private"`
}

// Object is one inventory object in its device-independent form.
type Object struct {
	Kind  string
	Ident string
	// Public is the certificate DER, the key's SubjectPublicKeyInfo DER, or
	// the SSH authorized_keys line.
	Public []byte
	// Private is the PKCS#8 DER or the SSH private key file; nil when not
	// loaded or not present (see Meta.HasPrivate).
	Private             []byte
	PassphraseProtected bool
	Source              string
	ImportedAt          time.Time
	Meta
}

// Key returns the object's identity.
func (o *Object) Key() Key { return Key{Kind: o.Kind, Ident: o.Ident} }

func (o *Object) normalize() {
	o.Tags = slices.Clone(o.Tags)
	slices.Sort(o.Tags)
	o.Tags = slices.Compact(o.Tags)
	o.Notes = slices.Clone(o.Notes)
	for i := range o.Notes {
		o.Notes[i].CreatedAt = o.Notes[i].CreatedAt.UTC().Truncate(time.Second)
	}
	slices.SortFunc(o.Notes, func(a, b Note) int { return strings.Compare(a.ID, b.ID) })
	o.Notes = slices.CompactFunc(o.Notes, func(a, b Note) bool { return a.ID == b.ID })
	if o.Tags == nil {
		o.Tags = []string{}
	}
	if o.Notes == nil {
		o.Notes = []Note{}
	}
}

// Digest is a stable hash of the identity and metadata. Private material
// is represented only by HasPrivate: the same public key always has the
// same private key, and Transit ciphertexts differ on every write.
func (o *Object) Digest() string {
	o.normalize()
	b, _ := json.Marshal(struct {
		Kind  string `json:"kind"`
		Ident string `json:"ident"`
		Meta
	}{o.Kind, o.Ident, o.Meta})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}

// Label is a short human description for reports.
func (o *Object) Label() string {
	if o.Name != "" {
		return o.Name
	}
	return shortIdent(o.Ident)
}

func shortIdent(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

// SSHIdent converts an OpenSSH "SHA256:<base64>" fingerprint into the hex
// form used in remote paths (base64 may contain "/").
func SSHIdent(fp string) (string, error) {
	b64, ok := strings.CutPrefix(fp, "SHA256:")
	if !ok {
		return "", fmt.Errorf("unexpected SSH fingerprint %q", fp)
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(b64, "="))
	if err != nil || len(raw) != sha256.Size {
		return "", fmt.Errorf("unexpected SSH fingerprint %q", fp)
	}
	return hex.EncodeToString(raw), nil
}

// sshFingerprint reverses SSHIdent.
func sshFingerprint(ident string) (string, error) {
	raw, err := hex.DecodeString(ident)
	if err != nil || len(raw) != sha256.Size {
		return "", fmt.Errorf("invalid SSH key identifier %q", ident)
	}
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(raw), nil
}

func validIdent(k Key) error {
	if _, ok := kindOrder[k.Kind]; !ok {
		return fmt.Errorf("unknown object kind %q", k.Kind)
	}
	if len(k.Ident) != 64 {
		return fmt.Errorf("invalid %s identifier %q", k.Kind, k.Ident)
	}
	if _, err := hex.DecodeString(k.Ident); err != nil {
		return fmt.Errorf("invalid %s identifier %q", k.Kind, k.Ident)
	}
	return nil
}

// Entry is one manifest line: the digest and KV version of an object.
type Entry struct {
	Digest  string `json:"digest"`
	Version int    `json:"version"`
}

// Manifest lists every object in the remote store. Devices read it once per
// sync instead of fetching every object.
type Manifest map[Key]Entry

// ErrConflict means another device changed the remote during this sync;
// the sync is retried from a fresh manifest.
var ErrConflict = errors.New("remote changed during sync")

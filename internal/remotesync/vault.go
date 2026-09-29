package remotesync

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	skcrypto "github.com/matusso/sslknife/internal/crypto"
	"github.com/matusso/sslknife/internal/vaultkv"
)

// Remote layout below the configured path:
//
//	<path>/manifest              object list with digests and versions
//	<path>/certificates/<sha256> certificate PEM and metadata
//	<path>/keys/<spki-sha256>    public key PEM, private key PEM, metadata
//	<path>/ssh/<sha256-hex>      authorized_keys line, private key file, metadata
//
// Values are plain JSON so they can be read with `vault kv get` as well.
const formatVersion = 1

var kindDirs = map[string]string{KindCert: "certificates", KindKey: "keys", KindSSH: "ssh"}

// VaultStore keeps the shared inventory in a HashiCorp Vault KV v2 mount.
type VaultStore struct {
	Client *vaultkv.Client
	Mount  string
	Path   string
	// Transit, when set, encrypts private keys with a Vault Transit key
	// before they are written, so KV readers without transit decrypt
	// permission only see ciphertext.
	Transit *vaultkv.Transit
	// Namespace is part of the identity only.
	Namespace string
}

func (s *VaultStore) kv() *vaultkv.KV { return s.Client.KV(s.Mount) }

func (s *VaultStore) path(parts ...string) string {
	return strings.Trim(s.Path, "/") + "/" + strings.Join(parts, "/")
}

// Identity implements Store.
func (s *VaultStore) Identity() string {
	return strings.Join([]string{"vault", s.Client.Address(), s.Namespace, strings.Trim(s.Mount, "/"), strings.Trim(s.Path, "/")}, "|")
}

// storeErr marks errors that affect every object (permission, reachability)
// as fatal and maps check-and-set failures to ErrConflict.
func storeErr(err error) error {
	switch {
	case errors.Is(err, vaultkv.ErrConflict):
		return fmt.Errorf("%w: %w", ErrConflict, err)
	case errors.Is(err, vaultkv.ErrPermission), errors.Is(err, vaultkv.ErrUnavailable):
		return Fatal(err)
	}
	return err
}

type manifestDoc struct {
	Format  int              `json:"format"`
	Updated time.Time        `json:"updated"`
	Objects map[string]Entry `json:"objects"`
}

// Manifest implements Store.
func (s *VaultStore) Manifest(ctx context.Context) (Manifest, int, error) {
	sec, err := s.kv().Get(ctx, s.path("manifest"))
	if errors.Is(err, vaultkv.ErrNotFound) {
		v := 0
		if sec != nil {
			v = sec.Version
		}
		return Manifest{}, v, nil
	}
	if err != nil {
		return nil, 0, storeErr(err)
	}
	var d manifestDoc
	if err := fromMap(sec.Data, &d); err != nil {
		return nil, 0, fmt.Errorf("remote manifest: %w", err)
	}
	if d.Format > formatVersion {
		return nil, 0, Fatal(fmt.Errorf("the remote inventory uses format %d; upgrade sslknife", d.Format))
	}
	m := Manifest{}
	for name, e := range d.Objects {
		kind, ident, ok := strings.Cut(name, ":")
		k := Key{Kind: kind, Ident: ident}
		if !ok || validIdent(k) != nil {
			continue
		}
		m[k] = e
	}
	return m, sec.Version, nil
}

// PutManifest implements Store.
func (s *VaultStore) PutManifest(ctx context.Context, m Manifest, cas int) error {
	d := manifestDoc{Format: formatVersion, Updated: time.Now().UTC().Truncate(time.Second), Objects: map[string]Entry{}}
	for k, e := range m {
		d.Objects[k.Kind+":"+k.Ident] = e
	}
	data, err := toMap(d)
	if err != nil {
		return err
	}
	_, err = s.kv().Put(ctx, s.path("manifest"), data, cas)
	return storeErr(err)
}

type noteDoc struct {
	ID        string    `json:"id"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

// objectDoc is the stored form of an Object.
type objectDoc struct {
	Format     int       `json:"format"`
	Kind       string    `json:"kind"`
	Ident      string    `json:"ident"`
	Name       string    `json:"name"`
	Comment    string    `json:"comment"`
	Tags       []string  `json:"tags"`
	Notes      []noteDoc `json:"notes"`
	Source     string    `json:"source,omitempty"`
	ImportedAt time.Time `json:"imported_at"`
	HasPrivate bool      `json:"has_private"`

	Certificate string `json:"certificate,omitempty"` // PEM
	PublicKey   string `json:"public_key,omitempty"`  // PEM, or authorized_keys line for SSH
	Fingerprint string `json:"fingerprint,omitempty"` // SSH SHA256:… fingerprint
	PrivateKey  string `json:"private_key,omitempty"` // PKCS#8 PEM, or the SSH key file
	// PrivateKeyTransit replaces PrivateKey when Transit encryption is on;
	// TransitKey names the key ("<mount>/<key>") needed to decrypt it.
	PrivateKeyTransit   string `json:"private_key_transit,omitempty"`
	TransitKey          string `json:"transit_key,omitempty"`
	PassphraseProtected bool   `json:"passphrase_protected,omitempty"`
}

// Get implements Store.
func (s *VaultStore) Get(ctx context.Context, k Key) (*Object, int, error) {
	if err := validIdent(k); err != nil {
		return nil, 0, err
	}
	sec, err := s.kv().Get(ctx, s.path(kindDirs[k.Kind], k.Ident))
	if err != nil {
		return nil, 0, storeErr(err)
	}
	var d objectDoc
	if err := fromMap(sec.Data, &d); err != nil {
		return nil, 0, fmt.Errorf("remote object %s/%s: %w", k.Kind, k.Ident, err)
	}
	o := &Object{Kind: d.Kind, Ident: d.Ident, Source: d.Source, ImportedAt: d.ImportedAt, PassphraseProtected: d.PassphraseProtected,
		Meta: Meta{Name: d.Name, Comment: d.Comment, Tags: d.Tags, HasPrivate: d.HasPrivate}}
	for _, n := range d.Notes {
		o.Notes = append(o.Notes, Note(n))
	}
	switch d.Kind {
	case KindCert:
		o.Public, err = pemBytes(d.Certificate, "CERTIFICATE")
	case KindKey:
		o.Public, err = pemBytes(d.PublicKey, "PUBLIC KEY")
	case KindSSH:
		o.Public = []byte(d.PublicKey)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("remote object %s/%s: %w", k.Kind, k.Ident, err)
	}
	if o.Private, err = s.openPrivate(ctx, &d); err != nil {
		return nil, 0, fmt.Errorf("remote object %s/%s: %w", k.Kind, k.Ident, err)
	}
	o.HasPrivate = o.Private != nil
	return o, sec.Version, nil
}

func (s *VaultStore) openPrivate(ctx context.Context, d *objectDoc) ([]byte, error) {
	var raw []byte
	switch {
	case d.PrivateKeyTransit != "":
		t := s.Transit
		if d.TransitKey != "" && (t == nil || t.Name() != d.TransitKey) {
			mount, key, ok := cutLast(d.TransitKey, "/")
			if !ok {
				return nil, fmt.Errorf("invalid transit key %q", d.TransitKey)
			}
			t = s.Client.Transit(mount, key)
		}
		if t == nil {
			return nil, errors.New("private key is Transit-encrypted but no transit key is known")
		}
		pt, err := t.Decrypt(ctx, d.PrivateKeyTransit)
		if err != nil {
			return nil, storeErr(fmt.Errorf("transit decrypt: %w", err))
		}
		raw = pt
	case d.PrivateKey != "":
		raw = []byte(d.PrivateKey)
	default:
		return nil, nil
	}
	if d.Kind == KindSSH {
		return raw, nil // the key file, stored as-is
	}
	der, err := pemBytes(string(raw), "PRIVATE KEY")
	skcrypto.Zero(raw)
	return der, err
}

func cutLast(s, sep string) (string, string, bool) {
	i := strings.LastIndex(s, sep)
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// Put implements Store.
func (s *VaultStore) Put(ctx context.Context, o *Object, cas int) (int, error) {
	if err := validIdent(o.Key()); err != nil {
		return 0, err
	}
	o.normalize()
	d := objectDoc{Format: formatVersion, Kind: o.Kind, Ident: o.Ident, Name: o.Name, Comment: o.Comment, Tags: o.Tags,
		Notes: []noteDoc{}, Source: o.Source, ImportedAt: o.ImportedAt.UTC(), HasPrivate: o.HasPrivate,
		PassphraseProtected: o.PassphraseProtected}
	for _, n := range o.Notes {
		d.Notes = append(d.Notes, noteDoc(n))
	}
	var private []byte
	switch o.Kind {
	case KindCert:
		d.Certificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: o.Public}))
	case KindKey:
		d.PublicKey = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: o.Public}))
		if o.Private != nil {
			private = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: o.Private})
		}
	case KindSSH:
		d.PublicKey = string(o.Public)
		d.Fingerprint, _ = sshFingerprint(o.Ident)
		if o.Private != nil {
			private = append([]byte(nil), o.Private...)
		}
	}
	defer skcrypto.Zero(private)
	if o.HasPrivate && private == nil {
		return 0, fmt.Errorf("%s %s: private key not loaded", o.Kind, o.Ident)
	}
	if private != nil {
		if s.Transit != nil {
			ct, err := s.Transit.Encrypt(ctx, private)
			if err != nil {
				return 0, storeErr(fmt.Errorf("transit encrypt: %w", err))
			}
			d.PrivateKeyTransit, d.TransitKey = ct, s.Transit.Name()
		} else {
			d.PrivateKey = string(private)
		}
	}
	data, err := toMap(d)
	if err != nil {
		return 0, err
	}
	v, err := s.kv().Put(ctx, s.path(kindDirs[o.Kind], o.Ident), data, cas)
	return v, storeErr(err)
}

// Delete implements Store.
func (s *VaultStore) Delete(ctx context.Context, k Key) error {
	if err := validIdent(k); err != nil {
		return err
	}
	return storeErr(s.kv().Destroy(ctx, s.path(kindDirs[k.Kind], k.Ident)))
}

func pemBytes(s, typ string) ([]byte, error) {
	b, _ := pem.Decode([]byte(s))
	if b == nil || b.Type != typ {
		return nil, fmt.Errorf("expected a %s PEM block", typ)
	}
	return b.Bytes, nil
}

func toMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	err = json.Unmarshal(b, &m)
	return m, err
}

func fromMap(m map[string]any, v any) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

package remotesync

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/matusso/sslknife/internal/certificate"
	skcrypto "github.com/matusso/sslknife/internal/crypto"
	"github.com/matusso/sslknife/internal/database"
	"github.com/matusso/sslknife/internal/inventory"
	"github.com/matusso/sslknife/internal/keys"
	"github.com/matusso/sslknife/internal/sshkeys"
)

// local is a local object together with its database row ID.
type local struct {
	*Object
	id string
}

// loadLocal reads the synced object kinds from the database, or only the
// one object when only is set. Private material is not loaded; see
// loadPrivate.
func loadLocal(ctx context.Context, db *database.DB, only *Key) (map[Key]*local, error) {
	out := map[Key]*local{}
	want := func(kind, col, value string) (string, []any, bool) {
		if only == nil {
			return "", nil, true
		}
		if only.Kind != kind {
			return "", nil, false
		}
		return col + " = ?", []any{value}, true
	}
	notes := func(kind, id string) ([]Note, error) {
		ns, err := db.Notes(ctx, kind, id)
		if err != nil {
			return nil, err
		}
		var out []Note
		for _, n := range ns {
			out = append(out, Note{ID: n.ID, Body: n.Body, CreatedAt: n.CreatedAt})
		}
		return out, nil
	}
	var ident string
	if only != nil {
		ident = only.Ident
	}
	var keys []*database.Key
	var err error
	if where, args, ok := want(KindKey, "k.spki_sha256", ident); ok {
		if keys, err = db.QueryKeys(ctx, where, args); err != nil {
			return nil, err
		}
	}
	for _, k := range keys {
		o := &Object{Kind: KindKey, Ident: k.SPKISHA256, Public: k.PublicDER, Source: k.Source, ImportedAt: k.ImportedAt,
			Meta: Meta{Name: k.Name, Comment: k.Comment, Tags: k.Tags, HasPrivate: k.HasPrivate()}}
		if o.Notes, err = notes(KindKey, k.ID); err != nil {
			return nil, err
		}
		out[o.Key()] = &local{Object: o, id: k.ID}
	}
	var certs []*database.Certificate
	if where, args, ok := want(KindCert, "c.sha256", ident); ok {
		if certs, err = db.QueryCertificates(ctx, where, args, ""); err != nil {
			return nil, err
		}
	}
	for _, c := range certs {
		o := &Object{Kind: KindCert, Ident: c.SHA256, Public: c.DER, Source: c.Source, ImportedAt: c.ImportedAt,
			Meta: Meta{Name: c.Name, Comment: c.Comment, Tags: c.Tags}}
		if o.Notes, err = notes(KindCert, c.ID); err != nil {
			return nil, err
		}
		out[o.Key()] = &local{Object: o, id: c.ID}
	}
	var sshKeys []*database.SSHKey
	fp := ""
	if only != nil && only.Kind == KindSSH {
		if fp, err = sshFingerprint(ident); err != nil {
			return nil, err
		}
	}
	if where, args, ok := want(KindSSH, "s.fingerprint_sha256", fp); ok {
		if sshKeys, err = db.QuerySSHKeys(ctx, where, args); err != nil {
			return nil, err
		}
	}
	for _, k := range sshKeys {
		ident, err := SSHIdent(k.FingerprintSHA256)
		if err != nil {
			return nil, err
		}
		o := &Object{Kind: KindSSH, Ident: ident, Public: []byte(k.PublicKey), PassphraseProtected: k.PassphraseProtected,
			Source: k.Source, ImportedAt: k.ImportedAt,
			Meta: Meta{Name: k.Name, Comment: k.Comment, Tags: k.Tags, HasPrivate: k.HasPrivate()}}
		if o.Notes, err = notes(KindSSH, k.ID); err != nil {
			return nil, err
		}
		out[o.Key()] = &local{Object: o, id: k.ID}
	}
	return out, nil
}

// loadPrivate fills l.Private. The caller zeroes it after use.
func loadPrivate(ctx context.Context, db *database.DB, l *local) error {
	if !l.HasPrivate || l.Private != nil {
		return nil
	}
	var err error
	switch l.Kind {
	case KindKey:
		var k *database.Key
		if k, err = db.GetKey(ctx, l.id); err == nil {
			l.Private, err = db.PrivateKeyDER(ctx, k)
		}
	case KindSSH:
		var k *database.SSHKey
		if k, err = db.GetSSHKey(ctx, l.id); err == nil {
			l.Private, err = db.SSHPrivateKey(ctx, k)
		}
	}
	return err
}

// importObject creates a remote object that does not exist locally.
func importObject(ctx context.Context, inv *inventory.Service, o *Object) error {
	opts := inventory.ImportOptions{Name: o.Name, Tags: o.Tags, Source: o.Source, Comment: o.Comment}
	if opts.Source == "" {
		opts.Source = "remote"
	}
	var objID string
	err := withNameFallback(&opts.Name, func() error {
		switch o.Kind {
		case KindKey:
			var res inventory.KeyResult
			var err error
			if o.Private != nil {
				priv, perr := x509.ParsePKCS8PrivateKey(o.Private)
				if perr != nil {
					return fmt.Errorf("remote private key: %w", perr)
				}
				res, err = inv.ImportPrivateKey(ctx, priv, opts)
			} else {
				pub, perr := x509.ParsePKIXPublicKey(o.Public)
				if perr != nil {
					return fmt.Errorf("remote public key: %w", perr)
				}
				res, err = inv.ImportPublicKey(ctx, pub, opts)
			}
			if err == nil {
				objID = res.Key.ID
			}
			return err
		case KindCert:
			c, err := x509.ParseCertificate(o.Public)
			if err != nil {
				return fmt.Errorf("remote certificate: %w", err)
			}
			res, err := inv.ImportCertificate(ctx, c, opts)
			if err == nil {
				objID = res.Cert.ID
			}
			return err
		case KindSSH:
			it, err := sshItem(o)
			if err != nil {
				return err
			}
			k, _, err := inv.ImportSSHKey(ctx, it, opts, true)
			if err == nil {
				objID = k.ID
			}
			return err
		}
		return fmt.Errorf("unknown object kind %q", o.Kind)
	})
	if err != nil {
		return err
	}
	for _, n := range o.Notes {
		if err := inv.DB.PutNote(ctx, o.Kind, objID, database.Note{ID: n.ID, Body: n.Body, CreatedAt: n.CreatedAt}); err != nil {
			return err
		}
	}
	return nil
}

func sshItem(o *Object) (sshkeys.Item, error) {
	src := o.Public
	if o.Private != nil {
		src = o.Private
	}
	items, err := sshkeys.Parse(src)
	if err != nil {
		return sshkeys.Item{}, fmt.Errorf("remote SSH key: %w", err)
	}
	it := items[0]
	if it.Kind == sshkeys.KindPrivate && it.Public == nil {
		// Legacy encrypted PEM keys do not carry the public key; take it
		// from the synced authorized_keys line.
		pub, err := sshkeys.Parse(o.Public)
		if err != nil {
			return sshkeys.Item{}, fmt.Errorf("remote SSH key: %w", err)
		}
		it.Public = pub[0].Public
	}
	return it, nil
}

// withNameFallback runs fn, and when the name is already taken on this
// device runs it again without the name rather than failing the object.
func withNameFallback(name *string, fn func() error) error {
	err := fn()
	if err != nil && *name != "" && strings.Contains(err.Error(), "already exists") {
		*name = ""
		return fn()
	}
	return err
}

// applyObject updates an existing local object from the remote one. With
// merge set both sides changed: names and comments prefer the remote value
// when it is set, and tags are united instead of replaced.
func applyObject(ctx context.Context, db *database.DB, l *local, o *Object, merge bool) error {
	if o.Private != nil && !l.HasPrivate {
		var err error
		switch o.Kind {
		case KindKey:
			if _, perr := x509.ParsePKCS8PrivateKey(o.Private); perr != nil {
				return fmt.Errorf("remote private key: %w", perr)
			}
			err = db.Tx(ctx, func(tx *sql.Tx) error { return db.AttachPrivate(ctx, tx, l.id, o.Private) })
		case KindSSH:
			err = db.AttachSSHPrivate(ctx, l.id, o.Private, o.PassphraseProtected)
		}
		if err != nil {
			return err
		}
	}
	name, comment := o.Name, o.Comment
	tags := o.Tags
	if merge {
		if name == "" {
			name = l.Name
		}
		if comment == "" {
			comment = l.Comment
		}
		tags = append(slices.Clone(l.Tags), o.Tags...)
	}
	var np, cp *string
	if name != l.Name {
		np = &name
	}
	if comment != l.Comment {
		cp = &comment
	}
	update := func(n, c *string) error {
		switch o.Kind {
		case KindKey:
			return db.UpdateKeyMeta(ctx, l.id, n, c)
		case KindCert:
			return db.UpdateCertificateMeta(ctx, l.id, n, c)
		default:
			return db.UpdateSSHKeyMeta(ctx, l.id, n, c)
		}
	}
	if np != nil || cp != nil {
		err := update(np, cp)
		if err != nil && np != nil && strings.Contains(err.Error(), "already exists") {
			// Keep the local name; the conflict is reported by the next push.
			err = update(nil, cp)
		}
		if err != nil {
			return err
		}
	}
	var add, remove []string
	for _, t := range tags {
		if !slices.Contains(l.Tags, t) {
			add = append(add, t)
		}
	}
	for _, t := range l.Tags {
		if !slices.Contains(tags, t) {
			remove = append(remove, t)
		}
	}
	if len(add) > 0 {
		if err := db.AddTags(ctx, o.Kind, l.id, add); err != nil {
			return err
		}
	}
	if len(remove) > 0 {
		if err := db.RemoveTags(ctx, o.Kind, l.id, remove); err != nil {
			return err
		}
	}
	for _, n := range o.Notes {
		if !slices.ContainsFunc(l.Notes, func(x Note) bool { return x.ID == n.ID }) {
			if err := db.PutNote(ctx, o.Kind, l.id, database.Note{ID: n.ID, Body: n.Body, CreatedAt: n.CreatedAt}); err != nil {
				return err
			}
		}
	}
	return nil
}

// deleteLocal removes an object deleted on another device.
func deleteLocal(ctx context.Context, db *database.DB, l *local) error {
	var err error
	switch l.Kind {
	case KindKey:
		err = db.DeleteKey(ctx, l.id)
	case KindCert:
		err = db.DeleteCertificate(ctx, l.id)
	case KindSSH:
		err = db.DeleteSSHKey(ctx, l.id)
	}
	if errors.Is(err, database.ErrNotFound) {
		return nil
	}
	return err
}

func zeroPrivate(o *Object) {
	if o != nil {
		skcrypto.Zero(o.Private)
		o.Private = nil
	}
}

// verifyObject checks that a remote object's content matches its identity,
// and that its private key belongs to its public key, before anything is
// written locally. A remote cannot plant a different certificate under a
// known fingerprint or attach a foreign private key to a stored key.
func verifyObject(o *Object) error {
	var got string
	switch o.Kind {
	case KindCert:
		c, err := x509.ParseCertificate(o.Public)
		if err != nil {
			return fmt.Errorf("remote certificate: %w", err)
		}
		got = certificate.Fingerprint(c).SHA256
	case KindKey:
		spki := o.Public
		if o.Private != nil {
			priv, err := x509.ParsePKCS8PrivateKey(o.Private)
			if err != nil {
				return fmt.Errorf("remote private key: %w", err)
			}
			pub, err := keys.Public(priv)
			if err != nil {
				return err
			}
			if spki, err = keys.SPKI(pub); err != nil {
				return err
			}
			if keys.SPKIFingerprint(o.Public) != keys.SPKIFingerprint(spki) {
				return errors.New("remote private key does not match its public key")
			}
		}
		got = keys.SPKIFingerprint(spki)
	case KindSSH:
		it, err := sshItem(o)
		if err != nil {
			return err
		}
		if it.Kind == sshkeys.KindPrivate && it.Private != nil {
			pub, err := sshkeys.Parse(o.Public)
			if err != nil || string(pub[0].Public.Marshal()) != string(it.Public.Marshal()) {
				return errors.New("remote SSH private key does not match its public key")
			}
		}
		if got, err = SSHIdent(sshkeys.Describe(it).FingerprintSHA256); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown object kind %q", o.Kind)
	}
	if got != o.Ident {
		return fmt.Errorf("remote %s content does not match its identifier %s", o.Kind, shortIdent(o.Ident))
	}
	return nil
}

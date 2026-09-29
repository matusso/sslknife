package remotesync

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matusso/sslknife/internal/certificate"
	skcrypto "github.com/matusso/sslknife/internal/crypto"
	"github.com/matusso/sslknife/internal/database"
	"github.com/matusso/sslknife/internal/inventory"
	"github.com/matusso/sslknife/internal/keys"
	"github.com/matusso/sslknife/internal/sshkeys"
	"github.com/matusso/sslknife/internal/vaultkv"
	"github.com/matusso/sslknife/internal/vaultkv/vaulttest"
)

type device struct {
	inv   *inventory.Service
	store *VaultStore
}

func newDevice(t *testing.T, srv *vaulttest.Server, transit bool) *device {
	t.Helper()
	db, err := database.Create(context.Background(), filepath.Join(t.TempDir(), "inv.db"), skcrypto.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	c, err := vaultkv.New(vaultkv.Options{Address: srv.URL, Token: srv.Token})
	if err != nil {
		t.Fatal(err)
	}
	st := &VaultStore{Client: c, Mount: "secret", Path: "sslknife"}
	if transit {
		st.Transit = c.Transit("transit", srv.Transit)
	}
	return &device{inv: inventory.New(db), store: st}
}

func (d *device) sync(t *testing.T) *Report {
	t.Helper()
	rep, err := Sync(context.Background(), d.inv, d.store, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rep.Changes {
		if c.Error != "" {
			t.Fatalf("sync change failed: %+v", c)
		}
	}
	return rep
}

func leafWithKey(t *testing.T, cn string) (*x509.Certificate, any) {
	t.Helper()
	k, err := keys.Generate(keys.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	c, err := certificate.Create(certificate.Request{Profile: certificate.ProfileServer, Subject: pkix.Name{CommonName: cn},
		SANs: []string{cn}, Validity: 30 * 24 * time.Hour, Key: k, PathLen: -1})
	if err != nil {
		t.Fatal(err)
	}
	return c, k
}

func TestSyncBetweenDevices(t *testing.T) {
	for _, transit := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "transit"}[transit], func(t *testing.T) {
			testSyncBetweenDevices(t, transit)
		})
	}
}

func testSyncBetweenDevices(t *testing.T, transit bool) {
	ctx := context.Background()
	srv := vaulttest.New(t)
	a, b := newDevice(t, srv, transit), newDevice(t, srv, transit)

	// Device A imports a certificate with its key and an SSH key.
	cert, key := leafWithKey(t, "api.example.com")
	if _, err := a.inv.ImportPrivateKey(ctx, key, inventory.ImportOptions{Name: "api-key"}); err != nil {
		t.Fatal(err)
	}
	res, err := a.inv.ImportCertificate(ctx, cert, inventory.ImportOptions{Name: "api", Tags: []string{"prod"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.inv.DB.AddNote(ctx, "cert", res.Cert.ID, "renew via ACME"); err != nil {
		t.Fatal(err)
	}
	_, sshPriv, _, err := sshkeys.Generate(keys.Ed25519, "deploy@ci", nil)
	if err != nil {
		t.Fatal(err)
	}
	items, err := sshkeys.Parse(sshPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.inv.ImportSSHKey(ctx, items[0], inventory.ImportOptions{Name: "deploy"}, true); err != nil {
		t.Fatal(err)
	}

	if rep := a.sync(t); rep.Count(ActPush) != 3 || rep.Objects != 3 {
		t.Fatalf("first push: %+v", rep)
	}
	// Private keys never reach the KV store in the clear with Transit.
	for _, p := range srv.Paths() {
		d := srv.Data(p)
		if pk, _ := d["private_key"].(string); transit && pk != "" {
			t.Fatalf("%s holds a plaintext private key with transit enabled", p)
		}
		if transit && strings.HasPrefix(p, "sslknife/keys/") && d["private_key_transit"] == nil {
			t.Fatalf("%s lacks the transit ciphertext", p)
		}
	}

	// Device B pulls everything, including private keys, links and notes.
	if rep := b.sync(t); rep.Count(ActPull) != 3 {
		t.Fatalf("pull: %+v", rep)
	}
	row, _, err := b.inv.Certificate(ctx, "api")
	if err != nil {
		t.Fatal(err)
	}
	if row.KeyID == "" || len(row.Tags) != 1 || row.Tags[0] != "prod" {
		t.Fatalf("pulled certificate not linked or tagged: %+v", row)
	}
	notes, _ := b.inv.DB.Notes(ctx, "cert", row.ID)
	if len(notes) != 1 || notes[0].Body != "renew via ACME" {
		t.Fatalf("notes: %+v", notes)
	}
	k, err := b.inv.DB.GetKey(ctx, "api-key")
	if err != nil || !k.HasPrivate() {
		t.Fatalf("key: %+v %v", k, err)
	}
	if _, err := b.inv.PrivateKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	sk, err := b.inv.DB.GetSSHKey(ctx, "deploy")
	if err != nil || !sk.HasPrivate() {
		t.Fatalf("ssh: %+v %v", sk, err)
	}

	// Nothing to do when both sides agree.
	writes := srv.Writes
	if rep := b.sync(t); len(rep.Changes) != 0 || srv.Writes != writes {
		t.Fatalf("idle sync changed something: %+v", rep)
	}

	// B renames and retags; A sees it.
	newName := "api-prod"
	if err := b.inv.DB.UpdateCertificateMeta(ctx, row.ID, &newName, nil); err != nil {
		t.Fatal(err)
	}
	if err := b.inv.DB.RemoveTags(ctx, "cert", row.ID, []string{"prod"}); err != nil {
		t.Fatal(err)
	}
	if err := b.inv.DB.AddTags(ctx, "cert", row.ID, []string{"production"}); err != nil {
		t.Fatal(err)
	}
	if rep := b.sync(t); rep.Count(ActPush) != 1 {
		t.Fatalf("push rename: %+v", rep)
	}
	if rep := a.sync(t); rep.Count(ActPull) != 1 {
		t.Fatalf("pull rename: %+v", rep)
	}
	arow, _, err := a.inv.Certificate(ctx, "api-prod")
	if err != nil || len(arow.Tags) != 1 || arow.Tags[0] != "production" {
		t.Fatalf("rename not applied on A: %+v %v", arow, err)
	}

	// Concurrent edits on both sides merge: tags are united.
	if err := a.inv.DB.AddTags(ctx, "cert", arow.ID, []string{"team-a"}); err != nil {
		t.Fatal(err)
	}
	if err := b.inv.DB.AddTags(ctx, "cert", row.ID, []string{"team-b"}); err != nil {
		t.Fatal(err)
	}
	a.sync(t)
	if rep := b.sync(t); rep.Count(ActMerge) != 1 {
		t.Fatalf("merge: %+v", rep)
	}
	a.sync(t)
	for _, d := range []*device{a, b} {
		r, _, _ := d.inv.Certificate(ctx, "api-prod")
		if strings.Join(r.Tags, ",") != "production,team-a,team-b" {
			t.Fatalf("merged tags: %v", r.Tags)
		}
	}

	// Deleting on A removes the object on B, and from Vault.
	if err := a.inv.DB.DeleteSSHKey(ctx, "x"); err == nil {
		t.Fatal("expected not found")
	}
	ask, _ := a.inv.DB.GetSSHKey(ctx, "deploy")
	if err := a.inv.DB.DeleteSSHKey(ctx, ask.ID); err != nil {
		t.Fatal(err)
	}
	if rep := a.sync(t); rep.Count(ActDeleteRemote) != 1 || rep.Objects != 2 {
		t.Fatalf("delete push: %+v", rep)
	}
	if rep := b.sync(t); rep.Count(ActDeleteLocal) != 1 {
		t.Fatalf("delete pull: %+v", rep)
	}
	if _, err := b.inv.DB.GetSSHKey(ctx, "deploy"); !database.IsNotFound(err) {
		t.Fatalf("SSH key still on B: %v", err)
	}
	for _, p := range srv.Paths() {
		if strings.HasPrefix(p, "sslknife/ssh/") {
			t.Fatalf("SSH object left in Vault: %s", p)
		}
	}
}

func TestSyncFirstJoinMergesExistingInventory(t *testing.T) {
	ctx := context.Background()
	srv := vaulttest.New(t)
	a, b := newDevice(t, srv, false), newDevice(t, srv, false)
	shared, _ := leafWithKey(t, "shared.example.com")
	onlyB, _ := leafWithKey(t, "b.example.com")
	if _, err := a.inv.ImportCertificate(ctx, shared, inventory.ImportOptions{Tags: []string{"a"}}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*x509.Certificate{shared, onlyB} {
		if _, err := b.inv.ImportCertificate(ctx, c, inventory.ImportOptions{Tags: []string{"b"}}); err != nil {
			t.Fatal(err)
		}
	}
	a.sync(t)
	rep := b.sync(t)
	if rep.Count(ActMerge) != 1 || rep.Count(ActPush) != 1 {
		t.Fatalf("%+v", rep)
	}
	a.sync(t)
	certs, _ := a.inv.DB.QueryCertificates(ctx, "", nil, "")
	if len(certs) != 2 {
		t.Fatalf("A has %d certificates", len(certs))
	}
	for _, c := range certs {
		if c.SubjectCN == "shared.example.com" && strings.Join(c.Tags, ",") != "a,b" {
			t.Fatalf("tags %v", c.Tags)
		}
	}
}

func TestSyncDryRunChangesNothing(t *testing.T) {
	ctx := context.Background()
	srv := vaulttest.New(t)
	a := newDevice(t, srv, false)
	c, _ := leafWithKey(t, "x.example.com")
	if _, err := a.inv.ImportCertificate(ctx, c, inventory.ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	rep, err := Sync(ctx, a.inv, a.store, Options{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Changes) != 1 || rep.Changes[0].Action != ActPush || srv.Writes != 0 {
		t.Fatalf("%+v writes=%d", rep, srv.Writes)
	}
}

func TestSyncConflictRetries(t *testing.T) {
	ctx := context.Background()
	srv := vaulttest.New(t)
	a, b := newDevice(t, srv, false), newDevice(t, srv, false)
	c1, _ := leafWithKey(t, "one.example.com")
	c2, _ := leafWithKey(t, "two.example.com")
	a.inv.ImportCertificate(ctx, c1, inventory.ImportOptions{})
	b.inv.ImportCertificate(ctx, c2, inventory.ImportOptions{})
	// B's manifest write races A's: a store that lets A write in between.
	racing := &racingStore{Store: b.store, before: func() { a.sync(t) }}
	rep, err := Sync(ctx, b.inv, racing, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Attempts != 2 || rep.Objects != 2 {
		t.Fatalf("%+v", rep)
	}
}

type racingStore struct {
	Store
	before func()
}

func (r *racingStore) PutManifest(ctx context.Context, m Manifest, cas int) error {
	if r.before != nil {
		r.before()
		r.before = nil
	}
	return r.Store.PutManifest(ctx, m, cas)
}

func TestSSHIdentRoundTrip(t *testing.T) {
	fp := "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
	id, err := SSHIdent(fp)
	if err != nil {
		t.Fatal(err)
	}
	back, err := sshFingerprint(id)
	if err != nil || back != fp {
		t.Fatalf("%s → %s → %s (%v)", fp, id, back, err)
	}
}

func TestSyncRejectsTamperedObjects(t *testing.T) {
	ctx := context.Background()
	srv := vaulttest.New(t)
	a, b := newDevice(t, srv, false), newDevice(t, srv, false)
	_, key := leafWithKey(t, "a.example.com")
	res, err := a.inv.ImportPrivateKey(ctx, key, inventory.ImportOptions{Name: "k"})
	if err != nil {
		t.Fatal(err)
	}
	a.sync(t)

	// Swap in a different private key under the same identifier.
	_, other := leafWithKey(t, "b.example.com")
	der, _ := x509.MarshalPKCS8PrivateKey(other)
	path := "sslknife/keys/" + res.Key.SPKISHA256
	d := srv.Data(path)
	forged := map[string]any{}
	for k, v := range d {
		forged[k] = v
	}
	forged["private_key"] = string(pemEncode("PRIVATE KEY", der))
	forged["name"] = "forged"
	srv.Set(path, forged)
	// Make the manifest announce a change so B fetches the object.
	m, ver, err := b.store.Manifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e := m[Key{Kind: KindKey, Ident: res.Key.SPKISHA256}]
	e.Digest = "changed"
	m[Key{Kind: KindKey, Ident: res.Key.SPKISHA256}] = e
	if err := b.store.PutManifest(ctx, m, ver); err != nil {
		t.Fatal(err)
	}

	rep, err := Sync(ctx, b.inv, b.store, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Failed != 1 || !strings.Contains(rep.Changes[0].Error, "does not match") {
		t.Fatalf("%+v", rep)
	}
	if ks, _ := b.inv.DB.QueryKeys(ctx, "", nil); len(ks) != 0 {
		t.Fatalf("forged key imported: %+v", ks)
	}
}

func pemEncode(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

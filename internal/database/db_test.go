package database

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	skcrypto "github.com/matusso/sslknife/internal/crypto"
)

func newTestDB(t *testing.T) (*DB, string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "data", "sslknife.db")
	root := skcrypto.RandomBytes(32)
	db, err := Create(context.Background(), path, root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, path, root
}

func sampleCert(id string) *Certificate {
	now := time.Now().UTC().Truncate(time.Second)
	return &Certificate{
		ID: id, SHA256: id + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SHA1: "s1", SPKISHA256: "spki-" + id,
		Serial: "01", Subject: "CN=needle-plaintext.example.com", SubjectCN: "needle-plaintext.example.com",
		Issuer: "CN=CA", IssuerCN: "CA", NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour),
		KeyAlgorithm: "ECDSA", KeyBits: 256, KeyDescription: "ECDSA P-256", SignatureAlgorithm: "ECDSA-SHA256",
		DER: []byte{0x30, 0x01}, Source: "test", ImportedAt: now,
		SANs: []SAN{{"dns", "needle-plaintext.example.com"}, {"dns", "WWW.example.com"}},
		Tags: []string{"Production"},
	}
}

func TestEncryptedAtRest(t *testing.T) {
	db, path, root := newTestDB(t)
	ctx := context.Background()
	if err := db.Tx(ctx, func(tx *sql.Tx) error { return db.InsertCertificate(ctx, tx, sampleCert("c1")) }); err != nil {
		t.Fatal(err)
	}
	db.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("needle-plaintext")) || bytes.Contains(raw, []byte("SQLite format 3")) {
		t.Fatal("database is not encrypted at rest")
	}
	// Windows only honours the read-only bit, so Unix modes are not observable.
	if st, _ := os.Stat(path); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("db mode %v", st.Mode().Perm())
	}

	if _, err := Open(ctx, path, skcrypto.RandomBytes(32)); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("wrong key: %v", err)
	}

	db2, err := Open(ctx, path, root)
	if err != nil {
		t.Fatal(err)
	}
	c, err := db2.GetCertificate(ctx, "c1")
	if err != nil || c.SubjectCN != "needle-plaintext.example.com" || len(c.SANs) != 2 || c.Tags[0] != "production" {
		t.Fatalf("roundtrip: %+v %v", c, err)
	}
	db2.Close()

	// Flip one bit in the second page: every read of it must fail.
	f, _ := os.OpenFile(path, os.O_RDWR, 0)
	b := make([]byte, 1)
	f.ReadAt(b, 4096+200)
	b[0] ^= 0x01
	f.WriteAt(b, 4096+200)
	f.Close()
	db3, err := Open(ctx, path, root)
	if err == nil {
		_, err = db3.QueryCertificates(ctx, "", nil, "")
		db3.Close()
	}
	if err == nil {
		t.Fatal("tampering not detected")
	}
}

func TestCreateRefusesExisting(t *testing.T) {
	_, path, root := newTestDB(t)
	if _, err := Create(context.Background(), path, root); err == nil {
		t.Fatal("expected error")
	}
}

func TestSecrets(t *testing.T) {
	db, _, _ := newTestDB(t)
	ctx := context.Background()
	var id string
	err := db.Tx(ctx, func(tx *sql.Tx) (err error) {
		id, err = db.PutSecret(ctx, tx, []byte("private"))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := db.GetSecret(ctx, id)
	if err != nil || string(got) != "private" {
		t.Fatal(got, err)
	}
	// Moving ciphertext to another row must fail authentication.
	if _, err := db.sql.Exec(`INSERT INTO secrets(id, nonce, ciphertext, created_at) SELECT 'other', nonce, ciphertext, 0 FROM secrets WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetSecret(ctx, "other"); !errors.Is(err, skcrypto.ErrDecrypt) {
		t.Fatalf("swapped secret opened: %v", err)
	}
}

func TestResolveAndMeta(t *testing.T) {
	db, _, _ := newTestDB(t)
	ctx := context.Background()
	for _, id := range []string{"abcd1111", "abcd2222"} {
		c := sampleCert(id)
		c.SPKISHA256 = id
		if err := db.Tx(ctx, func(tx *sql.Tx) error { return db.InsertCertificate(ctx, tx, c) }); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ResolveCertificate(ctx, "abcd"); !errors.Is(err, ErrAmbiguous) {
		t.Fatal("expected ambiguous", err)
	}
	if id, err := db.ResolveCertificate(ctx, "abcd1"); err != nil || id != "abcd1111" {
		t.Fatal(id, err)
	}
	if id, err := db.ResolveCertificate(ctx, "ABCD2222AAAA"); err != nil || id != "abcd2222" {
		t.Fatal("sha prefix", id, err)
	}
	if _, err := db.ResolveCertificate(ctx, "zzzz"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	name := "api-prod"
	if err := db.UpdateCertificateMeta(ctx, "abcd1111", &name, nil); err != nil {
		t.Fatal(err)
	}
	if id, _ := db.ResolveCertificate(ctx, "api-prod"); id != "abcd1111" {
		t.Fatal("name lookup")
	}
	if err := db.UpdateCertificateMeta(ctx, "abcd2222", &name, nil); err == nil {
		t.Fatal("duplicate name accepted")
	}
	if err := db.AddTags(ctx, "cert", "abcd1111", []string{"vpn", "Bad Tag"}); err == nil {
		t.Fatal("invalid tag accepted")
	}
	if err := db.AddTags(ctx, "cert", "abcd1111", []string{"vpn", "k8s"}); err != nil {
		t.Fatal(err)
	}
	if err := db.RemoveTags(ctx, "cert", "abcd1111", []string{"vpn"}); err != nil {
		t.Fatal(err)
	}
	c, _ := db.GetCertificate(ctx, "abcd1111")
	if len(c.Tags) != 2 || c.Tags[0] != "k8s" {
		t.Fatalf("tags %v", c.Tags)
	}
	if _, err := db.AddNote(ctx, "cert", c.ID, "rotated by ops"); err != nil {
		t.Fatal(err)
	}
	notes, _ := db.Notes(ctx, "cert", c.ID)
	if len(notes) != 1 {
		t.Fatal(notes)
	}
	if err := db.DeleteCertificate(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if notes, _ := db.Notes(ctx, "cert", c.ID); len(notes) != 0 {
		t.Fatal("notes not deleted")
	}
	if err := db.DeleteCertificate(ctx, c.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestKeys(t *testing.T) {
	db, _, _ := newTestDB(t)
	ctx := context.Background()
	k := &Key{ID: "k1", Name: "srv", Algorithm: "Ed25519", Bits: 256, Description: "Ed25519", SPKISHA256: "spki1",
		PublicDER: []byte{1}, Source: "test", ImportedAt: time.Now()}
	if err := db.Tx(ctx, func(tx *sql.Tx) error { return db.InsertKey(ctx, tx, k, []byte("pkcs8")) }); err != nil {
		t.Fatal(err)
	}
	c := sampleCert("c1")
	c.KeyID = "k1"
	if err := db.Tx(ctx, func(tx *sql.Tx) error { return db.InsertCertificate(ctx, tx, c) }); err != nil {
		t.Fatal(err)
	}
	got, err := db.KeyBySPKI(ctx, "spki1")
	if err != nil || !got.HasPrivate() {
		t.Fatal(err)
	}
	der, err := db.PrivateKeyDER(ctx, got)
	if err != nil || string(der) != "pkcs8" {
		t.Fatal(err)
	}
	if err := db.DeleteKey(ctx, "k1"); err != nil {
		t.Fatal(err)
	}
	var n int
	db.sql.QueryRow(`SELECT count(*) FROM secrets`).Scan(&n)
	if n != 0 {
		t.Fatal("secret not deleted")
	}
	c2, _ := db.GetCertificate(ctx, "c1")
	if c2.KeyID != "" {
		t.Fatal("key link not cleared")
	}
}

package ct

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matusso/sslknife/internal/certificate"
	skcrypto "github.com/matusso/sslknife/internal/crypto"
	"github.com/matusso/sslknife/internal/database"
	"github.com/matusso/sslknife/internal/inventory"
	"github.com/matusso/sslknife/internal/keys"
)

func testDB(t *testing.T) *database.DB {
	db, err := database.Create(context.Background(), filepath.Join(t.TempDir(), "ct.db"), skcrypto.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func storedCert(t *testing.T, db *database.DB) *x509.Certificate {
	k, _ := keys.Generate(keys.ECDSAP256)
	c, err := certificate.Create(certificate.Request{Profile: certificate.ProfileServer, Subject: pkix.Name{CommonName: "www.example.com"},
		SANs: []string{"example.com", "*.api.example.com"}, Validity: 24 * time.Hour, Key: k, PathLen: -1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inventory.New(db).ImportCertificate(context.Background(), c, inventory.ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCertSpotterCheck(t *testing.T) {
	db := testDB(t)
	c := storedCert(t, db)
	fp := certificate.Fingerprint(c)
	future := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
	page := func(after string) []map[string]any {
		mk := func(id, sha, spki, issuer string, names []string, notAfter time.Time) map[string]any {
			return map[string]any{"id": id, "tbs_sha256": "tbs" + id, "cert_sha256": sha, "pubkey_sha256": spki,
				"dns_names": names, "issuer": map[string]string{"name": issuer, "friendly_name": "CA " + id},
				"not_before": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), "not_after": notAfter.Format(time.RFC3339)}
		}
		switch after {
		case "":
			return []map[string]any{
				mk("1", fp.SHA256, fp.SPKISHA256, c.Issuer.String(), []string{"www.example.com", "example.com", "*.api.example.com"}, future),
				mk("2", "other", "otherkey", "C=US, O=Evil CA, CN=X1", []string{"login.example.com"}, future),
				mk("3", "old", "oldkey", c.Issuer.String(), []string{"old.example.com"}, time.Now().Add(-time.Hour)),
			}
		case "3":
			return []map[string]any{mk("4", "renewed", "newkey", "C=US, O=Evil CA, CN=X1", []string{"example.com", "*.api.example.com", "www.example.com"}, future)}
		}
		return nil
	}
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.RawQuery)
		if r.URL.Query().Get("domain") != "example.com" || r.URL.Query().Get("include_subdomains") != "true" {
			http.Error(w, "bad query", 400)
			return
		}
		json.NewEncoder(w).Encode(page(r.URL.Query().Get("after")))
	}))
	defer srv.Close()

	w, created, err := db.AddCTWatch(context.Background(), "example.com", true, "manual")
	if err != nil || !created {
		t.Fatal(err)
	}
	idx, _ := db.CTCertIndex(context.Background())
	chk := &Checker{DB: db, Provider: &CertSpotter{Client: srv.Client(), BaseURL: srv.URL}}
	res := chk.Check(context.Background(), *w, idx)
	if res.Error != "" || len(res.Added) != 4 {
		t.Fatalf("%+v", res)
	}
	status := map[string]string{}
	for _, o := range res.Added {
		status[o.ExternalID] = o.Status
	}
	// 4 covers the stored certificate's names with a different certificate.
	if status["1"] != StatusKnown || status["2"] != StatusUnexpected || status["3"] != StatusExpired || status["4"] != StatusChanged {
		t.Fatalf("%v", status)
	}
	// The next poll resumes after the last seen ID and adds nothing.
	ws, _ := db.CTWatches(context.Background())
	if ws[0].Cursor != "certspotter:4" {
		t.Fatalf("cursor %q", ws[0].Cursor)
	}
	calls = nil
	if res = chk.Check(context.Background(), ws[0], idx); len(res.Added) != 0 || res.Error != "" {
		t.Fatalf("%+v", res)
	}
	if len(calls) != 1 || !strings.Contains(calls[0], "after=4") {
		t.Fatalf("calls %v", calls)
	}
	if n, _ := db.CountCTObservations(context.Background(), StatusUnexpected, time.Time{}); n != 1 {
		t.Fatalf("unexpected count %d", n)
	}
	if _, err := db.AcknowledgeCTObservation(context.Background(), firstObs(t, db, "2")); err != nil {
		t.Fatal(err)
	}
}

func firstObs(t *testing.T, db *database.DB, ext string) string {
	obs, _ := db.CTObservations(context.Background(), database.CTObservationFilter{})
	for _, o := range obs {
		if o.ExternalID == ext {
			return o.ID
		}
	}
	t.Fatal("observation not found")
	return ""
}

func TestCrtSh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") != "%.example.com" {
			http.Error(w, "bad", 400)
			return
		}
		fmt.Fprint(w, `[{"id":10,"issuer_name":"C=US, O=Let's Encrypt, CN=R11","common_name":"a.example.com","name_value":"a.example.com\nb.example.com","not_before":"2026-09-01T00:00:00","not_after":"2026-12-01T00:00:00","serial_number":"0abc"},
			{"id":11,"issuer_name":"C=US, O=Let's Encrypt, CN=R11","common_name":"a.example.com","name_value":"a.example.com\nb.example.com","not_before":"2026-09-01T00:00:00","not_after":"2026-12-01T00:00:00","serial_number":"0abc"}]`)
	}))
	defer srv.Close()
	p := &CrtSh{Client: srv.Client(), BaseURL: srv.URL}
	got, cursor, err := p.Search(context.Background(), Query{Domain: "example.com", IncludeSubdomains: true})
	if err != nil || len(got) != 1 || len(got[0].DNSNames) != 2 || cursor != "11" {
		t.Fatalf("%+v %s %v", got, cursor, err)
	}
}

func TestRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	p := &CertSpotter{Client: srv.Client(), BaseURL: srv.URL}
	if _, _, err := p.Search(context.Background(), Query{Domain: "example.com"}); err == nil {
		t.Fatal("expected rate limit error")
	}
}

func TestAutoWatchAndPattern(t *testing.T) {
	db := testDB(t)
	storedCert(t, db)
	idx, _ := db.CTCertIndex(context.Background())
	n, err := AutoWatch(context.Background(), db, idx)
	if err != nil || n != 3 {
		t.Fatalf("%d %v", n, err)
	}
	ws, _ := db.CTWatches(context.Background())
	patterns := map[string]bool{}
	for _, w := range ws {
		patterns[w.Pattern()] = true
	}
	if !patterns["*.api.example.com"] || !patterns["example.com"] || !patterns["www.example.com"] {
		t.Fatal(patterns)
	}
	if n, _ := AutoWatch(context.Background(), db, idx); n != 0 {
		t.Fatal("auto watch not idempotent")
	}
	for in, want := range map[string]string{"Example.COM.": "example.com", "*.example.com": "*.example.com"} {
		d, sub, err := NormalizePattern(in, false)
		got := d
		if sub {
			got = "*." + d
		}
		if err != nil || got != want {
			t.Errorf("%s: %s %v", in, got, err)
		}
	}
	if _, _, err := NormalizePattern("com", false); err == nil {
		t.Error("TLD accepted")
	}
}

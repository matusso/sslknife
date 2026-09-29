package server

import (
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/matusso/sslknife/internal/certificate"
	"github.com/matusso/sslknife/internal/config"
	skcrypto "github.com/matusso/sslknife/internal/crypto"
	"github.com/matusso/sslknife/internal/database"
	"github.com/matusso/sslknife/internal/inventory"
	"github.com/matusso/sslknife/internal/keys"
)

const testToken = "test-token-0123456789abcdef"

func setup(t *testing.T) (*Server, *httptest.Server, *database.DB) {
	t.Helper()
	db, err := database.Create(context.Background(), filepath.Join(t.TempDir(), "s.db"), skcrypto.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	cfg, _ := config.Default()
	static := fstest.MapFS{"index.html": {Data: []byte("<html>app</html>")}, "app.js": {Data: []byte("//js")}}
	s, err := New(context.Background(), db, Options{Listen: "127.0.0.1:0", Token: testToken, Config: cfg, Static: static})
	if err != nil {
		t.Fatal(err)
	}
	s.listener.Close() // httptest provides its own listener
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.TLS = s.tlsConfig
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return s, ts, db
}

func client(ts *httptest.Server) *http.Client {
	jar, _ := cookiejar.New(nil)
	c := ts.Client()
	c.Jar = jar
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

func do(t *testing.T, c *http.Client, method, u, body string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, u, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestAuthFlowAndCSRF(t *testing.T) {
	_, ts, db := setup(t)
	c := client(ts)
	base := ts.URL

	// Unauthenticated API access is refused; the index shows the lock page.
	resp, _ := do(t, c, "GET", base+"/api/v1/dashboard", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("dashboard without auth: %d", resp.StatusCode)
	}
	resp, body := do(t, c, "GET", base+"/", "", nil)
	if resp.StatusCode != http.StatusUnauthorized || strings.Contains(body, "app</html>") {
		t.Fatal("index served without auth")
	}
	for _, h := range []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"} {
		if resp.Header.Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
	// Wrong token.
	resp, _ = do(t, c, "GET", base+"/?token=wrong", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatal("wrong token accepted")
	}
	// Login sets a strict cookie and redirects.
	resp, _ = do(t, c, "GET", base+"/?token="+testToken, "", nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	ck := resp.Cookies()[0]
	if !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode || !ck.Secure {
		t.Fatalf("cookie flags %+v", ck)
	}
	resp, body = do(t, c, "GET", base+"/", "", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "app</html>") {
		t.Fatal("index after login")
	}
	_, body = do(t, c, "GET", base+"/api/v1/session", "", nil)
	var sess map[string]string
	json.Unmarshal([]byte(body), &sess)
	if sess["csrf_token"] == "" {
		t.Fatal("no csrf token")
	}

	// Seed a certificate with a private key.
	k, _ := keys.Generate(keys.ECDSAP256)
	cert, _ := certificate.Create(certificate.Request{Profile: certificate.ProfileServer, Subject: pkix.Name{CommonName: "web.example.com"},
		Validity: 10 * 24 * time.Hour, Key: k, PathLen: -1})
	inv := inventory.New(db)
	if _, err := inv.ImportPrivateKey(context.Background(), k, inventory.ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	pemText := string(certificate.EncodePEM(cert))

	// POST without CSRF token is refused; with it, accepted.
	post := `{"pem":` + jsonString(pemText) + `,"tags":["web"]}`
	resp, _ = do(t, c, "POST", base+"/api/v1/certificates", post, map[string]string{"Content-Type": "application/json"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST without CSRF: %d", resp.StatusCode)
	}
	resp, _ = do(t, c, "POST", base+"/api/v1/certificates", post, map[string]string{"X-CSRF-Token": sess["csrf_token"], "Origin": "https://evil.example"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin POST: %d", resp.StatusCode)
	}
	resp, body = do(t, c, "POST", base+"/api/v1/certificates", post, map[string]string{"X-CSRF-Token": sess["csrf_token"]})
	if resp.StatusCode != 200 || !strings.Contains(body, `"created":1`) {
		t.Fatalf("import: %d %s", resp.StatusCode, body)
	}

	// Responses never carry private keys.
	for _, path := range []string{"/api/v1/dashboard", "/api/v1/certificates", "/api/v1/keys", "/api/v1/search?q=web", "/api/v1/ssh/keys"} {
		resp, body := do(t, c, "GET", base+path, "", nil)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, body)
		}
		if strings.Contains(body, "PRIVATE KEY") {
			t.Fatalf("%s leaks private key material", path)
		}
	}
	_, body = do(t, c, "GET", base+"/api/v1/certificates", "", nil)
	var list []map[string]any
	json.Unmarshal([]byte(body), &list)
	if len(list) != 1 || list[0]["key_id"] == nil {
		t.Fatalf("%s", body)
	}
	id := list[0]["id"].(string)
	resp, body = do(t, c, "GET", base+"/api/v1/certificates/"+id, "", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "BEGIN CERTIFICATE") || strings.Contains(body, "PRIVATE KEY") {
		t.Fatal(body)
	}

	// Bearer tokens work without cookies or CSRF.
	plain := ts.Client()
	resp, _ = do(t, plain, "DELETE", base+"/api/v1/certificates/"+id, "", map[string]string{"Authorization": "Bearer " + testToken})
	if resp.StatusCode != 200 {
		t.Fatalf("bearer delete: %d", resp.StatusCode)
	}
	resp, _ = do(t, plain, "GET", base+"/api/v1/dashboard", "", map[string]string{"Authorization": "Bearer nope"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatal("bad bearer accepted")
	}
	resp, _ = do(t, plain, "GET", base+"/api/v1/openapi.json", "", map[string]string{"Authorization": "Bearer " + testToken})
	if resp.StatusCode != 200 {
		t.Fatal("openapi")
	}
}

func TestHostCheck(t *testing.T) {
	_, ts, _ := setup(t)
	c := ts.Client()
	req, _ := http.NewRequest("GET", ts.URL+"/", nil)
	req.Host = "attacker.example"
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("rebinding host accepted: %d", resp.StatusCode)
	}
}

func TestPersistentIdentity(t *testing.T) {
	db, err := database.Create(context.Background(), filepath.Join(t.TempDir(), "i.db"), skcrypto.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg, _ := config.Default()
	var fps []string
	for i := 0; i < 2; i++ {
		s, err := New(context.Background(), db, Options{Listen: "127.0.0.1:0", Config: cfg})
		if err != nil {
			t.Fatal(err)
		}
		s.listener.Close()
		fps = append(fps, s.Fingerprint())
		leaf := s.tlsConfig.Certificates[0].Leaf
		if leaf.VerifyHostname("127.0.0.1") != nil || leaf.VerifyHostname("localhost") != nil {
			t.Fatal("identity does not cover loopback names")
		}
		if len(s.Token()) < 32 {
			t.Fatal("weak random token")
		}
	}
	if fps[0] != fps[1] {
		t.Fatal("server certificate not persisted")
	}
	if !IsLoopback("127.0.0.1:8443") || !IsLoopback("[::1]:1") || IsLoopback("0.0.0.0:8443") || IsLoopback(":8443") {
		t.Fatal("IsLoopback")
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

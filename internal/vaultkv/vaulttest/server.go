// Package vaulttest is an in-memory fake of the parts of the HashiCorp Vault
// HTTP API that vaultkv uses: KV v2 (with check-and-set), Transit, token
// lookup and AppRole/userpass logins. It is for tests only.
package vaulttest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
)

// Server is a running fake Vault.
type Server struct {
	*httptest.Server
	Token string // the only accepted token

	mu      sync.Mutex
	kv      map[string][]map[string]any // path → versions (nil entry = destroyed)
	Writes  int                         // KV writes, for tests that count round trips
	Reads   int
	Users   map[string]string // userpass username → password
	RoleID  string
	Secret  string
	Mount   string
	Transit string // transit key name ("" disables)
}

// New starts a fake Vault with a KV v2 engine at "secret".
func New(t testing.TB) *Server {
	s := &Server{Token: "hvs.test-root", kv: map[string][]map[string]any{}, Users: map[string]string{},
		RoleID: "role", Secret: "secret-id", Mount: "secret", Transit: "sslknife"}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.Close)
	return s
}

// Paths returns the stored KV paths, sorted.
func (s *Server) Paths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for p := range s.kv {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Data returns the latest data at path, or nil.
func (s *Server) Data(path string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.kv[path]
	if len(v) == 0 {
		return nil
	}
	return v[len(v)-1]
}

// Set writes a new version of path directly, as another Vault client would.
func (s *Server) Set(path string, data map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kv[path] = append(s.kv[path], data)
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	reply(w, code, map[string]any{"errors": []string{msg}})
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := strings.TrimPrefix(r.URL.Path, "/v1/")
	var body map[string]any
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	switch {
	case p == "auth/approle/login":
		if body["role_id"] != s.RoleID || body["secret_id"] != s.Secret {
			fail(w, 400, "invalid role or secret ID")
			return
		}
		reply(w, 200, map[string]any{"auth": map[string]any{"client_token": s.Token}})
		return
	case strings.HasPrefix(p, "auth/userpass/login/"):
		u := strings.TrimPrefix(p, "auth/userpass/login/")
		if pw, ok := s.Users[u]; !ok || body["password"] != pw {
			fail(w, 400, "invalid username or password")
			return
		}
		reply(w, 200, map[string]any{"auth": map[string]any{"client_token": s.Token}})
		return
	}
	if r.Header.Get("X-Vault-Token") != s.Token {
		fail(w, 403, "permission denied")
		return
	}
	switch {
	case p == "auth/token/lookup-self":
		reply(w, 200, map[string]any{"data": map[string]any{"display_name": "token-test", "policies": []string{"sslknife"}, "ttl": 3600}})
	case p == "auth/token/revoke-self":
		w.WriteHeader(204)
	case strings.HasPrefix(p, s.Mount+"/data/"):
		s.handleData(w, r, strings.TrimPrefix(p, s.Mount+"/data/"), body)
	case strings.HasPrefix(p, s.Mount+"/metadata/"):
		s.handleMetadata(w, r, strings.TrimPrefix(p, s.Mount+"/metadata/"))
	case s.Transit != "" && p == "transit/encrypt/"+s.Transit:
		pt, _ := body["plaintext"].(string)
		reply(w, 200, map[string]any{"data": map[string]any{"ciphertext": "vault:v1:" + reverse(pt)}})
	case s.Transit != "" && p == "transit/decrypt/"+s.Transit:
		ct, _ := body["ciphertext"].(string)
		if !strings.HasPrefix(ct, "vault:v1:") {
			fail(w, 400, "invalid ciphertext")
			return
		}
		reply(w, 200, map[string]any{"data": map[string]any{"plaintext": reverse(strings.TrimPrefix(ct, "vault:v1:"))}})
	default:
		fail(w, 404, "no handler for route "+p)
	}
}

// reverse is the fake "cipher": it only needs to round-trip and to be
// obviously not the plaintext.
func reverse(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

func (s *Server) handleData(w http.ResponseWriter, r *http.Request, path string, body map[string]any) {
	versions := s.kv[path]
	switch r.Method {
	case http.MethodGet:
		s.Reads++
		if len(versions) == 0 {
			fail(w, 404, "")
			return
		}
		reply(w, 200, map[string]any{"data": map[string]any{
			"data": versions[len(versions)-1], "metadata": map[string]any{"version": len(versions)}}})
	case http.MethodPost, http.MethodPut:
		if opts, ok := body["options"].(map[string]any); ok {
			if cas, ok := opts["cas"].(float64); ok && int(cas) != len(versions) {
				fail(w, 400, "check-and-set parameter did not match the current version")
				return
			}
		}
		data, _ := body["data"].(map[string]any)
		s.kv[path] = append(versions, data)
		s.Writes++
		reply(w, 200, map[string]any{"data": map[string]any{"version": len(s.kv[path])}})
	default:
		fail(w, 405, "method not allowed")
	}
}

func (s *Server) handleMetadata(w http.ResponseWriter, r *http.Request, path string) {
	switch r.Method {
	case http.MethodDelete:
		delete(s.kv, path)
		w.WriteHeader(204)
	case "LIST":
		prefix := strings.TrimSuffix(path, "/") + "/"
		seen := map[string]bool{}
		for p := range s.kv {
			if rest, ok := strings.CutPrefix(p, prefix); ok {
				if i := strings.IndexByte(rest, '/'); i >= 0 {
					rest = rest[:i+1]
				}
				seen[rest] = true
			}
		}
		if len(seen) == 0 {
			fail(w, 404, "")
			return
		}
		var keys []string
		for k := range seen {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		reply(w, 200, map[string]any{"data": map[string]any{"keys": keys}})
	default:
		fail(w, 405, "method not allowed")
	}
}

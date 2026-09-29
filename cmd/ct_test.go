package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/matusso/sslknife/internal/exitcode"
)

func TestCTCommands(t *testing.T) {
	e := newEnv(t)
	na := time.Now().Add(60 * 24 * time.Hour).UTC().Format(time.RFC3339)
	nb := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after") != "" {
			w.Write([]byte("[]"))
			return
		}
		json.NewEncoder(w).Encode([]map[string]any{{
			"id": "100", "tbs_sha256": "t1", "cert_sha256": "c1", "pubkey_sha256": "p1",
			"dns_names":  []string{"shop." + r.URL.Query().Get("domain")},
			"issuer":     map[string]string{"name": "C=US, O=Surprise CA, CN=S1", "friendly_name": "Surprise CA"},
			"not_before": nb, "not_after": na,
		}})
	}))
	defer srv.Close()
	t.Setenv(EnvCTBaseURL, srv.URL)

	e.ok("init")
	e.code(exitcode.NotFound, "ct", "check", "--no-auto-watch")
	e.ok("ct", "watch", "*.example.com")
	e.code(exitcode.Usage, "ct", "watch", "not a domain")
	if out := e.ok("ct", "list"); !strings.Contains(out, "*.example.com") {
		t.Fatal(out)
	}
	out := e.code(exitcode.CheckFailed, "ct", "check", "--strict")
	if !strings.Contains(out, "unexpected") || !strings.Contains(out, "shop.example.com") {
		t.Fatal(out)
	}
	// Second check: nothing new, --strict passes.
	e.ok("ct", "check", "--strict")

	var obs []observationView
	if err := json.Unmarshal([]byte(e.ok("ct", "history", "example.com", "--json")), &obs); err != nil || len(obs) != 1 {
		t.Fatal(err, obs)
	}
	e.ok("ct", "ack", obs[0].ID)
	if out := e.ok("ct", "history", "--status", "unexpected"); !strings.Contains(out, "(ack)") {
		t.Fatal(out)
	}
	e.ok("ct", "unwatch", "*.example.com")
	e.code(exitcode.NotFound, "ct", "unwatch", "*.example.com")
}

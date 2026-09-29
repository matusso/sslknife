package search

import (
	"strings"
	"testing"
	"time"
)

func TestCompile(t *testing.T) {
	now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	c, err := Compile(`example.com issuer:"Let's Encrypt" -tag:legacy`, now)
	if err != nil {
		t.Fatal(err)
	}
	if c.Certs == nil || strings.Count(c.Certs.Where, "?") != len(c.Certs.Args) {
		t.Fatalf("%+v", c.Certs)
	}
	if !strings.Contains(c.Certs.Where, "NOT (") {
		t.Fatal("negation")
	}
	if c.Keys != nil {
		t.Fatal("issuer: cannot match keys")
	}

	c, _ = Compile("type:key algorithm:ed25519", now)
	if c.Certs != nil || c.Keys == nil {
		t.Fatal("type:key")
	}

	c, _ = Compile("expires:<30d", now)
	if c.Certs.Args[0] != now.Add(30*24*time.Hour).Unix() {
		t.Fatal(c.Certs.Args)
	}
	c, _ = Compile("expires:>=2027-01-01", now)
	if !strings.Contains(c.Certs.Where, ">=") {
		t.Fatal(c.Certs.Where)
	}
	c, _ = Compile("", now)
	if c.Certs.Where != "1=1" || c.Keys.Where != "1=1" {
		t.Fatal("empty")
	}
	// A value with a colon but no known field is a plain term.
	c, err = Compile("host:8443", now)
	if err != nil || c.Certs == nil {
		t.Fatal(err)
	}
	// LIKE wildcards are escaped.
	c, _ = Compile("san:%_", now)
	if c.Certs.Args[0] != `%\%\_%` {
		t.Fatal(c.Certs.Args)
	}
	for _, bad := range []string{`subject:"open`, "expires:<soon", "type:nope", "status:weird", "ca:maybe", "tag:"} {
		if _, err := Compile(bad, now); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

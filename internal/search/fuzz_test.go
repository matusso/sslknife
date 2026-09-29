package search

import (
	"strings"
	"testing"
	"time"
)

func FuzzCompile(f *testing.F) {
	for _, s := range []string{"example.com", `issuer:"x y" -tag:a`, "expires:<30d", "type:key"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, q string) {
		c, err := Compile(q, time.Unix(0, 0))
		if err != nil {
			return
		}
		for _, cl := range []*Clause{c.Certs, c.Keys, c.SSH} {
			if cl != nil && strings.Count(cl.Where, "?") != len(cl.Args) {
				t.Fatalf("placeholder mismatch for %q", q)
			}
		}
	})
}

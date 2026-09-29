package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/matusso/sslknife/internal/prompt"
)

func TestCertWizard(t *testing.T) {
	a := &app{}
	// type=TLS Server, CN, org, two SANs, algorithm #4 (Ed25519), validity,
	// issuer empty, don't store, write files.
	answers := "1\napi.example.com\n\nwww.api.example.com\n10.0.0.5\n\n4\n90d\n\nn\ny\n"
	a.prompt = prompt.NewScripted(strings.NewReader(answers), &bytes.Buffer{})
	o := &createOpts{pathLen: -1}
	if err := a.certWizard(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if o.profile != "server" || o.subject.cn != "api.example.com" || len(o.sans) != 2 || o.algorithm != "ed25519" ||
		o.validity != "90d" || o.store || o.out != "api.example.com.crt" || o.keyOut != "api.example.com.key" {
		t.Fatalf("%+v", o)
	}
}

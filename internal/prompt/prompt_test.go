package prompt

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestScripted(t *testing.T) {
	var out bytes.Buffer
	p := NewScripted(strings.NewReader("maybe\ny\n\nhello\n9\n2\na\nb\n\nsecret123\nsecret123\n"), &out)
	if ok, err := p.Confirm("Store?", false); err != nil || !ok {
		t.Fatalf("confirm: %v %v", ok, err)
	}
	if ok, _ := p.Confirm("Again?", true); !ok {
		t.Fatal("default yes")
	}
	if s, _ := p.Line("Name", "def"); s != "hello" {
		t.Fatal(s)
	}
	if i, _ := p.Choose("Pick", []string{"a", "b"}, 0); i != 1 {
		t.Fatal(i)
	}
	if l, _ := p.Lines("SANs"); len(l) != 2 || l[1] != "b" {
		t.Fatal(l)
	}
	pw, err := p.NewPassword("Password", 8)
	if err != nil || string(pw) != "secret123" {
		t.Fatal(string(pw), err)
	}
}

func TestNonInteractive(t *testing.T) {
	p := New(strings.NewReader("y\n"), &bytes.Buffer{})
	if _, err := p.Confirm("x", true); !errors.Is(err, ErrNotInteractive) {
		t.Fatal(err)
	}
}

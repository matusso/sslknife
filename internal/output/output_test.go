package output

import (
	"bytes"
	"strings"
	"testing"
)

type sample struct {
	Zeta  string   `json:"zeta"`
	Alpha int      `json:"alpha"`
	Yes   string   `json:"yes_value"`
	List  []string `json:"list"`
}

func TestWriteYAMLKeepsOrder(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteYAML(&buf, sample{Zeta: "z", Alpha: 1, Yes: "yes", List: []string{"a", "123"}}); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	want := "zeta: z\nalpha: 1\nyes_value: yes\nlist:\n  - a\n  - \"123\"\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestTableAlignsWithANSI(t *testing.T) {
	tb := NewTable("NAME", "STATUS")
	st := Style{Enabled: true}
	tb.Row("a", st.Green("OK"))
	tb.Row("longer", "WARNING")
	var buf bytes.Buffer
	if err := tb.Render(&buf, Style{}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines: %q", lines)
	}
	if !strings.HasPrefix(lines[1], "a       ") || !strings.HasPrefix(lines[2], "longer  WARNING") {
		t.Fatalf("misaligned: %q", lines)
	}
}

func TestTree(t *testing.T) {
	root := &Node{Label: "root"}
	a := root.Add("a")
	a.Add("a1")
	root.Add("b")
	var buf bytes.Buffer
	_ = RenderTree(&buf, root)
	want := "root\n├── a\n│   └── a1\n└── b\n"
	if buf.String() != want {
		t.Fatalf("got\n%s", buf.String())
	}
}

func TestKV(t *testing.T) {
	var buf bytes.Buffer
	kv := NewKV(Style{})
	kv.Add("A", "1").Add("Longer", "2").Add("Empty", "")
	kv.Heading("Section").List("Names", []string{"x", "y"})
	_ = kv.Render(&buf)
	want := "A:      1\nLonger: 2\n\nSection\n  Names: x\n         y\n"
	if buf.String() != want {
		t.Fatalf("got\n%q\nwant\n%q", buf.String(), want)
	}
}

func TestParseFormat(t *testing.T) {
	for in, want := range map[string]Format{"": Text, "table": Text, "JSON": JSON, "yml": YAML, "raw": Raw} {
		if got, err := ParseFormat(in); err != nil || got != want {
			t.Errorf("ParseFormat(%q) = %v %v", in, got, err)
		}
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Error("expected error")
	}
}

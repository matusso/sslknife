package logging

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRedaction(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelTrace)
	l.Info("unlock", "password", "hunter2", "db_password", "x1", "api_token", "zqv9",
		"blob", []byte{1, 2, 3}, "data", "-----BEGIN PRIVATE KEY-----abc", "wrapped", Secret("s3cr3t"), "host", "example.com")
	l.Log(context.Background(), LevelTrace, "trace msg")
	out := buf.String()
	for _, leak := range []string{"hunter2", "x1", "zqv9", "abc", "s3cr3t"} {
		if strings.Contains(out, leak) {
			t.Errorf("leaked %q in %s", leak, out)
		}
	}
	if !strings.Contains(out, "example.com") || !strings.Contains(out, "level=TRACE") {
		t.Errorf("unexpected output %s", out)
	}
}

func TestParseLevel(t *testing.T) {
	for _, s := range []string{"error", "warn", "info", "debug", "trace"} {
		if _, ok := ParseLevel(s); !ok {
			t.Error(s)
		}
	}
	if _, ok := ParseLevel("loud"); ok {
		t.Error("loud")
	}
}

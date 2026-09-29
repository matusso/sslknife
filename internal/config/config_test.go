package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	tests := map[string]time.Duration{
		"10s":    10 * time.Second,
		"30d":    30 * 24 * time.Hour,
		"2w":     14 * 24 * time.Hour,
		"1y":     365 * 24 * time.Hour,
		"1d12h":  36 * time.Hour,
		"15m":    15 * time.Minute,
		" 90d  ": 90 * 24 * time.Hour,
	}
	for in, want := range tests {
		got, err := ParseDuration(in)
		if err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "abc", "d", "30x", "12dd"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Errorf("ParseDuration(%q) expected error", bad)
		}
	}
}

func TestLoad(t *testing.T) {
	t.Setenv(EnvDatabase, "")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	if _, err := Load(path, true); err == nil {
		t.Fatal("missing explicit config should fail")
	}
	cfg, err := Load(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLS.Timeout.D() != 10*time.Second || cfg.Expiry.WarningDays != 30 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}

	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, true); err != nil {
		t.Fatalf("empty config: %v", err)
	}

	content := `
database:
  path: /tmp/x.db
tls:
  timeout: 3s
  concurrency: 4
ct:
  enabled: false
  interval: 1h
  auto_watch_stored_sans: false
expiry:
  warning_days: 45
  critical_days: 10
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.Path != "/tmp/x.db" || cfg.TLS.Timeout.D() != 3*time.Second ||
		cfg.TLS.Concurrency != 4 || cfg.CT.Enabled || cfg.CT.Interval.D() != time.Hour ||
		cfg.Expiry.WarningDays != 45 {
		t.Fatalf("unexpected config: %+v", cfg)
	}

	if err := os.WriteFile(path, []byte("bogus: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, true); err == nil {
		t.Fatal("unknown fields should be rejected")
	}

	t.Setenv(EnvDatabase, "/other.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path, true)
	if err != nil || cfg.Database.Path != "/other.db" {
		t.Fatalf("env override: %v %v", cfg.Database.Path, err)
	}
}

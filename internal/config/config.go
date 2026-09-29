// Package config loads the SSLKnife configuration file and resolves
// platform-specific default locations.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the on-disk configuration. Secrets never belong here: the
// database password comes from the TTY, the OS keychain or the environment.
type Config struct {
	Database DatabaseConfig `yaml:"database"`
	TLS      TLSConfig      `yaml:"tls"`
	CT       CTConfig       `yaml:"ct"`
	Server   ServerConfig   `yaml:"server"`
	Expiry   ExpiryConfig   `yaml:"expiry"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

type TLSConfig struct {
	Timeout     Duration `yaml:"timeout"`
	Concurrency int      `yaml:"concurrency"`
	Proxy       string   `yaml:"proxy,omitempty"`
}

type CTConfig struct {
	Enabled             bool     `yaml:"enabled"`
	Provider            string   `yaml:"provider"` // certspotter or crtsh
	Interval            Duration `yaml:"interval"`
	AutoWatchStoredSANs bool     `yaml:"auto_watch_stored_sans"`
}

type ServerConfig struct {
	Listen string `yaml:"listen"`
	// RefreshInterval is how often known TLS endpoints are re-inspected
	// by the server (0 disables).
	RefreshInterval Duration `yaml:"refresh_interval"`
}

type ExpiryConfig struct {
	WarningDays  int `yaml:"warning_days"`
	CriticalDays int `yaml:"critical_days"`
}

// Default returns the built-in configuration.
func Default() (*Config, error) {
	dataDir, err := DefaultDataDir()
	if err != nil {
		return nil, err
	}
	return &Config{
		Database: DatabaseConfig{Path: filepath.Join(dataDir, "sslknife.db")},
		TLS:      TLSConfig{Timeout: Duration(10 * time.Second), Concurrency: 8},
		CT:       CTConfig{Enabled: true, Provider: "certspotter", Interval: Duration(15 * time.Minute), AutoWatchStoredSANs: true},
		Server:   ServerConfig{Listen: "127.0.0.1:8443", RefreshInterval: Duration(6 * time.Hour)},
		Expiry:   ExpiryConfig{WarningDays: 30, CriticalDays: 7},
	}, nil
}

// Load reads path on top of the defaults. A missing file is not an error
// unless mustExist is set (the user passed --config explicitly).
func Load(path string, mustExist bool) (*Config, error) {
	cfg, err := Default()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist) && !mustExist:
		// defaults only
	case err != nil:
		return nil, fmt.Errorf("read config: %w", err)
	default:
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		// An empty file decodes to io.EOF and leaves the defaults in place.
		if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
	}
	if p := os.Getenv(EnvDatabase); p != "" {
		cfg.Database.Path = p
	}
	cfg.Database.Path = ExpandHome(cfg.Database.Path)
	return cfg, cfg.Validate()
}

// Validate checks value ranges.
func (c *Config) Validate() error {
	if c.Database.Path == "" {
		return errors.New("config: database.path must not be empty")
	}
	if c.TLS.Timeout.D() <= 0 {
		return errors.New("config: tls.timeout must be positive")
	}
	if c.TLS.Concurrency < 1 || c.TLS.Concurrency > 256 {
		return errors.New("config: tls.concurrency must be between 1 and 256")
	}
	if c.Expiry.WarningDays < 0 || c.Expiry.CriticalDays < 0 {
		return errors.New("config: expiry days must not be negative")
	}
	if c.CT.Interval.D() < time.Minute {
		return errors.New("config: ct.interval must be at least 1m")
	}
	return nil
}

// Marshal renders the configuration as YAML.
func (c *Config) Marshal() ([]byte, error) { return yaml.Marshal(c) }

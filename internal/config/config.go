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
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the on-disk configuration. Secrets never belong here: the
// database password comes from the TTY, the OS keychain or the environment.
type Config struct {
	Database DatabaseConfig `yaml:"database"`
	Vault    VaultConfig    `yaml:"vault"`
	TLS      TLSConfig      `yaml:"tls"`
	CT       CTConfig       `yaml:"ct"`
	Server   ServerConfig   `yaml:"server"`
	Expiry   ExpiryConfig   `yaml:"expiry"`
	Remote   RemoteConfig   `yaml:"remote"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

type VaultConfig struct {
	// UnlockCache keeps the vault unlocked in a background process for this
	// long after its last use, once a password or Touch ID unlocked it
	// (0 disables).
	UnlockCache Duration `yaml:"unlock_cache"`
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

// RemoteConfig shares the inventory between devices through HashiCorp
// Vault. Tokens and AppRole secret IDs never belong here: they come from
// $VAULT_TOKEN, the OS keychain (`sslknife remote login`), a token file or
// $SSLKNIFE_VAULT_SECRET_ID / secret_id_file.
type RemoteConfig struct {
	// Type is "" (no remote) or "vault".
	Type      string `yaml:"type"`
	Address   string `yaml:"address,omitempty"`   // default $VAULT_ADDR
	Namespace string `yaml:"namespace,omitempty"` // default $VAULT_NAMESPACE
	CACert    string `yaml:"ca_cert,omitempty"`   // default $VAULT_CACERT
	Mount     string `yaml:"mount"`               // KV version 2 mount
	Path      string `yaml:"path"`                // prefix inside the mount
	// AuthMethod is token, approle, userpass or ldap.
	AuthMethod   string `yaml:"auth_method"`
	AuthMount    string `yaml:"auth_mount,omitempty"` // default: the method name
	Username     string `yaml:"username,omitempty"`   // userpass/ldap login
	RoleID       string `yaml:"role_id,omitempty"`    // approle
	SecretIDFile string `yaml:"secret_id_file,omitempty"`
	TokenFile    string `yaml:"token_file,omitempty"` // default ~/.vault-token
	// TransitKey, when set, encrypts private keys with this Vault Transit
	// key before they are stored in KV.
	TransitKey   string `yaml:"transit_key,omitempty"`
	TransitMount string `yaml:"transit_mount,omitempty"` // default transit
	// AutoSync syncs before and after every command that opens the vault.
	AutoSync bool `yaml:"auto_sync"`
	// Interval is how often `sslknife server` syncs.
	Interval Duration `yaml:"interval"`
}

// Remote types.
const RemoteVault = "vault"

// Enabled reports whether a remote is configured.
func (r RemoteConfig) Enabled() bool { return r.Type != "" }

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
		Remote:   RemoteConfig{Mount: "secret", Path: "sslknife", AuthMethod: "token", AutoSync: true, Interval: Duration(5 * time.Minute)},
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
	cfg.Remote.CACert = ExpandHome(cfg.Remote.CACert)
	cfg.Remote.SecretIDFile = ExpandHome(cfg.Remote.SecretIDFile)
	cfg.Remote.TokenFile = ExpandHome(cfg.Remote.TokenFile)
	return cfg, cfg.Validate()
}

// Validate checks value ranges.
func (c *Config) Validate() error {
	if c.Database.Path == "" {
		return errors.New("config: database.path must not be empty")
	}
	if c.Vault.UnlockCache.D() < 0 {
		return errors.New("config: vault.unlock_cache must not be negative")
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
	return c.Remote.validate()
}

func (r RemoteConfig) validate() error {
	if !r.Enabled() {
		return nil
	}
	if r.Type != RemoteVault {
		return fmt.Errorf("config: remote.type must be %q or empty, not %q", RemoteVault, r.Type)
	}
	if strings.Trim(r.Mount, "/") == "" || strings.Trim(r.Path, "/") == "" {
		return errors.New("config: remote.mount and remote.path must not be empty")
	}
	switch r.AuthMethod {
	case "token", "userpass", "ldap":
	case "approle":
		if r.RoleID == "" && os.Getenv(EnvVaultRoleID) == "" {
			return fmt.Errorf("config: remote.auth_method approle needs remote.role_id or $%s", EnvVaultRoleID)
		}
	default:
		return fmt.Errorf("config: remote.auth_method must be token, approle, userpass or ldap, not %q", r.AuthMethod)
	}
	if r.Interval.D() < 30*time.Second {
		return errors.New("config: remote.interval must be at least 30s")
	}
	return nil
}

// Marshal renders the configuration as YAML.
func (c *Config) Marshal() ([]byte, error) { return yaml.Marshal(c) }

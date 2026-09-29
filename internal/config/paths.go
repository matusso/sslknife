package config

import (
	"os"
	"path/filepath"
	"runtime"
)

const appName = "sslknife"

// Environment variables that override file locations.
const (
	EnvConfig   = "SSLKNIFE_CONFIG"
	EnvDatabase = "SSLKNIFE_DATABASE"
	EnvDataDir  = "SSLKNIFE_DATA_DIR"
)

// Environment variables for the Vault remote's AppRole login.
const (
	EnvVaultRoleID   = "SSLKNIFE_VAULT_ROLE_ID"
	EnvVaultSecretID = "SSLKNIFE_VAULT_SECRET_ID"
)

// DefaultConfigPath returns the platform config file location:
//
//	Linux:   $XDG_CONFIG_HOME/sslknife/config.yaml (~/.config/...)
//	macOS:   ~/Library/Application Support/sslknife/config.yaml
//	Windows: %AppData%\sslknife\config.yaml
func DefaultConfigPath() (string, error) {
	if p := os.Getenv(EnvConfig); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, appName, "config.yaml"), nil
}

// DefaultDataDir returns the platform data directory:
//
//	Linux:   $XDG_DATA_HOME/sslknife (~/.local/share/sslknife)
//	macOS:   ~/Library/Application Support/sslknife
//	Windows: %LocalAppData%\sslknife
func DefaultDataDir() (string, error) {
	if d := os.Getenv(EnvDataDir); d != "" {
		return d, nil
	}
	switch runtime.GOOS {
	case "windows":
		if d := os.Getenv("LocalAppData"); d != "" {
			return filepath.Join(d, appName), nil
		}
	case "darwin", "ios":
		dir, err := os.UserConfigDir() // ~/Library/Application Support
		if err != nil {
			return "", err
		}
		return filepath.Join(dir, appName), nil
	}
	if d := os.Getenv("XDG_DATA_HOME"); d != "" && filepath.IsAbs(d) {
		return filepath.Join(d, appName), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", appName), nil
}

// ExpandHome replaces a leading "~/" with the user's home directory.
func ExpandHome(p string) string {
	if p == "~" || len(p) >= 2 && p[0] == '~' && (p[1] == '/' || p[1] == filepath.Separator) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[1:])
		}
	}
	return p
}

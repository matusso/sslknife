// Package vaultkv is a small HashiCorp Vault HTTP client covering what the
// remote inventory needs: the KV version 2 secrets engine, the Transit engine
// and token, AppRole and username/password (userpass, LDAP) authentication.
// It avoids the official API module and its large dependency tree.
package vaultkv

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Standard Vault environment variables, honoured as fallbacks for the
// configuration file.
const (
	EnvAddr      = "VAULT_ADDR"
	EnvToken     = "VAULT_TOKEN"
	EnvNamespace = "VAULT_NAMESPACE"
	EnvCACert    = "VAULT_CACERT"
)

// maxResponse bounds how much of a response body is read.
const maxResponse = 64 << 20

var (
	// ErrNotFound means the path does not exist (or its latest version is deleted).
	ErrNotFound = errors.New("vault: not found")
	// ErrConflict means a check-and-set write lost against a concurrent writer.
	ErrConflict = errors.New("vault: check-and-set conflict")
	// ErrPermission means the token is missing, expired or lacks a policy.
	ErrPermission = errors.New("vault: permission denied")
	// ErrUnavailable means Vault could not be reached, is sealed or failed.
	ErrUnavailable = errors.New("vault: unavailable")
)

// Options configure a Client.
type Options struct {
	Address   string // e.g. https://vault.example.com:8200
	Namespace string // Vault Enterprise / HCP namespace
	CACert    string // PEM file with CA certificates to trust
	Token     string
	Timeout   time.Duration
	// HTTPClient replaces the default client (tests).
	HTTPClient *http.Client
}

// Client talks to one Vault server.
type Client struct {
	base      *url.URL
	namespace string
	token     string
	http      *http.Client
}

// New validates the options and builds a client.
func New(o Options) (*Client, error) {
	if o.Address == "" {
		return nil, errors.New("vault: no address configured (set remote.address or $VAULT_ADDR)")
	}
	u, err := url.Parse(strings.TrimRight(o.Address, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("vault: invalid address %q", o.Address)
	}
	hc := o.HTTPClient
	if hc == nil {
		tcfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if o.CACert != "" {
			pem, err := os.ReadFile(o.CACert)
			if err != nil {
				return nil, fmt.Errorf("vault: read CA certificate: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("vault: no certificates in %s", o.CACert)
			}
			tcfg.RootCAs = pool
		}
		timeout := o.Timeout
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		hc = &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tcfg, ForceAttemptHTTP2: true},
		}
	}
	return &Client{base: u, namespace: o.Namespace, token: o.Token, http: hc}, nil
}

// Address returns the server address.
func (c *Client) Address() string { return c.base.String() }

// SetToken replaces the token used for requests.
func (c *Client) SetToken(t string) { c.token = t }

// Token returns the current token.
func (c *Client) Token() string { return c.token }

// HasToken reports whether a token is set.
func (c *Client) HasToken() bool { return c.token != "" }

// response is the common Vault response envelope.
type response struct {
	Data     json.RawMessage `json:"data"`
	Auth     *authInfo       `json:"auth"`
	Errors   []string        `json:"errors"`
	Warnings []string        `json:"warnings"`
}

type authInfo struct {
	ClientToken   string   `json:"client_token"`
	Policies      []string `json:"policies"`
	LeaseDuration int      `json:"lease_duration"`
}

// escapePath escapes every segment of a slash-separated path.
func escapePath(p string) string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

func (c *Client) do(ctx context.Context, method, path string, body any) (*response, int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+"/v1/"+path, rd)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("X-Vault-Request", "true")
	if c.token != "" {
		req.Header.Set("X-Vault-Token", c.token)
	}
	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("vault: read response: %w", err)
	}
	var r response
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, resp.StatusCode, fmt.Errorf("vault: %s %s: HTTP %d with a non-JSON body", method, path, resp.StatusCode)
		}
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return &r, resp.StatusCode, nil
	}
	msg := strings.Join(r.Errors, "; ")
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return &r, resp.StatusCode, ErrNotFound
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized:
		if msg == "" {
			msg = "permission denied"
		}
		return &r, resp.StatusCode, fmt.Errorf("%w: %s %s: %s", ErrPermission, method, path, msg)
	case strings.Contains(msg, "check-and-set"):
		return &r, resp.StatusCode, fmt.Errorf("%w: %s", ErrConflict, msg)
	}
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}
	if resp.StatusCode >= 500 {
		return &r, resp.StatusCode, fmt.Errorf("%w: %s %s: HTTP %d: %s", ErrUnavailable, method, path, resp.StatusCode, msg)
	}
	return &r, resp.StatusCode, fmt.Errorf("vault: %s %s: HTTP %d: %s", method, path, resp.StatusCode, msg)
}

// TokenInfo describes the current token.
type TokenInfo struct {
	DisplayName string    `json:"display_name"`
	Policies    []string  `json:"policies"`
	TTL         int       `json:"ttl"`
	ExpireTime  time.Time `json:"expire_time"`
	Renewable   bool      `json:"renewable"`
}

// LookupSelf validates the token and returns its details.
func (c *Client) LookupSelf(ctx context.Context) (*TokenInfo, error) {
	r, _, err := c.do(ctx, http.MethodGet, "auth/token/lookup-self", nil)
	if err != nil {
		return nil, err
	}
	var d struct {
		DisplayName string   `json:"display_name"`
		Policies    []string `json:"policies"`
		TTL         int      `json:"ttl"`
		ExpireTime  *string  `json:"expire_time"`
		Renewable   bool     `json:"renewable"`
	}
	if err := json.Unmarshal(r.Data, &d); err != nil {
		return nil, fmt.Errorf("vault: token lookup: %w", err)
	}
	ti := &TokenInfo{DisplayName: d.DisplayName, Policies: d.Policies, TTL: d.TTL, Renewable: d.Renewable}
	if d.ExpireTime != nil && *d.ExpireTime != "" {
		ti.ExpireTime, _ = time.Parse(time.RFC3339Nano, *d.ExpireTime)
	}
	return ti, nil
}

// RevokeSelf revokes the current token.
func (c *Client) RevokeSelf(ctx context.Context) error {
	_, _, err := c.do(ctx, http.MethodPost, "auth/token/revoke-self", map[string]any{})
	return err
}

func (c *Client) login(ctx context.Context, path string, body map[string]any) (string, error) {
	r, _, err := c.do(ctx, http.MethodPost, path, body)
	if err != nil {
		return "", err
	}
	if r.Auth == nil || r.Auth.ClientToken == "" {
		return "", errors.New("vault: login returned no token")
	}
	c.token = r.Auth.ClientToken
	return c.token, nil
}

// LoginAppRole authenticates with an AppRole and keeps the resulting token.
func (c *Client) LoginAppRole(ctx context.Context, mount, roleID, secretID string) (string, error) {
	if mount == "" {
		mount = "approle"
	}
	return c.login(ctx, "auth/"+escapePath(mount)+"/login", map[string]any{"role_id": roleID, "secret_id": secretID})
}

// LoginPassword authenticates with the userpass or LDAP method (both share
// the same API) and keeps the resulting token.
func (c *Client) LoginPassword(ctx context.Context, mount, username string, password []byte) (string, error) {
	return c.login(ctx, "auth/"+escapePath(mount)+"/login/"+url.PathEscape(username), map[string]any{"password": string(password)})
}

// KV is a handle on a KV version 2 mount.
type KV struct {
	c     *Client
	mount string
}

// KV returns a handle on the KV v2 engine mounted at mount.
func (c *Client) KV(mount string) *KV { return &KV{c: c, mount: escapePath(mount)} }

// Secret is one KV v2 secret version.
type Secret struct {
	Data    map[string]any
	Version int
}

// Get reads the latest version of path. A soft-deleted latest version is
// reported as ErrNotFound with its version in the returned Secret, so a
// caller can still check-and-set on top of it.
func (kv *KV) Get(ctx context.Context, path string) (*Secret, error) {
	r, _, err := kv.c.do(ctx, http.MethodGet, kv.mount+"/data/"+escapePath(path), nil)
	var d struct {
		Data     map[string]any `json:"data"`
		Metadata struct {
			Version int `json:"version"`
		} `json:"metadata"`
	}
	if r != nil && len(r.Data) > 0 && string(r.Data) != "null" {
		if jerr := json.Unmarshal(r.Data, &d); jerr != nil && err == nil {
			return nil, fmt.Errorf("vault: read %s: %w", path, jerr)
		}
	}
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return &Secret{Version: d.Metadata.Version}, err
		}
		return nil, err
	}
	return &Secret{Data: d.Data, Version: d.Metadata.Version}, nil
}

// Put writes a new version of path. cas < 0 disables check-and-set; cas 0
// requires that the path does not exist; cas N requires current version N.
func (kv *KV) Put(ctx context.Context, path string, data map[string]any, cas int) (int, error) {
	body := map[string]any{"data": data}
	if cas >= 0 {
		body["options"] = map[string]any{"cas": cas}
	}
	r, _, err := kv.c.do(ctx, http.MethodPost, kv.mount+"/data/"+escapePath(path), body)
	if err != nil {
		return 0, err
	}
	var d struct {
		Version int `json:"version"`
	}
	_ = json.Unmarshal(r.Data, &d)
	return d.Version, nil
}

// Destroy permanently removes path and all of its versions.
func (kv *KV) Destroy(ctx context.Context, path string) error {
	_, _, err := kv.c.do(ctx, http.MethodDelete, kv.mount+"/metadata/"+escapePath(path), nil)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// List returns the keys directly below path (sub-folders end with "/").
func (kv *KV) List(ctx context.Context, path string) ([]string, error) {
	r, _, err := kv.c.do(ctx, "LIST", kv.mount+"/metadata/"+escapePath(path), nil)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var d struct {
		Keys []string `json:"keys"`
	}
	if err := json.Unmarshal(r.Data, &d); err != nil {
		return nil, fmt.Errorf("vault: list %s: %w", path, err)
	}
	return d.Keys, nil
}

// Transit is a handle on one Transit engine key.
type Transit struct {
	c    *Client
	path string // <mount>/…/<key>
	name string
	key  string
}

// Transit returns a handle on key in the Transit engine mounted at mount.
func (c *Client) Transit(mount, key string) *Transit {
	if mount == "" {
		mount = "transit"
	}
	return &Transit{c: c, name: mount + "/" + key, path: escapePath(mount), key: url.PathEscape(key)}
}

// Name returns "<mount>/<key>".
func (t *Transit) Name() string { return t.name }

// Encrypt returns a "vault:vN:…" ciphertext for plaintext.
func (t *Transit) Encrypt(ctx context.Context, plaintext []byte) (string, error) {
	r, _, err := t.c.do(ctx, http.MethodPost, t.path+"/encrypt/"+t.key,
		map[string]any{"plaintext": base64.StdEncoding.EncodeToString(plaintext)})
	if err != nil {
		return "", err
	}
	var d struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.Unmarshal(r.Data, &d); err != nil || d.Ciphertext == "" {
		return "", fmt.Errorf("vault: transit encrypt returned no ciphertext")
	}
	return d.Ciphertext, nil
}

// Decrypt reverses Encrypt. The caller should zero the result.
func (t *Transit) Decrypt(ctx context.Context, ciphertext string) ([]byte, error) {
	r, _, err := t.c.do(ctx, http.MethodPost, t.path+"/decrypt/"+t.key, map[string]any{"ciphertext": ciphertext})
	if err != nil {
		return nil, err
	}
	var d struct {
		Plaintext string `json:"plaintext"`
	}
	if err := json.Unmarshal(r.Data, &d); err != nil {
		return nil, fmt.Errorf("vault: transit decrypt: %w", err)
	}
	return base64.StdEncoding.DecodeString(d.Plaintext)
}

// Package ct monitors Certificate Transparency for watched domains through
// CT search services (Cert Spotter, crt.sh). It never mirrors CT logs: only
// issuances matching watched names are fetched and stored.
package ct

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/matusso/sslknife/internal/netdial"
)

// Issuance is one certificate (or precertificate) found in CT.
type Issuance struct {
	Provider     string    `json:"provider"`
	ID           string    `json:"id"`
	Identity     string    `json:"identity"` // de-duplicates precertificate/certificate pairs
	CertSHA256   string    `json:"cert_sha256,omitempty"`
	PubkeySHA256 string    `json:"pubkey_sha256,omitempty"`
	Serial       string    `json:"serial,omitempty"`
	Issuer       string    `json:"issuer"`
	IssuerName   string    `json:"issuer_name,omitempty"`
	DNSNames     []string  `json:"dns_names"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	Revoked      *bool     `json:"revoked,omitempty"`
}

// Query describes what to search for.
type Query struct {
	Domain            string
	IncludeSubdomains bool
	Cursor            string // provider-specific position from the previous poll
}

// Provider searches a CT aggregation service.
type Provider interface {
	Name() string
	// Search returns issuances after the cursor and the new cursor.
	Search(ctx context.Context, q Query) ([]Issuance, string, error)
}

// ErrRateLimited is returned when the service asks us to slow down.
var ErrRateLimited = errors.New("CT provider rate limit reached; try again later")

// NewProvider returns a provider by name.
func NewProvider(name string, d netdial.Dialer, token string) (Provider, error) {
	client := httpClient(d)
	switch strings.ToLower(name) {
	case "", "certspotter", "sslmate":
		return &CertSpotter{Client: client, Token: token, BaseURL: "https://api.certspotter.com"}, nil
	case "crtsh", "crt.sh":
		return &CrtSh{Client: client, BaseURL: "https://crt.sh"}, nil
	}
	return nil, fmt.Errorf("unknown CT provider %q (use certspotter or crtsh)", name)
}

func httpClient(d netdial.Dialer) *http.Client {
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &http.Client{
		Timeout: 3 * timeout,
		Transport: &http.Transport{
			DialContext:         func(ctx context.Context, _, addr string) (net.Conn, error) { return d.DialContext(ctx, addr) },
			TLSHandshakeTimeout: timeout,
		},
	}
}

func getJSON(ctx context.Context, c *http.Client, u string, headers map[string]string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "sslknife-ct/1")
	req.Header.Set("Accept", "application/json")
	for k, val := range headers {
		req.Header.Set(k, val)
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			return fmt.Errorf("%w (retry after %ss)", ErrRateLimited, ra)
		}
		return ErrRateLimited
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: HTTP %s %s", req.URL.Host, resp.Status, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(v)
}

// CertSpotter queries SSLMate's Cert Spotter API, which de-duplicates
// precertificates and supports incremental polling with "after".
type CertSpotter struct {
	Client   *http.Client
	Token    string // optional API key; raises the rate limit
	BaseURL  string
	MaxPages int
}

func (*CertSpotter) Name() string { return "certspotter" }

type csIssuance struct {
	ID           string   `json:"id"`
	TBSSHA256    string   `json:"tbs_sha256"`
	CertSHA256   string   `json:"cert_sha256"`
	PubkeySHA256 string   `json:"pubkey_sha256"`
	DNSNames     []string `json:"dns_names"`
	Issuer       struct {
		FriendlyName string `json:"friendly_name"`
		Name         string `json:"name"`
	} `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Revoked   *bool     `json:"revoked"`
}

// Search pages through issuances after q.Cursor.
func (c *CertSpotter) Search(ctx context.Context, q Query) ([]Issuance, string, error) {
	cursor := q.Cursor
	maxPages := c.MaxPages
	if maxPages <= 0 {
		maxPages = 20
	}
	headers := map[string]string{}
	if c.Token != "" {
		headers["Authorization"] = "Bearer " + c.Token
	}
	var out []Issuance
	for page := 0; page < maxPages; page++ {
		v := url.Values{}
		v.Set("domain", q.Domain)
		v.Set("include_subdomains", fmt.Sprint(q.IncludeSubdomains))
		v.Set("match_wildcards", "true")
		v.Add("expand", "dns_names")
		v.Add("expand", "issuer")
		v.Add("expand", "revocation")
		if cursor != "" {
			v.Set("after", cursor)
		}
		var batch []csIssuance
		if err := getJSON(ctx, c.Client, c.BaseURL+"/v1/issuances?"+v.Encode(), headers, &batch); err != nil {
			return out, cursor, err
		}
		if len(batch) == 0 {
			break
		}
		for _, b := range batch {
			out = append(out, Issuance{
				Provider: c.Name(), ID: b.ID, Identity: "tbs:" + b.TBSSHA256, CertSHA256: b.CertSHA256,
				PubkeySHA256: b.PubkeySHA256, Issuer: b.Issuer.Name, IssuerName: b.Issuer.FriendlyName,
				DNSNames: b.DNSNames, NotBefore: b.NotBefore, NotAfter: b.NotAfter, Revoked: b.Revoked,
			})
		}
		cursor = batch[len(batch)-1].ID
	}
	return out, cursor, nil
}

// CrtSh queries crt.sh. It has no incremental cursor; results are
// de-duplicated by issuer and serial number.
type CrtSh struct {
	Client  *http.Client
	BaseURL string
}

func (*CrtSh) Name() string { return "crtsh" }

type crtshEntry struct {
	ID           int64  `json:"id"`
	IssuerName   string `json:"issuer_name"`
	CommonName   string `json:"common_name"`
	NameValue    string `json:"name_value"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	SerialNumber string `json:"serial_number"`
}

func (c *CrtSh) Search(ctx context.Context, q Query) ([]Issuance, string, error) {
	domain := q.Domain
	if q.IncludeSubdomains {
		domain = "%." + domain
	}
	v := url.Values{}
	v.Set("q", domain)
	v.Set("output", "json")
	v.Set("exclude", "expired")
	var entries []crtshEntry
	if err := getJSON(ctx, c.Client, c.BaseURL+"/?"+v.Encode(), nil, &entries); err != nil {
		return nil, q.Cursor, err
	}
	seen := map[string]bool{}
	var out []Issuance
	var maxID int64
	for _, e := range entries {
		if e.ID > maxID {
			maxID = e.ID
		}
		identity := "serial:" + strings.ToLower(e.IssuerName) + "/" + strings.ToLower(e.SerialNumber)
		if seen[identity] {
			continue
		}
		seen[identity] = true
		nb, _ := time.Parse("2006-01-02T15:04:05", e.NotBefore)
		na, _ := time.Parse("2006-01-02T15:04:05", e.NotAfter)
		names := strings.Fields(strings.ReplaceAll(e.NameValue, "\n", " "))
		out = append(out, Issuance{
			Provider: c.Name(), ID: fmt.Sprint(e.ID), Identity: identity, Serial: e.SerialNumber,
			Issuer: e.IssuerName, DNSNames: names, NotBefore: nb.UTC(), NotAfter: na.UTC(),
		})
	}
	return out, fmt.Sprint(maxID), nil
}

package tlsinspect

import (
	"fmt"
	"slices"
	"time"

	"github.com/matusso/sslknife/internal/certificate"
)

// Snapshot is the compact record of one observation kept in history. It
// holds exactly the properties whose changes are worth detecting.
type Snapshot struct {
	Kind       string    `json:"kind"` // inspect or scan
	Target     string    `json:"target"`
	Protocol   string    `json:"protocol"`
	ScannedAt  time.Time `json:"scanned_at"`
	LeafSHA256 string    `json:"leaf_sha256"`
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	SANs       []string  `json:"sans"`
	NotAfter   time.Time `json:"not_after"`
	Key        string    `json:"key"`
	Trusted    bool      `json:"trusted"`
	Negotiated string    `json:"negotiated_version"`
	Cipher     string    `json:"negotiated_cipher"`
	Versions   []string  `json:"versions,omitempty"` // scan only
	Suites     []string  `json:"cipher_suites,omitempty"`
}

// Snapshot summarises an inspection.
func (r *Result) Snapshot() Snapshot {
	s := Snapshot{Kind: "inspect", Target: r.Target, Protocol: r.Protocol.Protocol, ScannedAt: time.Now().UTC().Truncate(time.Second),
		Trusted: r.Validation.Trusted, Negotiated: r.TLS.Version, Cipher: r.TLS.Cipher}
	if c := r.Certificate; c != nil {
		s.LeafSHA256, s.Subject, s.Issuer = c.Fingerprints.SHA256, c.Subject.DN, c.Issuer.DN
		s.SANs, s.NotAfter, s.Key = c.SANs.All(), c.Validity.NotAfter, c.PublicKey.Description
	}
	return s
}

// Snapshot summarises a scan.
func (r *ScanResult) Snapshot() Snapshot {
	s := r.Connection.Snapshot()
	s.Kind, s.ScannedAt = "scan", r.ScannedAt
	s.Versions = []string{}
	for _, v := range r.Versions {
		if v.Supported {
			s.Versions = append(s.Versions, v.Version)
		}
	}
	for _, c := range r.Ciphers {
		for _, x := range c.Suites {
			s.Suites = append(s.Suites, c.Version+" "+x.Name)
		}
	}
	return s
}

// DiffSnapshots compares two observations. Version and cipher lists are
// only compared when both observations are full scans.
func DiffSnapshots(a, b Snapshot) []certificate.Change {
	var out []certificate.Change
	scalar := func(field, x, y string) {
		out = append(out, certificate.Change{Field: field, Changed: x != y, Old: x, New: y})
	}
	set := func(field string, x, y []string) {
		c := certificate.Change{Field: field}
		for _, v := range y {
			if !slices.Contains(x, v) {
				c.Added = append(c.Added, v)
			}
		}
		for _, v := range x {
			if !slices.Contains(y, v) {
				c.Removed = append(c.Removed, v)
			}
		}
		c.Changed = len(c.Added)+len(c.Removed) > 0
		out = append(out, c)
	}
	scalar("Certificate", a.LeafSHA256, b.LeafSHA256)
	scalar("Subject", a.Subject, b.Subject)
	scalar("Issuer", a.Issuer, b.Issuer)
	set("SAN", a.SANs, b.SANs)
	scalar("Expiration", a.NotAfter.Format(time.DateOnly), b.NotAfter.Format(time.DateOnly))
	scalar("Public Key", a.Key, b.Key)
	scalar("Trusted", fmt.Sprint(a.Trusted), fmt.Sprint(b.Trusted))
	scalar("Negotiated Version", a.Negotiated, b.Negotiated)
	scalar("Negotiated Cipher", a.Cipher, b.Cipher)
	if a.Kind == "scan" && b.Kind == "scan" {
		set("TLS Versions", a.Versions, b.Versions)
		set("Cipher Suites", a.Suites, b.Suites)
	}
	return out
}

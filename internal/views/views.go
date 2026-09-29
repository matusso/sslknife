// Package views defines the public JSON schema of inventory objects shared
// by the CLI (--json/--yaml) and the REST API. Internal database rows are
// never serialised directly.
package views

import (
	"crypto/x509"
	"time"

	"github.com/matusso/sslknife/internal/database"
	"github.com/matusso/sslknife/internal/sshkeys"
	"golang.org/x/crypto/ssh"
)

// Expiry holds the configured warning thresholds.
type Expiry struct {
	WarningDays  int
	CriticalDays int
}

// CertStatus classifies a certificate: EXPIRED, NOT_YET_VALID, CRITICAL,
// WARNING, CA or OK, and returns the whole days remaining.
func CertStatus(nb, na time.Time, isCA bool, e Expiry, now time.Time) (string, int) {
	days := int(na.Sub(now).Hours() / 24)
	switch {
	case !now.Before(na):
		return "EXPIRED", days
	case now.Before(nb):
		return "NOT_YET_VALID", days
	case days < e.CriticalDays:
		return "CRITICAL", days
	case days < e.WarningDays:
		return "WARNING", days
	case isCA:
		return "CA", days
	}
	return "OK", days
}

// CertSummary describes a stored certificate in listings.
type CertSummary struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name,omitempty"`
	CommonName         string    `json:"common_name"`
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SANs               []string  `json:"sans"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	DaysRemaining      int       `json:"days_remaining"`
	Status             string    `json:"status"`
	Key                string    `json:"key"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	IsCA               bool      `json:"is_ca"`
	SelfSigned         bool      `json:"self_signed"`
	SHA256             string    `json:"sha256"`
	Serial             string    `json:"serial"`
	Tags               []string  `json:"tags"`
	KeyID              string    `json:"key_id,omitempty"`
	IssuerID           string    `json:"issuer_id,omitempty"`
	CTMonitored        bool      `json:"ct_monitored"`
	Source             string    `json:"source"`
	Comment            string    `json:"comment,omitempty"`
	ImportedAt         time.Time `json:"imported_at"`
}

// Summarize converts a stored certificate.
func Summarize(c *database.Certificate, e Expiry) CertSummary {
	status, days := CertStatus(c.NotBefore, c.NotAfter, c.IsCA, e, time.Now())
	s := CertSummary{
		ID: c.ID, Name: c.Name, CommonName: c.SubjectCN, Subject: c.Subject, Issuer: c.Issuer,
		NotBefore: c.NotBefore, NotAfter: c.NotAfter, DaysRemaining: days, Status: status,
		Key: c.KeyDescription, SignatureAlgorithm: c.SignatureAlgorithm, IsCA: c.IsCA, SelfSigned: c.SelfSigned,
		SHA256: c.SHA256, Serial: c.Serial, Tags: c.Tags, KeyID: c.KeyID, IssuerID: c.IssuerID,
		CTMonitored: c.CTMonitored, Source: c.Source, Comment: c.Comment, ImportedAt: c.ImportedAt,
		SANs: []string{},
	}
	for _, san := range c.SANs {
		s.SANs = append(s.SANs, san.Value)
	}
	if s.Tags == nil {
		s.Tags = []string{}
	}
	return s
}

// SummarizeAll converts a list (never nil).
func SummarizeAll(certs []*database.Certificate, e Expiry) []CertSummary {
	out := make([]CertSummary, 0, len(certs))
	for _, c := range certs {
		out = append(out, Summarize(c, e))
	}
	return out
}

// Key describes a stored key; it never contains key material.
type Key struct {
	ID             string    `json:"id"`
	Name           string    `json:"name,omitempty"`
	Algorithm      string    `json:"algorithm"`
	Bits           int       `json:"bits"`
	Description    string    `json:"description"`
	SPKISHA256     string    `json:"spki_sha256"`
	SSHFingerprint string    `json:"ssh_fingerprint,omitempty"`
	HasPrivate     bool      `json:"has_private_key"`
	Source         string    `json:"source"`
	Comment        string    `json:"comment,omitempty"`
	Tags           []string  `json:"tags"`
	ImportedAt     time.Time `json:"imported_at"`
	Certificates   []string  `json:"certificates,omitempty"`
}

// NewKey converts a stored key.
func NewKey(k *database.Key) Key {
	v := Key{ID: k.ID, Name: k.Name, Algorithm: k.Algorithm, Bits: k.Bits, Description: k.Description,
		SPKISHA256: k.SPKISHA256, HasPrivate: k.HasPrivate(), Source: k.Source, Comment: k.Comment, Tags: k.Tags, ImportedAt: k.ImportedAt}
	if pub, err := x509.ParsePKIXPublicKey(k.PublicDER); err == nil {
		if sp, err := ssh.NewPublicKey(pub); err == nil {
			v.SSHFingerprint = ssh.FingerprintSHA256(sp)
		}
	}
	if v.Tags == nil {
		v.Tags = []string{}
	}
	return v
}

// SSHKey describes a stored SSH key; it never contains private material.
type SSHKey struct {
	ID          string    `json:"id"`
	Name        string    `json:"name,omitempty"`
	Type        string    `json:"type"`
	Bits        int       `json:"bits"`
	Fingerprint string    `json:"fingerprint_sha256"`
	Comment     string    `json:"comment,omitempty"`
	HasPrivate  bool      `json:"has_private_key"`
	Passphrase  bool      `json:"passphrase_protected"`
	PublicKey   string    `json:"public_key"`
	Source      string    `json:"source"`
	Tags        []string  `json:"tags"`
	ImportedAt  time.Time `json:"imported_at"`
}

// NewSSHKey converts a stored SSH key.
func NewSSHKey(k *database.SSHKey) SSHKey {
	v := SSHKey{ID: k.ID, Name: k.Name, Type: k.Type, Bits: k.Bits, Fingerprint: k.FingerprintSHA256, Comment: k.Comment,
		HasPrivate: k.HasPrivate(), Passphrase: k.PassphraseProtected, PublicKey: k.PublicKey, Source: k.Source, Tags: k.Tags, ImportedAt: k.ImportedAt}
	if v.Tags == nil {
		v.Tags = []string{}
	}
	return v
}

// CTObservation describes one CT observation.
type CTObservation struct {
	ID         string    `json:"id"`
	Watch      string    `json:"watch,omitempty"`
	Status     string    `json:"status"`
	Reason     string    `json:"reason"`
	DNSNames   []string  `json:"dns_names"`
	Issuer     string    `json:"issuer"`
	IssuerName string    `json:"issuer_name,omitempty"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	CertSHA256 string    `json:"cert_sha256,omitempty"`
	Serial     string    `json:"serial,omitempty"`
	Provider   string    `json:"provider"`
	ExternalID string    `json:"provider_id"`
	Revoked    *bool     `json:"revoked,omitempty"`
	KnownCert  string    `json:"known_certificate,omitempty"`
	Acked      bool      `json:"acknowledged"`
	FirstSeen  time.Time `json:"first_seen"`
}

// NewCTObservation converts a stored observation.
func NewCTObservation(o database.CTObservation, watch string) CTObservation {
	names := o.DNSNames
	if names == nil {
		names = []string{}
	}
	return CTObservation{ID: o.ID, Watch: watch, Status: o.Status, Reason: o.Reason, DNSNames: names, Issuer: o.Issuer,
		IssuerName: o.IssuerName, NotBefore: o.NotBefore, NotAfter: o.NotAfter, CertSHA256: o.CertSHA256, Serial: o.Serial,
		Provider: o.Provider, ExternalID: o.ExternalID, Revoked: o.Revoked, KnownCert: o.KnownCertID, Acked: o.Acknowledged, FirstSeen: o.FirstSeen}
}

// SSHInfo is re-exported for API consumers.
type SSHInfo = sshkeys.Info

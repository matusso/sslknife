package certificate

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Change describes one compared field.
type Change struct {
	Field   string   `json:"field"`
	Changed bool     `json:"changed"`
	Old     string   `json:"old,omitempty"`
	New     string   `json:"new,omitempty"`
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
}

// Diff compares two certificate descriptions field by field.
func Diff(a, b Info) []Change {
	var out []Change
	scalar := func(field, x, y string) {
		out = append(out, Change{Field: field, Changed: x != y, Old: x, New: y})
	}
	set := func(field string, x, y []string) {
		c := Change{Field: field}
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
	scalar("Subject", a.Subject.DN, b.Subject.DN)
	scalar("Issuer", a.Issuer.DN, b.Issuer.DN)
	scalar("Serial", a.Serial, b.Serial)
	set("SAN", a.SANs.All(), b.SANs.All())
	scalar("Not Before", a.Validity.NotBefore.Format(time.RFC3339), b.Validity.NotBefore.Format(time.RFC3339))
	scalar("Expiration", a.Validity.NotAfter.Format(time.RFC3339), b.Validity.NotAfter.Format(time.RFC3339))
	scalar("Public Key", pubSummary(a), pubSummary(b))
	scalar("Signature Algorithm", a.SignatureAlgorithm, b.SignatureAlgorithm)
	scalar("CA", fmt.Sprint(a.IsCA), fmt.Sprint(b.IsCA))
	set("Key Usage", a.KeyUsage, b.KeyUsage)
	set("Extended Key Usage", a.ExtKeyUsage, b.ExtKeyUsage)
	set("OCSP", a.OCSPServers, b.OCSPServers)
	set("CRL Distribution Points", a.CRLDistribution, b.CRLDistribution)
	set("Policies", policyOIDs(a.Policies), policyOIDs(b.Policies))
	scalar("Fingerprint (SHA-256)", a.Fingerprints.SHA256, b.Fingerprints.SHA256)
	return out
}

func pubSummary(i Info) string {
	return i.PublicKey.Description + " " + i.PublicKey.SPKISHA256
}

func policyOIDs(p []Policy) []string {
	out := make([]string, len(p))
	for i, x := range p {
		out[i] = x.OID
		if x.Name != "" {
			out[i] += " (" + x.Name + ")"
		}
	}
	return out
}

// Identical reports whether no field changed.
func Identical(changes []Change) bool {
	return !slices.ContainsFunc(changes, func(c Change) bool { return c.Changed })
}

// FormatChange renders a change in +/- style for text output.
func FormatChange(c Change) []string {
	if !c.Changed {
		return []string{"  unchanged"}
	}
	var lines []string
	if c.Added != nil || c.Removed != nil {
		for _, r := range c.Removed {
			lines = append(lines, "- "+r)
		}
		for _, a := range c.Added {
			lines = append(lines, "+ "+a)
		}
		return lines
	}
	return []string{"- " + strings.TrimSpace(c.Old), "+ " + strings.TrimSpace(c.New)}
}

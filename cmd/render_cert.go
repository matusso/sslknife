package cmd

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/matusso/sslknife/internal/certificate"
	"github.com/matusso/sslknife/internal/database"
	"github.com/matusso/sslknife/internal/output"
	"github.com/matusso/sslknife/internal/views"
)

// certSummary is the JSON schema for stored certificates in listings.
type certSummary = views.CertSummary

func (a *app) expiry() views.Expiry {
	return views.Expiry{WarningDays: a.cfg.Expiry.WarningDays, CriticalDays: a.cfg.Expiry.CriticalDays}
}

// certStatus classifies a certificate for listings.
func (a *app) certStatus(nb, na time.Time, isCA bool) (string, int) {
	return views.CertStatus(nb, na, isCA, a.expiry(), time.Now())
}

func (a *app) summarize(c *database.Certificate) certSummary { return views.Summarize(c, a.expiry()) }

func (a *app) summarizeAll(certs []*database.Certificate) []certSummary {
	return views.SummarizeAll(certs, a.expiry())
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func (a *app) renderCertTable(w io.Writer, certs []certSummary) error {
	st := a.out.Style
	t := output.NewTable("ID", "NAME", "CN", "EXPIRES", "DAYS", "ALGORITHM", "STATUS")
	for _, c := range certs {
		cn := c.CommonName
		if cn == "" {
			cn = c.Subject
		}
		days := fmt.Sprint(c.DaysRemaining)
		if c.Status == "EXPIRED" {
			days = "-"
		}
		t.Row(st.Dim(c.ID[:8]), c.Name, truncate(cn, 40), c.NotAfter.Format(time.DateOnly), days, c.Key, st.Level(c.Status))
	}
	return t.Render(w, st)
}

func daysLabel(v certificate.Validity) string {
	switch v.Status {
	case "expired":
		return fmt.Sprintf("expired %d days ago", -v.DaysRemaining)
	case "not_yet_valid":
		return "not yet valid"
	}
	return fmt.Sprintf("%d days remaining", v.DaysRemaining)
}

func (a *app) validityLevel(v certificate.Validity) string {
	switch v.Status {
	case "expired":
		return "EXPIRED"
	case "not_yet_valid":
		return "INVALID"
	}
	if v.DaysRemaining < a.cfg.Expiry.CriticalDays {
		return "CRITICAL"
	}
	if v.DaysRemaining < a.cfg.Expiry.WarningDays {
		return "WARNING"
	}
	return "VALID"
}

// renderInfo writes the full human-readable description of a certificate.
func (a *app) renderInfo(w io.Writer, info certificate.Info) error {
	st := a.out.Style
	kv := output.NewKV(st)
	kv.Add("Subject", info.Subject.DN).Add("Issuer", info.Issuer.DN).Add("Serial", info.Serial).
		Addf("Version", "%d", info.Version)
	var kind []string
	if info.IsCA {
		kind = append(kind, st.Cyan("CA"))
	}
	if info.SelfSigned {
		kind = append(kind, "self-signed")
	}
	if len(kind) == 0 {
		kind = append(kind, "end-entity")
	}
	kv.Add("Type", strings.Join(kind, ", "))

	kv.Heading("Validity")
	kv.Add("Not Before", info.Validity.NotBefore.Format(time.RFC3339)).
		Add("Not After", info.Validity.NotAfter.Format(time.RFC3339)).
		Add("Status", st.Level(a.validityLevel(info.Validity))+"  "+daysLabel(info.Validity)).
		Addf("Lifetime", "%d days", info.Validity.LifetimeDays)

	if len(info.SANs.All()) > 0 {
		kv.Heading("Subject Alternative Names")
		kv.List("DNS", info.SANs.DNS).List("IP", info.SANs.IP).List("Email", info.SANs.Email).List("URI", info.SANs.URI)
	}

	kv.Heading("Public Key")
	pk := info.PublicKey
	kv.Add("Algorithm", pk.Description).Add("Curve", pk.Curve)
	if pk.Exponent != 0 {
		kv.Addf("Exponent", "%d", pk.Exponent)
	}
	kv.Add("Strength", st.Level(strings.ToUpper(pk.Strength)))
	kv.Add("SPKI SHA-256", pk.SPKISHA256)

	kv.Heading("Signature")
	sig := info.SignatureAlgorithm
	if info.SignatureStrength != "modern" {
		sig += "  " + st.Level(strings.ToUpper(info.SignatureStrength))
	}
	kv.Add("Algorithm", sig)

	kv.Heading("Fingerprints")
	kv.Add("SHA-256", certificate.Colon(info.Fingerprints.SHA256)).
		Add("SHA-1", certificate.Colon(info.Fingerprints.SHA1)+st.Dim("  (legacy identifier)"))

	kv.Heading("Extensions")
	if bc := info.BasicConstraints; bc != nil {
		v := fmt.Sprintf("CA:%v", bc.CA)
		if bc.PathLen != nil {
			v += fmt.Sprintf(", pathlen:%d", *bc.PathLen)
		}
		if bc.Critical {
			v += st.Dim("  (critical)")
		}
		kv.Add("Basic Constraints", v)
	}
	kv.Add("Key Usage", strings.Join(info.KeyUsage, ", ")).
		Add("Extended Key Usage", strings.Join(info.ExtKeyUsage, ", ")).
		Add("Subject Key ID", info.SubjectKeyID).
		Add("Authority Key ID", info.AuthorityKeyID).
		List("CRL Distribution", info.CRLDistribution).
		List("OCSP", info.OCSPServers).
		List("CA Issuers", info.CAIssuers)
	var pol []string
	for _, p := range info.Policies {
		if p.Name != "" {
			pol = append(pol, p.OID+" ("+p.Name+")")
		} else {
			pol = append(pol, p.OID)
		}
	}
	kv.List("Policies", pol)
	if nc := info.NameConstraints; nc != nil {
		var l []string
		add := func(prefix string, v []string) {
			for _, x := range v {
				l = append(l, prefix+x)
			}
		}
		add("permitted DNS: ", nc.PermittedDNS)
		add("excluded DNS: ", nc.ExcludedDNS)
		add("permitted IP: ", nc.PermittedIP)
		add("excluded IP: ", nc.ExcludedIP)
		add("permitted email: ", nc.PermittedEmail)
		add("excluded email: ", nc.ExcludedEmail)
		add("permitted URI: ", nc.PermittedURI)
		add("excluded URI: ", nc.ExcludedURI)
		kv.List("Name Constraints", l)
	}
	if info.MustStaple {
		kv.Add("TLS Feature", "OCSP Must-Staple")
	}
	var scts []string
	for _, s := range info.SCTs {
		scts = append(scts, fmt.Sprintf("%s  %s  %s/%s", s.Timestamp.Format(time.RFC3339), s.LogID, s.HashAlgorithm, s.SignatureAlgorithm))
	}
	kv.List("SCTs", scts)
	var unknown []string
	for _, e := range info.Extensions {
		if !e.Known {
			crit := ""
			if e.Critical {
				crit = st.Red(" (critical)")
			}
			unknown = append(unknown, fmt.Sprintf("%s  %d bytes%s", e.OID, e.Size, crit))
		}
	}
	kv.List("Unknown", unknown)
	kv.Addf("DER size", "%d bytes", info.DERSize)

	if len(info.Warnings) > 0 {
		kv.Heading(st.Yellow("Warnings"))
		for _, wn := range info.Warnings {
			kv.Add("!", wn)
		}
	}
	if err := kv.Render(w); err != nil {
		return err
	}
	if info.PEM != "" {
		fmt.Fprintln(w)
		_, err := io.WriteString(w, info.PEM)
		return err
	}
	return nil
}

// renderChainTree prints certificates root-first as a tree, like
//
//	Root CA
//	└── Intermediate
//	    └── leaf
func (a *app) renderChainTree(w io.Writer, labels []string) error {
	if len(labels) == 0 {
		return nil
	}
	root := &output.Node{Label: labels[len(labels)-1]}
	cur := root
	for i := len(labels) - 2; i >= 0; i-- {
		cur = cur.Add(labels[i])
	}
	return output.RenderTree(w, root)
}

func (a *app) renderFindings(w io.Writer, findings []certificate.Finding) error {
	st := a.out.Style
	if len(findings) == 0 {
		_, err := fmt.Fprintln(w, st.Green("No issues found."))
		return err
	}
	for i, f := range findings {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "%s  %s  %s\n", st.Level(strings.ToUpper(f.Severity)), st.Bold(f.ID), st.Dim(f.Certificate))
		fmt.Fprintf(w, "  %s     %s\n", st.Dim("WHAT"), f.What)
		fmt.Fprintf(w, "  %s      %s\n", st.Dim("WHY"), f.Why)
		fmt.Fprintf(w, "  %s %s\n", st.Dim("EVIDENCE"), f.Evidence)
		if f.Reference != "" {
			fmt.Fprintf(w, "  %s      %s\n", st.Dim("REF"), f.Reference)
		}
	}
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	fmt.Fprintf(w, "\n%d errors, %d warnings, %d notices\n", counts[certificate.SevError], counts[certificate.SevWarning], counts[certificate.SevNotice])
	return nil
}

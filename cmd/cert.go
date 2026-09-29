package cmd

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/matusso/sslknife/internal/certificate"
	"github.com/matusso/sslknife/internal/config"
	"github.com/matusso/sslknife/internal/database"
	"github.com/matusso/sslknife/internal/exitcode"
	"github.com/matusso/sslknife/internal/output"
	"github.com/matusso/sslknife/internal/tlsinspect"
)

func newCertCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "cert",
		Aliases: []string{"certificate", "certs", "x509"},
		Short:   "Inspect, create and manage X.509 certificates",
	}
	cmd.AddCommand(
		newCertInspectCmd(a),
		newCertFieldCmd(a, "sans", "Print Subject Alternative Names, one per line", certFieldSANs),
		newCertFieldCmd(a, "subject", "Print the subject distinguished name", certFieldSubject),
		newCertFieldCmd(a, "issuer", "Print the issuer distinguished name", certFieldIssuer),
		newCertExpiresCmd(a),
		newCertPEMCmd(a),
		newCertLintCmd(a),
		newCertDiffCmd(a),
		newCertChainCmd(a),
		newCertCreateCmd(a),
		newCertCSRCmd(a),
		newCertImportCmd(a),
		newCertListCmd(a),
		newCertShowCmd(a),
		newCertExportCmd(a),
		newCertDeleteCmd(a),
		newCertTagCmd(a, true),
		newCertTagCmd(a, false),
		newCertNoteCmd(a),
		newCertRenameCmd(a),
		newCertExpiringCmd(a),
	)
	return cmd
}

// loadCerts reads certificates from a file, stdin ("-"), or, when arg is
// not a readable file, from the inventory by ID/name/fingerprint.
func (a *app) loadCerts(ctx context.Context, arg string) ([]*x509.Certificate, string, error) {
	if arg == "-" || fileExists(arg) {
		data, err := a.readInput(arg)
		if err != nil {
			return nil, "", err
		}
		certs, err := certificate.Parse(data)
		if err != nil {
			if errors.Is(err, certificate.ErrNoCertificate) {
				return nil, "", exitcode.New(exitcode.Usage, "%s: no certificate found (supported: PEM, DER, PKCS#7)", displayName(arg))
			}
			return nil, "", fmt.Errorf("%s: %w", displayName(arg), err)
		}
		return certs, displayName(arg), nil
	}
	if looksRemote(arg) {
		certs, err := a.fetchRemoteChain(ctx, arg)
		return certs, arg, err
	}
	if !database.Exists(a.cfg.Database.Path) {
		return nil, "", exitcode.New(exitcode.NotFound, "%s: no such file (use host:port for a remote server)", arg)
	}
	inv, err := a.inventory(ctx)
	if err != nil {
		return nil, "", err
	}
	row, c, err := inv.Certificate(ctx, arg)
	if err != nil {
		return nil, "", mapLookupErr(err, arg)
	}
	return []*x509.Certificate{c}, "inventory:" + row.ID, nil
}

// fetchRemoteChain retrieves the certificate chain presented by a server.
func (a *app) fetchRemoteChain(ctx context.Context, arg string) ([]*x509.Certificate, error) {
	c, err := a.connector(ctx, arg, &tlsFlags{})
	if err != nil {
		return nil, err
	}
	certs, err := c.Certificates(ctx)
	if err != nil {
		return nil, networkErr(err)
	}
	if len(certs) == 0 {
		return nil, exitcode.New(exitcode.Network, "%s presented no certificate", arg)
	}
	return certs, nil
}

// certFileExts are extensions that mark an argument as a (missing) file
// rather than a hostname.
var certFileExts = []string{".pem", ".crt", ".cer", ".der", ".p7b", ".p7c", ".key", ".csr", ".p12", ".pfx", ".jks", ".pub", ".txt"}

// looksRemote reports whether a non-file argument names a network target:
// host:port, a URL, or a bare hostname such as example.com.
func looksRemote(arg string) bool {
	if arg == "-" || fileExists(arg) {
		return false
	}
	if tlsinspect.LooksLikeTarget(arg) {
		return true
	}
	lower := strings.ToLower(arg)
	for _, ext := range certFileExts {
		if strings.HasSuffix(lower, ext) {
			return false
		}
	}
	return strings.Contains(arg, ".") && !strings.ContainsAny(arg, `/\`) && certificate.ValidateDNSName(lower) == nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func mapLookupErr(err error, ref string) error {
	switch {
	case errors.Is(err, database.ErrNotFound):
		return exitcode.New(exitcode.NotFound, "%q is neither a file nor a stored object", ref)
	case errors.Is(err, database.ErrAmbiguous):
		return exitcode.With(exitcode.Usage, err)
	}
	return err
}

func (a *app) describeOpts(includePEM bool) certificate.Options {
	return certificate.Options{WarningDays: a.cfg.Expiry.WarningDays, IncludePEM: includePEM}
}

type inspectView struct {
	Source       string             `json:"source"`
	Certificates []certificate.Info `json:"certificates"`
}

func newCertInspectCmd(a *app) *cobra.Command {
	var withPEM, leafOnly bool
	cmd := &cobra.Command{
		Use:   "inspect <file|->",
		Short: "Show everything about a certificate or bundle",
		Long: `Decode a certificate file (PEM, DER or PKCS#7, auto-detected) and show all
fields and extensions, with deprecated or unusual properties highlighted.

The argument may also be the ID, name or fingerprint of a stored certificate.`,
		Example: `  sslknife cert inspect server.pem
  cat chain.pem | sslknife cert inspect -
  sslknife cert inspect server.der --json | jq '.certificates[0].sans'`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			certs, src, err := a.loadCerts(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if leafOnly {
				certs = certs[:1]
			}
			view := inspectView{Source: src}
			for _, c := range certs {
				view.Certificates = append(view.Certificates, certificate.Describe(c, a.describeOpts(withPEM)))
			}
			if a.out.Format == output.Raw {
				_, err := a.stdout.Write(certificate.EncodePEM(certs...))
				return err
			}
			return a.out.Emit(view, func(w io.Writer) error {
				for i, info := range view.Certificates {
					if len(view.Certificates) > 1 {
						if i > 0 {
							fmt.Fprintln(w)
						}
						fmt.Fprintln(w, a.out.Style.Bold(fmt.Sprintf("── Certificate %d of %d ──", i+1, len(view.Certificates))))
					}
					if err := a.renderInfo(w, info); err != nil {
						return err
					}
				}
				if len(certs) > 1 {
					ordered := certificate.Order(certificate.FindLeaf(certs), certs)
					var labels []string
					for _, c := range ordered {
						labels = append(labels, certificate.NewName(c.Subject).DisplayName())
					}
					fmt.Fprintln(w)
					fmt.Fprintln(w, a.out.Style.Bold("Chain"))
					return a.renderChainTree(w, labels)
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&withPEM, "pem", false, "include the PEM encoding")
	cmd.Flags().BoolVar(&leafOnly, "leaf", false, "only show the first certificate")
	return cmd
}

type certField int

const (
	certFieldSANs certField = iota
	certFieldSubject
	certFieldIssuer
)

func newCertFieldCmd(a *app, use, short string, field certField) *cobra.Command {
	return &cobra.Command{
		Use:   use + " <file|->",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			certs, _, err := a.loadCerts(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			c := certs[0]
			switch field {
			case certFieldSANs:
				sans := certificate.CertSANs(c)
				return a.out.Emit(sans, func(w io.Writer) error {
					for _, s := range sans.All() {
						fmt.Fprintln(w, s)
					}
					return nil
				})
			case certFieldSubject:
				n := certificate.NewName(c.Subject)
				return a.out.Emit(n, func(w io.Writer) error { _, err := fmt.Fprintln(w, n.DN); return err })
			default:
				n := certificate.NewName(c.Issuer)
				return a.out.Emit(n, func(w io.Writer) error { _, err := fmt.Fprintln(w, n.DN); return err })
			}
		},
	}
}

func newCertExpiresCmd(a *app) *cobra.Command {
	var check string
	cmd := &cobra.Command{
		Use:   "expires <file|->",
		Short: "Print the expiry date and remaining days",
		Long: `Print when the certificate expires. With --check, exit with status 5 when
the certificate expires within the given period (for monitoring scripts).`,
		Example: `  sslknife cert expires server.pem
  sslknife cert expires server.pem --check 30d || echo "renew soon"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			certs, _, err := a.loadCerts(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			v := certificate.ComputeValidity(certs[0].NotBefore, certs[0].NotAfter, time.Now(), a.cfg.Expiry.WarningDays)
			err = a.out.Emit(v, func(w io.Writer) error {
				_, err := fmt.Fprintf(w, "%s  %s\n", v.NotAfter.Format(time.RFC3339), daysLabel(v))
				return err
			})
			if err != nil || check == "" {
				return err
			}
			d, err := config.ParseDuration(check)
			if err != nil {
				return usageError{err}
			}
			if time.Until(v.NotAfter) < d {
				return exitcode.Silent(exitcode.CheckFailed)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&check, "check", "", "exit 5 if the certificate expires within this period (e.g. 30d)")
	return cmd
}

func newCertPEMCmd(a *app) *cobra.Command {
	var der bool
	cmd := &cobra.Command{
		Use:   "pem <file|->",
		Short: "Convert certificates to PEM (or DER with --der)",
		Example: `  sslknife cert pem server.der > server.pem
  sslknife cert pem bundle.p7b > chain.pem
  sslknife cert pem server.pem --der > server.der`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			certs, _, err := a.loadCerts(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if der {
				if len(certs) != 1 {
					return exitcode.New(exitcode.Unsupported, "DER holds exactly one certificate but the input has %d; pick one with 'cert inspect --leaf' or split the bundle", len(certs))
				}
				_, err = a.stdout.Write(certs[0].Raw)
				return err
			}
			_, err = a.stdout.Write(certificate.EncodePEM(certs...))
			return err
		},
	}
	cmd.Flags().BoolVar(&der, "der", false, "write binary DER instead of PEM")
	return cmd
}

type lintView struct {
	Source   string                `json:"source"`
	Findings []certificate.Finding `json:"findings"`
	Errors   int                   `json:"errors"`
	Warnings int                   `json:"warnings"`
	Notices  int                   `json:"notices"`
}

func newCertLintCmd(a *app) *cobra.Command {
	var hostname, trustStore string
	var trust, strict bool
	cmd := &cobra.Command{
		Use:   "lint <file|->",
		Short: "Check a certificate or chain against RFC 5280 and CA/B Forum rules",
		Long: `Check certificates for standards violations and risky properties. Each
finding explains WHAT is wrong, WHY it matters and the EVIDENCE found, with a
reference to the relevant RFC or CA/Browser Forum Baseline Requirement.

A bundle with several certificates is also checked as a chain (order,
missing intermediates, issuer constraints).

Exit status is 5 when an error-level finding exists (or any warning with --strict).`,
		Example: `  sslknife cert lint server.pem
  sslknife cert lint fullchain.pem --hostname api.example.com --trust
  sslknife cert lint chain.pem --truststore company-root.pem --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			certs, src, err := a.loadCerts(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			opts := certificate.LintOptions{Hostname: hostname, CheckTrust: trust || trustStore != ""}
			if trustStore != "" {
				data, err := a.readInput(trustStore)
				if err != nil {
					return err
				}
				if opts.Roots, _, err = certificate.LoadPool(data); err != nil {
					return fmt.Errorf("truststore: %w", err)
				}
			}
			findings := certificate.Lint(certs, opts)
			view := lintView{Source: src, Findings: findings}
			if view.Findings == nil {
				view.Findings = []certificate.Finding{}
			}
			for _, f := range findings {
				switch f.Severity {
				case certificate.SevError:
					view.Errors++
				case certificate.SevWarning:
					view.Warnings++
				default:
					view.Notices++
				}
			}
			if err := a.out.Emit(view, func(w io.Writer) error { return a.renderFindings(w, findings) }); err != nil {
				return err
			}
			if view.Errors > 0 || strict && view.Warnings > 0 {
				return exitcode.Silent(exitcode.CheckFailed)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&hostname, "hostname", "", "check that the certificate is valid for this hostname")
	cmd.Flags().BoolVar(&trust, "trust", false, "validate the chain against the system trust store")
	cmd.Flags().StringVar(&trustStore, "truststore", "", "validate the chain against these root certificates (PEM/DER)")
	cmd.Flags().BoolVar(&strict, "strict", false, "fail on warnings as well as errors")
	return cmd
}

type diffView struct {
	A         string               `json:"a"`
	B         string               `json:"b"`
	Identical bool                 `json:"identical"`
	Changes   []certificate.Change `json:"changes"`
}

func newCertDiffCmd(a *app) *cobra.Command {
	var changedOnly bool
	cmd := &cobra.Command{
		Use:   "diff <cert1> <cert2>",
		Short: "Compare two certificates field by field",
		Long: `Compare two certificates (files or stored certificates) and show what
changed: subject, issuer, SANs, validity, key, signature, usages and policies.

Exit status is 5 when the certificates differ.`,
		Example: `  sslknife cert diff old.pem new.pem
  sslknife cert diff api-prod renewed.pem --changed`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ca, _, err := a.loadCerts(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			cb, _, err := a.loadCerts(cmd.Context(), args[1])
			if err != nil {
				return err
			}
			changes := certificate.Diff(certificate.Describe(ca[0], certificate.Options{}), certificate.Describe(cb[0], certificate.Options{}))
			view := diffView{A: args[0], B: args[1], Identical: certificate.Identical(changes), Changes: changes}
			err = a.out.Emit(view, func(w io.Writer) error {
				st := a.out.Style
				for _, c := range changes {
					if changedOnly && !c.Changed {
						continue
					}
					fmt.Fprintf(w, "%s:\n", st.Bold(c.Field))
					for _, l := range certificate.FormatChange(c) {
						switch {
						case strings.HasPrefix(l, "+"):
							l = st.Green(l)
						case strings.HasPrefix(l, "-"):
							l = st.Red(l)
						default:
							l = st.Dim(l)
						}
						fmt.Fprintln(w, l)
					}
					fmt.Fprintln(w)
				}
				if view.Identical {
					fmt.Fprintln(w, "Certificates are identical.")
				}
				return nil
			})
			if err == nil && !view.Identical {
				return exitcode.Silent(exitcode.CheckFailed)
			}
			return err
		},
	}
	cmd.Flags().BoolVar(&changedOnly, "changed", false, "only show fields that changed")
	return cmd
}

type chainView struct {
	Source       string                    `json:"source"`
	Certificates []chainEntry              `json:"certificates"`
	Verification *certificate.VerifyResult `json:"verification,omitempty"`
}

type chainEntry struct {
	Subject  string    `json:"subject"`
	Issuer   string    `json:"issuer"`
	NotAfter time.Time `json:"not_after"`
	SHA256   string    `json:"sha256"`
	IsCA     bool      `json:"is_ca"`
}

func newCertChainCmd(a *app) *cobra.Command {
	var verify bool
	var trustStore, hostname string
	cmd := &cobra.Command{
		Use:   "chain <file|id|host:port>",
		Short: "Show the certificate chain as a tree",
		Long: `Order the certificates of a bundle (or a stored certificate and its stored
issuers) from leaf to root and display them as a tree.`,
		Example: `  sslknife cert chain fullchain.pem
  sslknife cert chain api-prod --verify
  sslknife cert chain fullchain.pem --verify --truststore company-root.pem`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			certs, src, err := a.loadCerts(ctx, args[0])
			if err != nil {
				return err
			}
			var ordered []*x509.Certificate
			if strings.HasPrefix(src, "inventory:") {
				inv, _ := a.inventory(ctx)
				row, _, _ := inv.Certificate(ctx, strings.TrimPrefix(src, "inventory:"))
				rows, err := inv.Chain(ctx, row)
				if err != nil {
					return err
				}
				for _, r := range rows {
					c, err := x509.ParseCertificate(r.DER)
					if err != nil {
						return err
					}
					ordered = append(ordered, c)
				}
			} else {
				ordered = certificate.Order(certificate.FindLeaf(certs), certs)
			}
			view := chainView{Source: src}
			var labels []string
			for _, c := range ordered {
				fp := certificate.Fingerprint(c)
				view.Certificates = append(view.Certificates, chainEntry{
					Subject: c.Subject.String(), Issuer: c.Issuer.String(), NotAfter: c.NotAfter.UTC(), SHA256: fp.SHA256, IsCA: c.IsCA,
				})
				label := certificate.NewName(c.Subject).DisplayName() + a.out.Style.Dim("  expires "+c.NotAfter.UTC().Format(time.DateOnly))
				labels = append(labels, label)
			}
			if verify || trustStore != "" {
				vo := certificate.VerifyOptions{Intermediates: ordered[1:], Hostname: hostname}
				if trustStore != "" {
					data, err := a.readInput(trustStore)
					if err != nil {
						return err
					}
					if vo.Roots, _, err = certificate.LoadPool(data); err != nil {
						return err
					}
				}
				res := certificate.Verify(ordered[0], vo)
				view.Verification = &res
			}
			err = a.out.Emit(view, func(w io.Writer) error {
				if err := a.renderChainTree(w, labels); err != nil {
					return err
				}
				if top := ordered[len(ordered)-1]; !certificate.IsSelfSigned(top) {
					fmt.Fprintf(w, "%s chain ends at %q, whose issuer %q is not in the input\n",
						a.out.Style.Yellow("note:"), certificate.NewName(top.Subject).DisplayName(), top.Issuer.String())
				}
				if v := view.Verification; v != nil {
					if v.Trusted {
						fmt.Fprintf(w, "Trust: %s (%s)\n", a.out.Style.Level("VALID"), strings.Join(v.Chain, " → "))
					} else {
						fmt.Fprintf(w, "Trust: %s %s\n", a.out.Style.Level("INVALID"), v.Error)
					}
				}
				return nil
			})
			if err == nil && view.Verification != nil && !view.Verification.Trusted {
				return exitcode.Silent(exitcode.CheckFailed)
			}
			return err
		},
	}
	cmd.Flags().BoolVar(&verify, "verify", false, "validate against the system trust store")
	cmd.Flags().StringVar(&trustStore, "truststore", "", "validate against these roots instead of the system store")
	cmd.Flags().StringVar(&hostname, "hostname", "", "also check the leaf is valid for this hostname")
	return cmd
}

// fingerprintView is the output of `sslknife fingerprint`.
type fingerprintView struct {
	Source  string `json:"source"`
	Kind    string `json:"kind"`
	Subject string `json:"subject,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	SHA1    string `json:"sha1,omitempty"`
	SPKI    string `json:"spki_sha256"`
}

func newFingerprintCmd(a *app) *cobra.Command {
	var plain bool
	cmd := &cobra.Command{
		Use:     "fingerprint <file|->",
		Aliases: []string{"fp"},
		Short:   "Print SHA-256, SHA-1 and SPKI fingerprints",
		Long: `Print fingerprints of certificates, CSRs and keys.

SHA-256 identifies the certificate. SPKI SHA-256 identifies the public key
(stable across renewals with the same key, used for HPKP-style pinning).
SHA-1 is shown only as a legacy identifier for older tools; it is not a
recommended hash for any security purpose.`,
		Example: `  sslknife fingerprint cert.pem
  sslknife fingerprint server.key --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			views, err := a.fingerprints(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return a.out.Emit(views, func(w io.Writer) error {
				for i, v := range views {
					if i > 0 {
						fmt.Fprintln(w)
					}
					kv := output.NewKV(a.out.Style)
					format := func(h string) string {
						if plain {
							return h
						}
						return certificate.Colon(h)
					}
					kv.Add("Kind", v.Kind).Add("Subject", v.Subject)
					if v.SHA256 != "" {
						kv.Add("SHA256", format(v.SHA256))
						kv.Add("SHA1", format(v.SHA1)+a.out.Style.Dim("  (legacy)"))
					}
					kv.Add("SPKI SHA256", format(v.SPKI))
					if err := kv.Render(w); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&plain, "plain", false, "print lowercase hex without colons")
	return cmd
}

func (a *app) fingerprints(ctx context.Context, arg string) ([]fingerprintView, error) {
	src := displayName(arg)
	if arg == "-" || fileExists(arg) {
		data, err := a.readInput(arg)
		if err != nil {
			return nil, err
		}
		if certs, err := certificate.Parse(data); err == nil {
			var out []fingerprintView
			for _, c := range certs {
				fp := certificate.Fingerprint(c)
				out = append(out, fingerprintView{Source: src, Kind: "certificate", Subject: c.Subject.String(), SHA256: fp.SHA256, SHA1: fp.SHA1, SPKI: fp.SPKISHA256})
			}
			return out, nil
		}
		if csr, err := certificate.ParseCSR(data); err == nil {
			return []fingerprintView{{Source: src, Kind: "certificate request", Subject: csr.Subject.String(), SPKI: spkiHash(csr.RawSubjectPublicKeyInfo)}}, nil
		}
		if pub, kind, err := a.anyPublicKey(data, arg); err == nil {
			return []fingerprintView{{Source: src, Kind: kind, SPKI: pub.SPKISHA256}}, nil
		} else if !isNoKey(err) {
			return nil, err
		}
		return nil, exitcode.New(exitcode.Usage, "%s: no certificate, request or key found", src)
	}
	certs, src, err := a.loadCerts(ctx, arg)
	if err != nil {
		return nil, err
	}
	fp := certificate.Fingerprint(certs[0])
	return []fingerprintView{{Source: src, Kind: "certificate", Subject: certs[0].Subject.String(), SHA256: fp.SHA256, SHA1: fp.SHA1, SPKI: fp.SPKISHA256}}, nil
}

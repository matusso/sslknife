package cmd

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/matusso/sslknife/internal/certificate"
	"github.com/matusso/sslknife/internal/config"
	skcrypto "github.com/matusso/sslknife/internal/crypto"
	"github.com/matusso/sslknife/internal/exitcode"
	"github.com/matusso/sslknife/internal/inventory"
	"github.com/matusso/sslknife/internal/keys"
)

type subjectFlags struct {
	cn, org, ou, country, province, locality string
}

func (s subjectFlags) name() pkix.Name {
	n := pkix.Name{CommonName: s.cn}
	split := func(v string) []string {
		if v == "" {
			return nil
		}
		return []string{v}
	}
	n.Organization, n.OrganizationalUnit = split(s.org), split(s.ou)
	n.Country, n.Province, n.Locality = split(s.country), split(s.province), split(s.locality)
	return n
}

func addSubjectFlags(cmd *cobra.Command, s *subjectFlags) {
	f := cmd.Flags()
	f.StringVar(&s.cn, "cn", "", "subject common name")
	f.StringVar(&s.org, "org", "", "subject organization (O)")
	f.StringVar(&s.ou, "ou", "", "subject organizational unit (OU)")
	f.StringVar(&s.country, "country", "", "subject country (C), two letters")
	f.StringVar(&s.province, "province", "", "subject state or province (ST)")
	f.StringVar(&s.locality, "locality", "", "subject locality (L)")
}

type createOpts struct {
	subject      subjectFlags
	profile      string
	sans         []string
	algorithm    string
	keyRef       string
	validity     string
	pathLen      int
	caRef        string
	caKeyRef     string
	csrFile      string
	out          string
	keyOut       string
	encryptKey   bool
	passwordFile string
	force        bool
	store        bool
	name         string
	tags         []string
	interactive  bool
}

func defaultValidity(p certificate.Profile) string {
	switch p {
	case certificate.ProfileRootCA:
		return "3650d"
	case certificate.ProfileIntermediateCA:
		return "1825d"
	}
	return "365d"
}

func newCertCreateCmd(a *app) *cobra.Command {
	o := &createOpts{}
	cmd := &cobra.Command{
		Use:     "create",
		Aliases: []string{"new", "issue"},
		Short:   "Create a certificate: self-signed, CA-signed, root or intermediate CA",
		Long: `Create certificates for TLS servers and clients, code signing, S/MIME, and
root or intermediate CAs.

Without flags on a terminal, an interactive wizard asks for the details.
With --ca the certificate is signed by an existing CA (a stored certificate
with a linked private key, or files given with --ca and --ca-key); otherwise
it is self-signed. --csr signs an existing certificate request.

Serial numbers carry 128 random bits. Key usages follow the profile:
servers get digitalSignature (+keyEncipherment for RSA) and serverAuth;
CAs get keyCertSign/cRLSign with a critical basicConstraints.

Types: server, client, server-client, code-signing, email, root-ca, intermediate-ca`,
		Example: `  sslknife cert create                                   # wizard
  sslknife cert create --type root-ca --cn "Example Root CA" --algorithm ecdsa-p384 --store --name root
  sslknife cert create --type intermediate-ca --cn "Example Issuing CA" --ca root --path-len 0 --store --name issuing
  sslknife cert create --cn api.example.com --san www.api.example.com --ca issuing --validity 90d
  sslknife cert create --type client --cn alice --san alice@example.com --ca issuing -o alice.crt --key-out alice.key
  sslknife cert create --csr request.csr --ca issuing -o signed.crt`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if o.interactive || (cmd.Flags().NFlag() == 0 && a.prompt.Interactive()) {
				if err := a.certWizard(cmd.Context(), o); err != nil {
					return err
				}
			}
			return a.runCreate(cmd.Context(), o)
		},
	}
	addSubjectFlags(cmd, &o.subject)
	f := cmd.Flags()
	f.StringVarP(&o.profile, "type", "t", "server", "certificate type")
	f.StringSliceVar(&o.sans, "san", nil, "subject alternative name: DNS, IP, e-mail or URI (repeatable)")
	f.StringVarP(&o.algorithm, "algorithm", "a", string(keys.ECDSAP256), "algorithm for a new key")
	f.StringVar(&o.keyRef, "key", "", "use an existing private key (file or stored key)")
	f.StringVar(&o.validity, "validity", "", "validity period (default 365d; 1825d intermediate; 3650d root)")
	f.IntVar(&o.pathLen, "path-len", -1, "CA path length constraint (-1: none)")
	f.StringVar(&o.caRef, "ca", "", "issuer certificate (stored certificate or file)")
	f.StringVar(&o.caKeyRef, "ca-key", "", "issuer private key (file or stored key; default: key linked to --ca)")
	f.StringVar(&o.csrFile, "csr", "", "sign this certificate request instead of generating a key")
	f.StringVarP(&o.out, "out", "o", "", "certificate output file (default <cn>.crt unless --store)")
	f.StringVar(&o.keyOut, "key-out", "", "private key output file (default <cn>.key unless --store)")
	f.BoolVar(&o.encryptKey, "encrypt-key", false, "encrypt the private key file with a password")
	f.StringVar(&o.passwordFile, "password-file", "", "password file for --encrypt-key or encrypted input keys")
	f.BoolVar(&o.force, "force", false, "overwrite output files")
	f.BoolVar(&o.store, "store", false, "store the certificate and new key in the vault")
	f.StringVar(&o.name, "name", "", "friendly name in the vault")
	f.StringSliceVar(&o.tags, "tag", nil, "tags in the vault (repeatable)")
	f.BoolVarP(&o.interactive, "interactive", "i", false, "run the interactive wizard")
	_ = cmd.RegisterFlagCompletionFunc("type", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		var out []string
		for _, p := range certificate.Profiles {
			out = append(out, string(p)+"\t"+p.Label())
		}
		return out, cobra.ShellCompDirectiveNoFileComp
	})
	_ = cmd.RegisterFlagCompletionFunc("algorithm", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return algorithmList(), cobra.ShellCompDirectiveNoFileComp
	})
	_ = cmd.RegisterFlagCompletionFunc("ca", a.completeCerts)
	return cmd
}

func (a *app) certWizard(ctx context.Context, o *createOpts) error {
	p := a.prompt
	var labels []string
	for _, pr := range certificate.Profiles {
		labels = append(labels, pr.Label())
	}
	i, err := p.Choose("Certificate type:", labels, 0)
	if err != nil {
		return err
	}
	profile := certificate.Profiles[i]
	o.profile = string(profile)
	if o.subject.cn, err = p.Line("Common Name", o.subject.cn); err != nil {
		return err
	}
	if o.subject.org, err = p.Line("Organization (optional)", o.subject.org); err != nil {
		return err
	}
	if !profile.IsCA() {
		if o.sans, err = p.Lines("SANs (DNS names, IPs, e-mails, URIs; the CN is added for servers)"); err != nil {
			return err
		}
	}
	var algs []string
	for _, al := range keys.Algorithms {
		algs = append(algs, al.Label())
	}
	def := 0
	if profile.IsCA() {
		def = 1 // P-384 for CAs
	}
	if i, err = p.Choose("Algorithm:", algs, def); err != nil {
		return err
	}
	o.algorithm = string(keys.Algorithms[i])
	if o.validity, err = p.Line("Validity", defaultValidity(profile)); err != nil {
		return err
	}
	if profile != certificate.ProfileRootCA {
		prompt := "Issuer (stored CA name/ID or file; empty = self-signed)"
		if profile == certificate.ProfileIntermediateCA {
			prompt = "Issuer (stored CA name/ID or file)"
		}
		if o.caRef, err = p.Line(prompt, o.caRef); err != nil {
			return err
		}
	}
	if profile.IsCA() {
		pl, err := p.Line("Path length constraint (empty = none)", "")
		if err != nil {
			return err
		}
		if pl != "" {
			if _, err := fmt.Sscanf(pl, "%d", &o.pathLen); err != nil {
				return usagef("invalid path length %q", pl)
			}
		}
	}
	if o.store, err = p.Confirm("Store certificate and key in the vault?", true); err != nil {
		return err
	}
	if o.store {
		if o.name, err = p.Line("Friendly name (optional)", ""); err != nil {
			return err
		}
	}
	writeFiles, err := p.Confirm("Also write PEM files to the current directory?", !o.store)
	if err != nil {
		return err
	}
	if writeFiles {
		base := sanitizeFileName(o.subject.cn)
		o.out, o.keyOut = base+".crt", base+".key"
	}
	return nil
}

// loadSigner resolves a private key from a file or the vault.
func (a *app) loadSigner(ctx context.Context, ref, passwordFile string) (crypto.Signer, error) {
	if ref == "-" || fileExists(ref) {
		data, err := a.readInput(ref)
		if err != nil {
			return nil, err
		}
		pk, err := keys.ParsePrivateKey(data, a.keyPassword(passwordFile, displayName(ref)))
		if err != nil {
			if isNoKey(err) {
				return nil, exitcode.New(exitcode.Usage, "%s: no private key found", displayName(ref))
			}
			return nil, exitcode.With(exitcode.Auth, err)
		}
		s, ok := pk.Key.(crypto.Signer)
		if !ok {
			return nil, exitcode.New(exitcode.Unsupported, "%s: key type %T cannot sign", ref, pk.Key)
		}
		return s, nil
	}
	inv, k, err := a.getKey(ctx, ref)
	if err != nil {
		return nil, err
	}
	priv, err := inv.PrivateKey(ctx, k)
	if err != nil {
		return nil, err
	}
	s, ok := priv.(crypto.Signer)
	if !ok {
		return nil, exitcode.New(exitcode.Unsupported, "stored key %s cannot sign", k.ID)
	}
	return s, nil
}

// loadIssuer resolves the CA certificate and key.
func (a *app) loadIssuer(ctx context.Context, caRef, caKeyRef, passwordFile string) (*x509.Certificate, crypto.Signer, error) {
	certs, src, err := a.loadCerts(ctx, caRef)
	if err != nil {
		return nil, nil, err
	}
	ca := certs[0]
	if caKeyRef != "" {
		key, err := a.loadSigner(ctx, caKeyRef, passwordFile)
		return ca, key, err
	}
	if strings.HasPrefix(src, "inventory:") {
		inv, _ := a.inventory(ctx)
		row, err := inv.DB.GetCertificate(ctx, strings.TrimPrefix(src, "inventory:"))
		if err != nil {
			return nil, nil, err
		}
		if row.KeyID == "" {
			return nil, nil, exitcode.New(exitcode.NotFound, "no private key is stored for CA %s; pass --ca-key", row.ID)
		}
		key, err := a.loadSigner(ctx, row.KeyID, passwordFile)
		return ca, key, err
	}
	// A PEM file may carry the key next to the certificate.
	if key, err := a.loadSigner(ctx, caRef, passwordFile); err == nil {
		return ca, key, nil
	}
	return nil, nil, usagef("--ca-key is required when --ca is a file without a private key")
}

type createView struct {
	Certificate certificate.Info `json:"certificate"`
	CertFile    string           `json:"certificate_file,omitempty"`
	KeyFile     string           `json:"key_file,omitempty"`
	StoredID    string           `json:"stored_id,omitempty"`
	KeyID       string           `json:"stored_key_id,omitempty"`
}

func (a *app) runCreate(ctx context.Context, o *createOpts) error {
	profile, err := certificate.ParseProfile(o.profile)
	if err != nil {
		return usageError{err}
	}
	if o.validity == "" {
		o.validity = defaultValidity(profile)
	}
	validity, err := config.ParseDuration(o.validity)
	if err != nil {
		return usageError{err}
	}
	req := certificate.Request{Profile: profile, Subject: o.subject.name(), SANs: o.sans, Validity: validity, PathLen: o.pathLen}
	var newKey crypto.Signer
	switch {
	case o.csrFile != "":
		data, err := a.readInput(o.csrFile)
		if err != nil {
			return err
		}
		csr, err := certificate.ParseCSR(data)
		if err != nil {
			return exitcode.With(exitcode.Usage, err)
		}
		fromCSR := certificate.RequestFromCSR(csr, profile)
		fromCSR.Validity, fromCSR.PathLen = validity, o.pathLen
		if o.subject.cn != "" {
			fromCSR.Subject = req.Subject
		}
		fromCSR.SANs = append(fromCSR.SANs, o.sans...)
		req = fromCSR
	case o.keyRef != "":
		if req.Key, err = a.loadSigner(ctx, o.keyRef, o.passwordFile); err != nil {
			return err
		}
	default:
		algo, err := keys.ParseAlgorithm(o.algorithm)
		if err != nil {
			return usageError{err}
		}
		if newKey, err = keys.Generate(algo); err != nil {
			return err
		}
		req.Key = newKey
	}
	if req.Subject.CommonName == "" && len(req.SANs) == 0 {
		return usagef("give at least --cn or --san")
	}
	if o.caRef != "" {
		if profile == certificate.ProfileRootCA {
			return usagef("a root CA is self-signed; drop --ca or use --type intermediate-ca")
		}
		if req.Issuer, req.IssuerKey, err = a.loadIssuer(ctx, o.caRef, o.caKeyRef, o.passwordFile); err != nil {
			return err
		}
	} else if req.Key == nil {
		return usagef("signing a CSR requires --ca")
	}
	cert, err := certificate.Create(req)
	if err != nil {
		return exitcode.With(exitcode.Usage, err)
	}

	base := sanitizeFileName(firstNonEmpty(req.Subject.CommonName, firstOf(req.SANs), "certificate"))
	if !o.store && o.out == "" {
		o.out = base + ".crt"
	}
	if newKey != nil && !o.store && o.keyOut == "" {
		o.keyOut = base + ".key"
	}
	view := createView{Certificate: certificate.Describe(cert, a.describeOpts(false))}
	chain := []*x509.Certificate{cert}
	if o.out != "" {
		if err := writeNewFile(o.out, certificate.EncodePEM(chain...), 0o644, o.force); err != nil {
			return err
		}
		view.CertFile = o.out
	}
	if newKey != nil && o.keyOut != "" {
		var pw []byte
		if o.encryptKey {
			if pw, err = a.newSecretPassword(o.passwordFile); err != nil {
				return err
			}
			defer skcrypto.Zero(pw)
		}
		data, err := keys.MarshalPrivateKeyPEM(newKey, pw)
		if err != nil {
			return err
		}
		defer skcrypto.Zero(data)
		if err := writeNewFile(o.keyOut, data, 0o600, o.force); err != nil {
			return err
		}
		view.KeyFile = o.keyOut
	}
	if o.store {
		inv, err := a.inventory(ctx)
		if err != nil {
			return err
		}
		opts := inventory.ImportOptions{Name: o.name, Tags: o.tags, Source: "created"}
		if newKey != nil {
			kr, err := inv.ImportPrivateKey(ctx, newKey, inventory.ImportOptions{Name: keyNameFor(o.name), Tags: o.tags, Source: "created"})
			if err != nil {
				return err
			}
			view.KeyID = kr.Key.ID
		}
		r, err := inv.ImportCertificate(ctx, cert, opts)
		if err != nil {
			return err
		}
		view.StoredID = r.Cert.ID
	}
	return a.out.Emit(view, func(w io.Writer) error {
		st := a.out.Style
		info := view.Certificate
		issuer := "self-signed"
		if !info.SelfSigned {
			issuer = "signed by " + info.Issuer.DisplayName()
		}
		fmt.Fprintf(w, "Created %s certificate for %s (%s)\n", profile.Label(), st.Bold(info.Subject.DisplayName()), issuer)
		fmt.Fprintf(w, "  %s %s, valid until %s\n", st.Dim("key"), info.PublicKey.Description, info.Validity.NotAfter.Format(time.DateOnly))
		if s := info.SANs.All(); len(s) > 0 {
			fmt.Fprintf(w, "  %s %s\n", st.Dim("SANs"), strings.Join(s, ", "))
		}
		if view.CertFile != "" {
			fmt.Fprintf(w, "  %s %s\n", st.Dim("certificate"), view.CertFile)
		}
		if view.KeyFile != "" {
			fmt.Fprintf(w, "  %s %s (mode 0600)\n", st.Dim("private key"), view.KeyFile)
		}
		if view.StoredID != "" {
			fmt.Fprintf(w, "  %s %s\n", st.Dim("stored as"), view.StoredID)
		}
		return nil
	})
}

func keyNameFor(certName string) string {
	if certName == "" {
		return ""
	}
	return certName + "-key"
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func firstOf(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

func newCertCSRCmd(a *app) *cobra.Command {
	var s subjectFlags
	var sans []string
	var algorithm, keyRef, out, keyOut, passwordFile string
	var encryptKey, force, store bool
	cmd := &cobra.Command{
		Use:   "csr",
		Short: "Create a certificate signing request (PKCS#10)",
		Example: `  sslknife cert csr --cn api.example.com --san www.api.example.com
  sslknife cert csr --cn api.example.com --key server.key -o api.csr
  sslknife cert csr --cn api.example.com --key api-prod-key --store`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if s.cn == "" && len(sans) == 0 {
				return usagef("give at least --cn or --san")
			}
			var key crypto.Signer
			var generated bool
			var err error
			if keyRef != "" {
				if key, err = a.loadSigner(ctx, keyRef, passwordFile); err != nil {
					return err
				}
			} else {
				algo, err := keys.ParseAlgorithm(algorithm)
				if err != nil {
					return usageError{err}
				}
				if key, err = keys.Generate(algo); err != nil {
					return err
				}
				generated = true
			}
			csr, err := certificate.CreateCSR(s.name(), sans, key)
			if err != nil {
				return exitcode.With(exitcode.Usage, err)
			}
			base := sanitizeFileName(firstNonEmpty(s.cn, firstOf(sans)))
			if out == "" {
				out = base + ".csr"
			}
			if err := writeNewFile(out, certificate.EncodeCSRPEM(csr), 0o644, force); err != nil {
				return err
			}
			a.out.Infof("Certificate request written to %s", out)
			if generated {
				if store {
					inv, err := a.inventory(ctx)
					if err != nil {
						return err
					}
					kr, err := inv.ImportPrivateKey(ctx, key, inventory.ImportOptions{Source: "csr"})
					if err != nil {
						return err
					}
					a.out.Infof("Private key stored in vault as %s", kr.Key.ID)
				}
				if keyOut == "" && !store {
					keyOut = base + ".key"
				}
				if keyOut != "" {
					var pw []byte
					if encryptKey {
						if pw, err = a.newSecretPassword(passwordFile); err != nil {
							return err
						}
						defer skcrypto.Zero(pw)
					}
					data, err := keys.MarshalPrivateKeyPEM(key, pw)
					if err != nil {
						return err
					}
					defer skcrypto.Zero(data)
					if err := writeNewFile(keyOut, data, 0o600, force); err != nil {
						return err
					}
					a.out.Infof("Private key written to %s (mode 0600)", keyOut)
				}
			}
			return nil
		},
	}
	addSubjectFlags(cmd, &s)
	f := cmd.Flags()
	f.StringSliceVar(&sans, "san", nil, "subject alternative name (repeatable)")
	f.StringVarP(&algorithm, "algorithm", "a", string(keys.ECDSAP256), "algorithm for a new key")
	f.StringVar(&keyRef, "key", "", "existing private key (file or stored key)")
	f.StringVarP(&out, "out", "o", "", "CSR output file (default <cn>.csr)")
	f.StringVar(&keyOut, "key-out", "", "new key output file (default <cn>.key unless --store)")
	f.BoolVar(&encryptKey, "encrypt-key", false, "encrypt the new key file")
	f.StringVar(&passwordFile, "password-file", "", "password file")
	f.BoolVar(&store, "store", false, "store the new key in the vault")
	f.BoolVar(&force, "force", false, "overwrite output files")
	return cmd
}

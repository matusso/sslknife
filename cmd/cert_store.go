package cmd

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/matusso/sslknife/internal/certificate"
	"github.com/matusso/sslknife/internal/config"
	"github.com/matusso/sslknife/internal/database"
	"github.com/matusso/sslknife/internal/exitcode"
	"github.com/matusso/sslknife/internal/inventory"
	"github.com/matusso/sslknife/internal/keys"
	"github.com/matusso/sslknife/internal/output"
	"github.com/matusso/sslknife/internal/prompt"
)

type importView struct {
	Certificates []importedCert `json:"certificates"`
	Keys         []keyView      `json:"keys,omitempty"`
}

type importedCert struct {
	Created bool `json:"created"`
	certSummary
}

func newCertImportCmd(a *app) *cobra.Command {
	var name, comment, passwordFile string
	var tags []string
	var yes, leafOnly, withKeys, chainAll bool
	cmd := &cobra.Command{
		Use:   "import <file|-|host:port>",
		Short: "Store certificates in the inventory, from files or remote servers",
		Long: `Import every certificate in a file (PEM, DER or PKCS#7) into the vault.
Duplicates are detected by SHA-256 fingerprint. Issuers already stored are
linked automatically, as are private keys with the same public key.

If the file also contains private keys you are asked whether to store them
(or pass --with-keys --yes).

With host:port (or a URL) SSLKnife connects, shows the chain the server
presents and asks which certificates to store; --chain stores all of them,
otherwise non-interactive runs store the leaf only.`,
		Example: `  sslknife cert import fullchain.pem --name api-prod --tag production
  sslknife cert import api.example.com:443 --chain
  sslknife cert import smtp://mail.example.com --tag mail
  sslknife cert import bundle.p7b --leaf
  cat cert.pem | sslknife cert import - --tag kubernetes`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			var data []byte
			var certs []*x509.Certificate
			source := "file:" + displayName(args[0])
			if looksRemote(args[0]) {
				remote, err := a.fetchRemoteChain(ctx, args[0])
				if err != nil {
					return err
				}
				if certs, err = a.selectRemote(remote, chainAll, yes); err != nil {
					return err
				}
				source = "tls:" + args[0]
			} else {
				var err error
				if data, err = a.readInput(args[0]); err != nil {
					return err
				}
				if certs, err = certificate.Parse(data); err != nil {
					return exitcode.New(exitcode.Usage, "%s: no certificate found", displayName(args[0]))
				}
			}
			if leafOnly {
				certs = []*x509.Certificate{certificate.FindLeaf(certs)}
			}
			if len(certs) == 0 {
				return exitcode.New(exitcode.Error, "nothing selected")
			}
			inv, err := a.inventory(ctx)
			if err != nil {
				return err
			}
			opts := inventory.ImportOptions{Name: name, Tags: tags, Comment: comment, Source: source}
			// Import the leaf first so --name applies to it.
			leaf := certificate.FindLeaf(certs)
			ordered := append([]*x509.Certificate{leaf}, removeCert(certs, leaf)...)
			res, err := inv.ImportCertificates(ctx, ordered, opts)
			if err != nil {
				return err
			}
			view := importView{}
			for _, r := range res {
				view.Certificates = append(view.Certificates, importedCert{Created: r.Created, certSummary: a.summarize(r.Cert)})
			}
			if data != nil && certificate.IsPEM(data) {
				privs, err := keys.ParsePrivateKeys(data, a.keyPassword(passwordFile, displayName(args[0])))
				switch {
				case err == nil && len(privs) > 0:
					// Ask interactively; --with-keys makes a refusal an error, and
					// --with-keys --yes stores without asking.
					store := false
					if withKeys || a.prompt.Interactive() {
						err := a.confirmPrivateImport(len(privs), withKeys && yes)
						if err == nil {
							store = true
						} else if withKeys {
							return err
						}
					}
					if store {
						for _, pk := range privs {
							kr, err := inv.ImportPrivateKey(ctx, pk.Key, inventory.ImportOptions{Tags: tags, Source: opts.Source})
							if err != nil {
								return err
							}
							view.Keys = append(view.Keys, toKeyView(kr.Key))
						}
					} else {
						a.out.Warnf("the file contains %d private key(s) that were not stored (use --with-keys)", len(privs))
					}
				case err != nil && !isNoKey(err):
					a.out.Warnf("private key in file not imported: %v", err)
				}
			}
			return a.out.Emit(view, func(w io.Writer) error {
				for _, c := range view.Certificates {
					state := a.out.Style.Green("stored")
					if !c.Created {
						state = a.out.Style.Dim("exists")
					}
					label := c.CommonName
					if label == "" {
						label = c.Subject
					}
					fmt.Fprintf(w, "%s  %s  %s  expires %s\n", state, c.ID, label, c.NotAfter.Format(time.DateOnly))
				}
				for _, k := range view.Keys {
					fmt.Fprintf(w, "%s  %s  %s private key\n", a.out.Style.Green("stored"), k.ID, k.Description)
				}
				return nil
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&name, "name", "", "friendly name for the leaf certificate")
	f.StringSliceVar(&tags, "tag", nil, "tags (repeatable)")
	f.StringVar(&comment, "comment", "", "free-text comment")
	f.BoolVar(&leafOnly, "leaf", false, "import only the end-entity certificate")
	f.BoolVar(&chainAll, "chain", false, "store the whole chain presented by a remote server")
	f.BoolVar(&withKeys, "with-keys", false, "also store private keys found in the file")
	f.StringVar(&passwordFile, "password-file", "", "password for encrypted keys in the file")
	f.BoolVarP(&yes, "yes", "y", false, "do not ask for confirmation")
	return cmd
}

// selectRemote asks which certificates of a presented chain to store.
func (a *app) selectRemote(certs []*x509.Certificate, all, yes bool) ([]*x509.Certificate, error) {
	if all {
		return certs, nil
	}
	if yes || !a.prompt.Interactive() {
		return certs[:1], nil
	}
	fmt.Fprintln(a.stderr, "The server presented:")
	for i, c := range certs {
		fmt.Fprintf(a.stderr, "  %d) %s  (issuer %s, expires %s)\n", i+1, certificate.NewName(c.Subject).DisplayName(),
			certificate.NewName(c.Issuer).DisplayName(), c.NotAfter.UTC().Format(time.DateOnly))
	}
	ans, err := a.prompt.Line("Store which? (all, leaf, none, or numbers like 1,2)", "all")
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(ans) {
	case "all", "a":
		return certs, nil
	case "leaf", "l":
		return certs[:1], nil
	case "none", "n":
		return nil, exitcode.New(exitcode.Error, "nothing selected")
	}
	var out []*x509.Certificate
	for _, f := range strings.FieldsFunc(ans, func(r rune) bool { return r == ',' || r == ' ' }) {
		var n int
		if _, err := fmt.Sscanf(f, "%d", &n); err != nil || n < 1 || n > len(certs) {
			return nil, usagef("invalid selection %q", f)
		}
		out = append(out, certs[n-1])
	}
	return out, nil
}

func removeCert(certs []*x509.Certificate, c *x509.Certificate) []*x509.Certificate {
	var out []*x509.Certificate
	for _, x := range certs {
		if x != c {
			out = append(out, x)
		}
	}
	return out
}

func newCertListCmd(a *app) *cobra.Command {
	var query string
	var tags []string
	var caOnly bool
	cmd := &cobra.Command{
		Use:     "list [query]",
		Aliases: []string{"ls"},
		Short:   "List stored certificates",
		Long: `List stored certificates, soonest expiry first. An optional query uses the
search language (see 'sslknife search --help').`,
		Example: `  sslknife cert list
  sslknife cert list 'issuer:DigiCert expires:<90d'
  sslknife cert list --tag production --json`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			inv, err := a.inventory(cmd.Context())
			if err != nil {
				return err
			}
			q := query
			if len(args) == 1 {
				q = strings.TrimSpace(q + " " + args[0])
			}
			for _, t := range tags {
				q += " tag:" + t
			}
			if caOnly {
				q += " type:ca"
			}
			certs, err := inv.ListCertificates(cmd.Context(), inventory.ListFilter{Query: q})
			if err != nil {
				return usageError{err}
			}
			views := a.summarizeAll(certs)
			return a.out.Emit(views, func(w io.Writer) error {
				if len(views) == 0 {
					fmt.Fprintln(w, "No certificates found.")
					return nil
				}
				return a.renderCertTable(w, views)
			})
		},
	}
	cmd.Flags().StringVar(&query, "filter", "", "search query")
	cmd.Flags().StringSliceVar(&tags, "tag", nil, "only certificates with this tag")
	cmd.Flags().BoolVar(&caOnly, "ca", false, "only CA certificates")
	return cmd
}

type showView struct {
	certSummary
	Details  certificate.Info `json:"details"`
	Chain    []certSummary    `json:"chain"`
	Children []certSummary    `json:"issued,omitempty"`
	Notes    []noteView       `json:"notes,omitempty"`
}

type noteView struct {
	ID        string    `json:"id"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

func newCertShowCmd(a *app) *cobra.Command {
	var withPEM bool
	cmd := &cobra.Command{
		Use:               "show <id|name|fingerprint>",
		Short:             "Show a stored certificate with its chain, key and notes",
		Example:           "  sslknife cert show api-prod\n  sslknife cert show 3f2a --yaml",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: a.completeCerts,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			inv, err := a.inventory(ctx)
			if err != nil {
				return err
			}
			row, c, err := inv.Certificate(ctx, args[0])
			if err != nil {
				return mapLookupErr(err, args[0])
			}
			chain, err := inv.Chain(ctx, row)
			if err != nil {
				return err
			}
			children, err := inv.Children(ctx, row)
			if err != nil {
				return err
			}
			notes, err := inv.DB.Notes(ctx, "cert", row.ID)
			if err != nil {
				return err
			}
			v := showView{certSummary: a.summarize(row), Details: certificate.Describe(c, a.describeOpts(withPEM)),
				Chain: a.summarizeAll(chain), Children: a.summarizeAll(children)}
			for _, n := range notes {
				v.Notes = append(v.Notes, noteView{ID: n.ID, Body: n.Body, CreatedAt: n.CreatedAt})
			}
			return a.out.Emit(v, func(w io.Writer) error {
				st := a.out.Style
				kv := output.NewKV(st)
				kv.Add("ID", row.ID).Add("Name", row.Name).Add("Status", st.Level(v.Status)).
					Add("Tags", strings.Join(row.Tags, ", ")).Add("Source", row.Source).
					Add("Imported", row.ImportedAt.Format(time.RFC3339)).Add("Comment", row.Comment)
				if row.KeyID != "" {
					kv.Add("Private key", row.KeyID)
				}
				if err := kv.Render(w); err != nil {
					return err
				}
				fmt.Fprintln(w)
				if len(chain) > 1 || !row.SelfSigned {
					fmt.Fprintln(w, st.Bold("Chain"))
					var labels []string
					for _, c := range chain {
						labels = append(labels, c.ID[:8]+"  "+certificate.Name{DN: c.Subject, CommonName: c.SubjectCN}.DisplayName())
					}
					if top := chain[len(chain)-1]; !top.SelfSigned {
						labels = append(labels, st.Dim(top.Issuer+"  (not stored)"))
					}
					if err := a.renderChainTree(w, labels); err != nil {
						return err
					}
					fmt.Fprintln(w)
				}
				if len(children) > 0 {
					fmt.Fprintln(w, st.Bold(fmt.Sprintf("Issued certificates (%d)", len(children))))
					if err := a.renderCertTable(w, v.Children); err != nil {
						return err
					}
					fmt.Fprintln(w)
				}
				if err := a.renderInfo(w, v.Details); err != nil {
					return err
				}
				if len(notes) > 0 {
					fmt.Fprintln(w)
					fmt.Fprintln(w, st.Bold("Notes"))
					for _, n := range notes {
						fmt.Fprintf(w, "  %s  %s\n", st.Dim(n.CreatedAt.Format(time.DateOnly)), n.Body)
					}
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&withPEM, "pem", false, "include the PEM encoding")
	return cmd
}

func newCertExportCmd(a *app) *cobra.Command {
	var out string
	var chain, der, force bool
	cmd := &cobra.Command{
		Use:   "export <id|name>",
		Short: "Write a stored certificate (optionally with its chain) as PEM or DER",
		Example: `  sslknife cert export api-prod > api.pem
  sslknife cert export api-prod --chain -o fullchain.pem`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: a.completeCerts,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			inv, err := a.inventory(ctx)
			if err != nil {
				return err
			}
			row, c, err := inv.Certificate(ctx, args[0])
			if err != nil {
				return mapLookupErr(err, args[0])
			}
			certs := []*x509.Certificate{c}
			if chain {
				rows, err := inv.Chain(ctx, row)
				if err != nil {
					return err
				}
				for _, r := range rows[1:] {
					ic, err := x509.ParseCertificate(r.DER)
					if err != nil {
						return err
					}
					certs = append(certs, ic)
				}
			}
			var data []byte
			if der {
				if len(certs) > 1 {
					return exitcode.New(exitcode.Unsupported, "DER holds a single certificate; use PEM to export a chain")
				}
				data = c.Raw
			} else {
				data = certificate.EncodePEM(certs...)
			}
			if out != "" {
				return writeNewFile(out, data, 0o644, force)
			}
			_, err = a.stdout.Write(data)
			return err
		},
	}
	cmd.Flags().StringVarP(&out, "out", "o", "", "output file (default stdout)")
	cmd.Flags().BoolVar(&chain, "chain", false, "include stored issuer certificates")
	cmd.Flags().BoolVar(&der, "der", false, "write DER instead of PEM")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite the output file")
	return cmd
}

func newCertDeleteCmd(a *app) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:               "delete <id|name>...",
		Aliases:           []string{"rm"},
		Short:             "Delete stored certificates",
		Args:              cobra.MinimumNArgs(1),
		ValidArgsFunction: a.completeCerts,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			inv, err := a.inventory(ctx)
			if err != nil {
				return err
			}
			var rows []*database.Certificate
			for _, ref := range args {
				row, err := inv.DB.GetCertificate(ctx, ref)
				if err != nil {
					return mapLookupErr(err, ref)
				}
				rows = append(rows, row)
			}
			q := fmt.Sprintf("Delete %d certificate(s)?", len(rows))
			if len(rows) == 1 {
				q = fmt.Sprintf("Delete certificate %s (%s)?", rows[0].ID, rows[0].SubjectCN)
			}
			if err := a.confirm(q, yes); err != nil {
				return err
			}
			for _, r := range rows {
				if err := inv.DB.DeleteCertificate(ctx, r.ID); err != nil {
					return err
				}
				a.out.Infof("Deleted %s", r.ID)
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask for confirmation")
	return cmd
}

func newCertTagCmd(a *app, add bool) *cobra.Command {
	use, short := "tag <id|name> <tag>...", "Add tags to a stored certificate"
	if !add {
		use, short = "untag <id|name> <tag>...", "Remove tags from a stored certificate"
	}
	return &cobra.Command{
		Use:               use,
		Short:             short,
		Example:           "  sslknife cert tag api-prod production kubernetes",
		Args:              cobra.MinimumNArgs(2),
		ValidArgsFunction: a.completeCerts,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			inv, err := a.inventory(ctx)
			if err != nil {
				return err
			}
			id, err := inv.DB.ResolveCertificate(ctx, args[0])
			if err != nil {
				return mapLookupErr(err, args[0])
			}
			if add {
				err = inv.DB.AddTags(ctx, "cert", id, args[1:])
			} else {
				err = inv.DB.RemoveTags(ctx, "cert", id, args[1:])
			}
			if err != nil {
				return usageError{err}
			}
			return nil
		},
	}
}

func newCertNoteCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:               "note <id|name> <text>",
		Short:             "Attach a note to a stored certificate",
		Example:           `  sslknife cert note api-prod "renewed by ops, ticket OPS-123"`,
		Args:              cobra.MinimumNArgs(2),
		ValidArgsFunction: a.completeCerts,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			inv, err := a.inventory(ctx)
			if err != nil {
				return err
			}
			id, err := inv.DB.ResolveCertificate(ctx, args[0])
			if err != nil {
				return mapLookupErr(err, args[0])
			}
			_, err = inv.DB.AddNote(ctx, "cert", id, strings.Join(args[1:], " "))
			return err
		},
	}
}

func newCertRenameCmd(a *app) *cobra.Command {
	var comment string
	cmd := &cobra.Command{
		Use:               "rename <id|name> <new-name>",
		Short:             "Set a stored certificate's friendly name (and optionally comment)",
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: a.completeCerts,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			inv, err := a.inventory(ctx)
			if err != nil {
				return err
			}
			id, err := inv.DB.ResolveCertificate(ctx, args[0])
			if err != nil {
				return mapLookupErr(err, args[0])
			}
			var cp *string
			if cmd.Flags().Changed("comment") {
				cp = &comment
			}
			return inv.DB.UpdateCertificateMeta(ctx, id, &args[1], cp)
		},
	}
	cmd.Flags().StringVar(&comment, "comment", "", "also set the comment")
	return cmd
}

func newCertExpiringCmd(a *app) *cobra.Command {
	var within string
	var includeExpired bool
	cmd := &cobra.Command{
		Use:   "expiring",
		Short: "List stored certificates that expire soon",
		Long: `List stored certificates expiring within a period (default: expiry.warning_days
from the config, 30 days). Exit status is 5 when any are found, so the
command can drive monitoring.`,
		Example: `  sslknife cert expiring
  sslknife cert expiring --within 90d --json
  sslknife cert expiring --expired`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d := time.Duration(a.cfg.Expiry.WarningDays) * 24 * time.Hour
			if within != "" {
				var err error
				if d, err = config.ParseDuration(within); err != nil {
					return usageError{err}
				}
			}
			inv, err := a.inventory(cmd.Context())
			if err != nil {
				return err
			}
			certs, err := inv.Expiring(cmd.Context(), d, includeExpired)
			if err != nil {
				return err
			}
			views := a.summarizeAll(certs)
			err = a.out.Emit(views, func(w io.Writer) error {
				if len(views) == 0 {
					fmt.Fprintf(w, "No certificates expire within %s.\n", formatDays(d))
					return nil
				}
				return a.renderCertTable(w, views)
			})
			if err == nil && len(views) > 0 {
				return exitcode.Silent(exitcode.CheckFailed)
			}
			return err
		},
	}
	cmd.Flags().StringVar(&within, "within", "", "period, e.g. 30d, 12w, 1y")
	cmd.Flags().BoolVar(&includeExpired, "expired", false, "include certificates that have already expired")
	return cmd
}

func formatDays(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", days)
}

// completeCerts offers stored certificate names and IDs.
func (a *app) completeCerts(cmd *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 && cmd.Name() != "delete" {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return a.completeObjects(cmd, func(inv *inventory.Service) []string {
		certs, err := inv.DB.QueryCertificates(cmd.Context(), "", nil, "")
		if err != nil {
			return nil
		}
		var out []string
		for _, c := range certs {
			label := c.SubjectCN + " (expires " + c.NotAfter.Format(time.DateOnly) + ")"
			if c.Name != "" {
				out = append(out, c.Name+"\t"+label)
			}
			out = append(out, c.ID+"\t"+label)
		}
		return out
	})
}

// completeKeys offers stored key names and IDs.
func (a *app) completeKeys(cmd *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return a.completeObjects(cmd, func(inv *inventory.Service) []string {
		ks, err := inv.DB.QueryKeys(cmd.Context(), "", nil)
		if err != nil {
			return nil
		}
		var out []string
		for _, k := range ks {
			if k.Name != "" {
				out = append(out, k.Name+"\t"+k.Description)
			}
			out = append(out, k.ID+"\t"+k.Description)
		}
		return out
	})
}

// completeObjects only runs when the vault can be unlocked without a
// prompt (environment or keychain); completion must never block on input.
func (a *app) completeObjects(cmd *cobra.Command, list func(*inventory.Service) []string) ([]string, cobra.ShellCompDirective) {
	if a.cfg == nil {
		if err := a.setup(cmd); err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
	}
	a.prompt = prompt.New(strings.NewReader(""), io.Discard)
	inv, err := a.inventory(cmd.Context())
	if err != nil {
		if errors.Is(err, database.ErrIntegrity) {
			return nil, cobra.ShellCompDirectiveError
		}
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return list(inv), cobra.ShellCompDirectiveNoFileComp
}

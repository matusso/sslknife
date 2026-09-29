package cmd

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

type searchView struct {
	Query        string        `json:"query"`
	Certificates []certSummary `json:"certificates"`
	Keys         []keyView     `json:"keys"`
	SSHKeys      []sshKeyView  `json:"ssh_keys"`
}

func newSearchCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "search <query>",
		Short: "Search the inventory",
		Long: `Search stored certificates and keys. All terms must match.

  example.com            substring of name, CN, subject, issuer or any SAN
  name:api cn:api        friendly name / subject common name
  subject:"Example Inc"  subject DN substring (quote values with spaces)
  issuer:DigiCert        issuer DN substring
  san:example.com        SAN substring
  serial:0a1b            serial number
  fingerprint:ab12cd     SHA-256 or SHA-1 fingerprint prefix
  spki:ab12              public key (SPKI SHA-256) prefix
  algorithm:rsa          key algorithm, e.g. rsa, rsa4096, p256, ed25519
  tag:production         tag
  type:cert|key|ssh|ca|leaf|root|private|public
  status:expired|expiring|valid|future
  expires:<30d           expires within 30 days (also >90d, <=2027-01-01, =2026-12-31)
  source:created         where the object came from
  -tag:legacy            prefix any term with - to negate it`,
		Example: `  sslknife search 'expires:<30d'
  sslknife search 'issuer:"Let'"'"'s Encrypt" -tag:staging'
  sslknife search 'type:key algorithm:rsa' --json`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			inv, err := a.inventory(cmd.Context())
			if err != nil {
				return err
			}
			q := args[0]
			for _, s := range args[1:] {
				q += " " + s
			}
			res, err := inv.Search(cmd.Context(), q)
			if err != nil {
				return usageError{err}
			}
			view := searchView{Query: q, Certificates: a.summarizeAll(res.Certificates), Keys: []keyView{}, SSHKeys: []sshKeyView{}}
			for _, k := range res.Keys {
				view.Keys = append(view.Keys, toKeyView(k))
			}
			for _, k := range res.SSHKeys {
				view.SSHKeys = append(view.SSHKeys, toSSHView(k))
			}
			return a.out.Emit(view, func(w io.Writer) error {
				if len(view.Certificates)+len(view.Keys)+len(view.SSHKeys) == 0 {
					fmt.Fprintln(w, "No matches.")
					return nil
				}
				if len(view.Certificates) > 0 {
					fmt.Fprintln(w, a.out.Style.Bold(fmt.Sprintf("Certificates (%d)", len(view.Certificates))))
					if err := a.renderCertTable(w, view.Certificates); err != nil {
						return err
					}
				}
				if len(view.Keys) > 0 {
					if len(view.Certificates) > 0 {
						fmt.Fprintln(w)
					}
					fmt.Fprintln(w, a.out.Style.Bold(fmt.Sprintf("Keys (%d)", len(view.Keys))))
					if err := a.renderKeyTable(w, view.Keys); err != nil {
						return err
					}
				}
				if len(view.SSHKeys) > 0 {
					fmt.Fprintln(w)
					fmt.Fprintln(w, a.out.Style.Bold(fmt.Sprintf("SSH keys (%d)", len(view.SSHKeys))))
					return a.renderSSHTable(w, view.SSHKeys)
				}
				return nil
			})
		},
	}
}

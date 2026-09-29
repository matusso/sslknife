package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/matusso/sslknife/internal/certificate"
	"github.com/matusso/sslknife/internal/converter"
	skcrypto "github.com/matusso/sslknife/internal/crypto"
	"github.com/matusso/sslknife/internal/exitcode"
	"github.com/matusso/sslknife/internal/keys"
	"github.com/matusso/sslknife/internal/output"
)

func newJKSCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "jks",
		Aliases: []string{"keystore"},
		Short:   "Inspect, extract and convert Java keystores (JKS and PKCS#12) without keytool",
		Long: `Work with Java keystores without a JDK. JKS and PKCS#12 keystores and
truststores are supported. The store password comes from --password-file,
$SSLKNIFE_KEY_PASSWORD or a prompt (Java's default is often "changeit").`,
	}
	cmd.AddCommand(newJKSListCmd(a, "inspect"), newJKSListCmd(a, "list"), newJKSExtractCmd(a), newJKSConvertCmd(a))
	return cmd
}

func (a *app) openKeystore(path, passwordFile string) (*converter.Bundle, error) {
	data, err := a.readInput(path)
	if err != nil {
		return nil, err
	}
	if f := converter.Detect(data); f != converter.FormatJKS && f != converter.FormatPKCS12 && f != converter.FormatJCEKS {
		return nil, exitcode.New(exitcode.Usage, "%s is %s, not a Java keystore (use 'sslknife inspect')", displayName(path), f.Description())
	}
	return a.decodeInputs([]string{path}, passwordFile)
}

type jksView struct {
	File    string             `json:"file"`
	Format  string             `json:"format"`
	Entries []jksEntry         `json:"entries"`
	Summary converter.Contents `json:"contents"`
}

type jksEntry struct {
	Alias   string      `json:"alias"`
	Type    string      `json:"type"` // PrivateKeyEntry, trustedCertEntry
	Created *time.Time  `json:"created,omitempty"`
	Key     string      `json:"key,omitempty"`
	Chain   []entryView `json:"chain"`
	Expires time.Time   `json:"expires"`
	Status  string      `json:"status"`
}

// groupEntries turns bundle objects into keystore entries: each key with
// its certificate chain, and the remaining certificates as trusted entries.
func (a *app) groupEntries(b *converter.Bundle) []jksEntry {
	var out []jksEntry
	used := map[int]bool{}
	for _, o := range b.Objects {
		if o.Kind != converter.KindPrivateKey {
			continue
		}
		e := jksEntry{Alias: o.Alias, Type: "PrivateKeyEntry", Key: keys.Describe(o.PublicKey()).Description}
		if !o.Created.IsZero() {
			t := o.Created.UTC()
			e.Created = &t
		}
		var chainCerts []*converter.Object
		for j := range b.Objects {
			c := &b.Objects[j]
			if c.Kind == converter.KindCertificate && !used[j] && keys.Equal(c.Cert.PublicKey, o.PublicKey()) {
				chainCerts = append(chainCerts, c)
				used[j] = true
				// Follow issuers.
				cur := c.Cert
				for len(chainCerts) < 10 {
					found := false
					for k := range b.Objects {
						n := &b.Objects[k]
						if n.Kind == converter.KindCertificate && !used[k] && !certificate.IsSelfSigned(cur) && certificate.Issues(n.Cert, cur) {
							chainCerts, used[k], cur, found = append(chainCerts, n), true, n.Cert, true
							break
						}
					}
					if !found {
						break
					}
				}
				break
			}
		}
		sub := &converter.Bundle{}
		for _, c := range chainCerts {
			sub.Objects = append(sub.Objects, *c)
		}
		e.Chain = entries(sub)
		if len(chainCerts) > 0 {
			e.Expires = chainCerts[0].Cert.NotAfter.UTC()
		}
		out = append(out, e)
	}
	for j, o := range b.Objects {
		if o.Kind != converter.KindCertificate || used[j] {
			continue
		}
		e := jksEntry{Alias: o.Alias, Type: "trustedCertEntry", Expires: o.Cert.NotAfter.UTC(),
			Chain: entries(&converter.Bundle{Objects: []converter.Object{o}})}
		if !o.Created.IsZero() {
			t := o.Created.UTC()
			e.Created = &t
		}
		out = append(out, e)
	}
	for i := range out {
		status, _ := a.certStatus(time.Time{}, out[i].Expires, false)
		out[i].Status = status
	}
	return out
}

func newJKSListCmd(a *app, use string) *cobra.Command {
	var passwordFile string
	cmd := &cobra.Command{
		Use:   use + " <keystore>",
		Short: "List keystore entries: aliases, types, chains and expiry",
		Example: `  sslknife jks ` + use + ` keystore.jks
  SSLKNIFE_KEY_PASSWORD=changeit sslknife jks ` + use + ` truststore.p12 --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			b, err := a.openKeystore(args[0], passwordFile)
			if err != nil {
				return err
			}
			v := jksView{File: displayName(args[0]), Format: b.Format.Description(), Entries: a.groupEntries(b), Summary: b.Summarize()}
			return a.out.Emit(v, func(w io.Writer) error {
				st := a.out.Style
				fmt.Fprintf(w, "%s  %s, %d entries\n\n", st.Bold(v.File), v.Format, len(v.Entries))
				if use == "list" {
					t := output.NewTable("ALIAS", "TYPE", "SUBJECT", "ALGORITHM", "EXPIRES", "STATUS")
					for _, e := range v.Entries {
						subj, alg := "", e.Key
						if len(e.Chain) > 0 {
							subj = shortDN(e.Chain[0].Subject)
							if alg == "" {
								alg = e.Chain[0].Algorithm
							}
						}
						t.Row(e.Alias, e.Type, truncate(subj, 40), alg, e.Expires.Format(time.DateOnly), st.Level(e.Status))
					}
					return t.Render(w, st)
				}
				for _, e := range v.Entries {
					fmt.Fprintf(w, "%s  %s", st.Bold(e.Alias), e.Type)
					if e.Created != nil {
						fmt.Fprintf(w, st.Dim("  created %s"), e.Created.Format(time.DateOnly))
					}
					fmt.Fprintln(w)
					if e.Key != "" {
						fmt.Fprintf(w, "  key: %s\n", e.Key)
					}
					root := &output.Node{Label: "chain"}
					cur := root
					for _, c := range e.Chain {
						cur = cur.Add(fmt.Sprintf("%s  %s", shortDN(c.Subject), st.Dim(c.Algorithm+", expires "+c.NotAfter.Format(time.DateOnly))))
					}
					if len(e.Chain) == 0 {
						root.Add(st.Yellow("no certificate for this key"))
					}
					var tree strings.Builder
					_ = output.RenderTree(&tree, root)
					for _, line := range strings.Split(strings.TrimRight(tree.String(), "\n"), "\n") {
						fmt.Fprintln(w, "  "+line)
					}
					fmt.Fprintln(w)
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&passwordFile, "password-file", "", "keystore password file")
	return cmd
}

func newJKSExtractCmd(a *app) *cobra.Command {
	var passwordFile, dir string
	var force, encrypt bool
	cmd := &cobra.Command{
		Use:   "extract <keystore>",
		Short: "Write every entry as PEM files (<alias>.crt, <alias>.key)",
		Long: `Extract each keystore entry into PEM files in --dir: the certificate chain
as <alias>.crt and, for key entries, the private key as <alias>.key (mode
0600, optionally encrypted with --encrypt).`,
		Example: "  sslknife jks extract keystore.jks --dir extracted/",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			b, err := a.openKeystore(args[0], passwordFile)
			if err != nil {
				return err
			}
			var pw []byte
			if encrypt {
				if pw, err = a.outPassword("", "the extracted keys"); err != nil {
					return err
				}
				defer skcrypto.Zero(pw)
			}
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return err
			}
			written := 0
			for i, o := range b.Objects {
				alias := sanitizeFileName(o.Alias)
				if o.Alias == "" {
					alias = fmt.Sprintf("entry-%d", i+1)
				}
				switch o.Kind {
				case converter.KindPrivateKey:
					data, err := keys.MarshalPrivateKeyPEM(o.Key, pw)
					if err != nil {
						return err
					}
					err = writeNewFile(filepath.Join(dir, alias+".key"), data, 0o600, force)
					skcrypto.Zero(data)
					if err != nil {
						return err
					}
					written++
				case converter.KindCertificate:
					path := filepath.Join(dir, alias+".crt")
					if err := writeNewFile(path, certificate.EncodePEM(o.Cert), 0o644, force); err != nil {
						return err
					}
					written++
				}
			}
			a.out.Infof("Wrote %d file(s) to %s", written, dir)
			return nil
		},
	}
	cmd.Flags().StringVar(&passwordFile, "password-file", "", "keystore password file")
	cmd.Flags().StringVar(&dir, "dir", ".", "output directory")
	cmd.Flags().BoolVar(&encrypt, "encrypt", false, "encrypt extracted private keys")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing files")
	return cmd
}

func newJKSConvertCmd(a *app) *cobra.Command {
	var o convertOpts
	cmd := &cobra.Command{
		Use:   "convert <keystore>",
		Short: "Convert a keystore to PKCS#12 (default), JKS or PEM",
		Example: `  sslknife jks convert legacy.jks                 # → legacy.p12
  sslknife jks convert legacy.jks --to pem -o legacy.pem
  sslknife jks convert truststore.jks --to pem --stdout`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			to, err := converter.ParseTarget(o.to)
			if err != nil {
				return usageError{err}
			}
			b, err := a.openKeystore(args[0], o.passwordFile)
			if err != nil {
				return err
			}
			enc := converter.EncodeOptions{Alias: o.alias}
			if to == converter.FormatPKCS12 || to == converter.FormatJKS || o.encrypt {
				if enc.Password, err = a.outPassword(o.outPasswordFile, "the "+string(to)+" output"); err != nil {
					return err
				}
				defer skcrypto.Zero(enc.Password)
			}
			res, err := converter.Encode(b, to, enc)
			if err != nil {
				if errors.Is(err, converter.ErrImpossible) {
					return exitcode.With(exitcode.Unsupported, err)
				}
				return err
			}
			for _, n := range res.Notes {
				a.out.Warnf("%s", n)
			}
			return a.writeOutput(res, args[0], o)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&o.to, "to", "t", "pkcs12", "target format: pkcs12, jks, pem")
	f.StringVarP(&o.out, "out", "o", "", "output file")
	f.BoolVar(&o.stdout, "stdout", false, "write to standard output")
	f.BoolVar(&o.showSecret, "show-secret", false, "allow private key material on standard output")
	f.BoolVar(&o.encrypt, "encrypt", false, "encrypt private keys in PEM output")
	f.StringVar(&o.passwordFile, "password-file", "", "keystore password file")
	f.StringVar(&o.outPasswordFile, "out-password-file", "", "password for the output")
	f.BoolVar(&o.force, "force", false, "overwrite the output file")
	return cmd
}

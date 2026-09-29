package cmd

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/matusso/sslknife/internal/config"
	"github.com/matusso/sslknife/internal/converter"
	skcrypto "github.com/matusso/sslknife/internal/crypto"
	"github.com/matusso/sslknife/internal/database"
	"github.com/matusso/sslknife/internal/exitcode"
	"github.com/matusso/sslknife/internal/inventory"
	"github.com/matusso/sslknife/internal/output"
	"github.com/matusso/sslknife/internal/sshkeys"
	"github.com/matusso/sslknife/internal/views"
)

// EnvSSHPassphrase supplies SSH key passphrases non-interactively.
const EnvSSHPassphrase = "SSLKNIFE_SSH_PASSPHRASE"

func newSSHCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssh",
		Short: "Generate, inspect, store and certify SSH keys",
	}
	cmd.AddCommand(newSSHGenerateCmd(a), newSSHInspectCmd(a), newSSHImportCmd(a), newSSHListCmd(a), newSSHShowCmd(a),
		newSSHExportCmd(a), newSSHDeleteCmd(a), newSSHFingerprintCmd(a), newSSHPublicCmd(a), newSSHConvertCmd(a),
		newSSHTagCmd(a), newSSHCertCmd(a))
	return cmd
}

// sshPassphrase reads a passphrase for an existing key.
func (a *app) sshPassphrase(file, what string) ([]byte, error) {
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		return []byte(strings.TrimRight(string(data), "\r\n")), nil
	}
	if p := os.Getenv(EnvSSHPassphrase); p != "" {
		return []byte(p), nil
	}
	if !a.prompt.Interactive() {
		return nil, exitcode.New(exitcode.Auth, "%s is passphrase protected: use --passphrase-file or %s", what, EnvSSHPassphrase)
	}
	return a.prompt.Password("Passphrase for " + what)
}

// loadSSHItems parses a file, or loads a stored key when arg is not a file.
func (a *app) loadSSHItems(ctx context.Context, arg string) ([]sshkeys.Item, string, error) {
	if arg == "-" || fileExists(config.ExpandHome(arg)) {
		data, err := a.readInput(config.ExpandHome(arg))
		if err != nil {
			return nil, "", err
		}
		items, err := sshkeys.Parse(data)
		if err != nil {
			return nil, "", exitcode.New(exitcode.Usage, "%s: no SSH key found", displayName(arg))
		}
		return items, displayName(arg), nil
	}
	if !database.Exists(a.cfg.Database.Path) {
		return nil, "", exitcode.New(exitcode.NotFound, "%s: no such file", arg)
	}
	v, err := a.requireVault(ctx)
	if err != nil {
		return nil, "", err
	}
	k, err := v.db.GetSSHKey(ctx, arg)
	if err != nil {
		return nil, "", mapLookupErr(err, arg)
	}
	items, err := sshkeys.Parse([]byte(k.PublicKey))
	if err != nil {
		return nil, "", err
	}
	items[0].Comment = k.Comment
	return items, "vault:" + k.ID, nil
}

func newSSHGenerateCmd(a *app) *cobra.Command {
	var alg, out, comment, passphraseFile, name string
	var tags []string
	var noPass, store, force bool
	cmd := &cobra.Command{
		Use:     "generate",
		Aliases: []string{"gen", "keygen", "create"},
		Short:   "Generate an SSH key pair (like ssh-keygen)",
		Long: `Generate an SSH key pair in OpenSSH format: <out> (private, mode 0600) and
<out>.pub. On a terminal you are asked for a passphrase (empty for none);
otherwise $SSLKNIFE_SSH_PASSPHRASE or --passphrase-file is used, or
--no-passphrase must be given.`,
		Example: `  sslknife ssh generate
  sslknife ssh generate --type ecdsa-p384 -o ~/.ssh/id_ecdsa -C alice@laptop
  sslknife ssh generate --no-passphrase --store --name deploy-key`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			algo, err := sshkeys.ParseAlgorithm(alg)
			if err != nil {
				return usageError{err}
			}
			if out == "" {
				out = "id_" + strings.SplitN(string(algo), "-", 2)[0]
			}
			out = config.ExpandHome(out)
			if comment == "" {
				user := os.Getenv("USER")
				host, _ := os.Hostname()
				if user != "" && host != "" {
					comment = user + "@" + host
				}
			}
			var pass []byte
			switch {
			case noPass:
			case passphraseFile != "" || os.Getenv(EnvSSHPassphrase) != "":
				if pass, err = a.sshPassphrase(passphraseFile, "the new key"); err != nil {
					return err
				}
			case a.prompt.Interactive():
				p, err := a.prompt.Password("Passphrase (empty for no passphrase)")
				if err != nil {
					return err
				}
				if len(p) > 0 {
					again, err := a.prompt.Password("Repeat passphrase")
					if err != nil {
						return err
					}
					if string(again) != string(p) {
						return exitcode.New(exitcode.Usage, "passphrases do not match")
					}
				}
				pass = p
			default:
				return usagef("no terminal: set %s, use --passphrase-file, or pass --no-passphrase", EnvSSHPassphrase)
			}
			defer skcrypto.Zero(pass)
			_, priv, pub, err := sshkeys.Generate(algo, comment, pass)
			if err != nil {
				return err
			}
			defer skcrypto.Zero(priv)
			if err := writeNewFile(out, priv, 0o600, force); err != nil {
				return err
			}
			if err := writeNewFile(out+".pub", pub, 0o644, force); err != nil {
				return err
			}
			items, _ := sshkeys.Parse(priv)
			info := sshkeys.Describe(items[0])
			if store {
				inv, err := a.inventory(cmd.Context())
				if err != nil {
					return err
				}
				if _, _, err := inv.ImportSSHKey(cmd.Context(), items[0], inventory.ImportOptions{Name: name, Tags: tags, Source: "generated"}, true); err != nil {
					return err
				}
			}
			return a.out.Emit(info, func(w io.Writer) error {
				fmt.Fprintf(w, "Generated %s key (%d bits)%s\n", info.Type, info.Bits, map[bool]string{true: ", passphrase protected", false: ""}[len(pass) > 0])
				fmt.Fprintf(w, "  private: %s (mode 0600)\n  public:  %s.pub\n  %s\n", out, out, info.FingerprintSHA256)
				if store {
					fmt.Fprintln(w, "  stored in the vault")
				}
				return nil
			})
		},
	}
	f := cmd.Flags()
	f.StringVarP(&alg, "type", "t", "ed25519", "key type: ed25519, ecdsa-p256, ecdsa-p384, ecdsa-p521, rsa-3072, rsa-4096")
	f.StringVarP(&out, "out", "o", "", "private key file (default ./id_<type>)")
	f.StringVarP(&comment, "comment", "C", "", "comment (default user@host)")
	f.StringVar(&passphraseFile, "passphrase-file", "", "read the passphrase from a file")
	f.BoolVar(&noPass, "no-passphrase", false, "do not protect the private key")
	f.BoolVar(&store, "store", false, "also store the key in the vault")
	f.StringVar(&name, "name", "", "friendly name in the vault")
	f.StringSliceVar(&tags, "tag", nil, "tags in the vault")
	f.BoolVar(&force, "force", false, "overwrite existing files")
	return cmd
}

func (a *app) renderSSHInfo(w io.Writer, info sshkeys.Info) error {
	st := a.out.Style
	kv := output.NewKV(st)
	kv.Add("Kind", info.Kind).Add("Format", info.Format).Add("Type", info.Type)
	if info.Bits > 0 {
		kv.Addf("Bits", "%d", info.Bits)
	}
	kv.Add("Fingerprint SHA256", info.FingerprintSHA256).
		Add("Fingerprint MD5", st.Dim(info.FingerprintMD5+"  (legacy)")).
		Add("Comment", info.Comment)
	if info.Kind == sshkeys.KindPrivate {
		kv.Addf("Passphrase", "%s", map[bool]string{true: "yes", false: st.Yellow("no")}[info.Encrypted])
	}
	kv.Add("Strength", st.Level(strings.ToUpper(info.Strength))).List("Notes", info.Notes).List("Options", info.Options)
	if c := info.Certificate; c != nil {
		kv.Heading("Certificate")
		kv.Add("Type", c.CertType).Add("Key ID", c.KeyID).Addf("Serial", "%d", c.Serial).List("Principals", c.Principals)
		after, before := "always", "forever"
		if c.ValidAfter != nil {
			after = c.ValidAfter.Format(time.RFC3339)
		}
		if c.ValidBefore != nil {
			before = c.ValidBefore.Format(time.RFC3339)
		}
		status := map[string]string{"valid": "VALID", "expired": "EXPIRED", "not_yet_valid": "INVALID"}[c.Status]
		kv.Add("Valid", after+" → "+before+"  "+st.Level(status))
		var opts []string
		for k, v := range c.CriticalOptions {
			opts = append(opts, k+" "+v)
		}
		kv.List("Critical options", opts).List("Extensions", c.Extensions).
			Add("CA", c.CAType+"  "+c.CAFingerprint).Add("Signature", c.SignatureAlgo)
	}
	return kv.Render(w)
}

func newSSHInspectCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <file|id>",
		Short: "Describe SSH keys, authorized_keys files and certificates",
		Long: `Describe public keys, private keys (without decrypting them when the
format includes the public key), every line of an authorized_keys file, and
OpenSSH certificates.`,
		Example: `  sslknife ssh inspect ~/.ssh/id_ed25519.pub
  sslknife ssh inspect ~/.ssh/authorized_keys
  sslknife ssh inspect id_ed25519-cert.pub --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			items, _, err := a.loadSSHItems(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			var infos []sshkeys.Info
			for _, it := range items {
				infos = append(infos, sshkeys.Describe(it))
			}
			var v any = infos
			if len(infos) == 1 {
				v = infos[0]
			}
			return a.out.Emit(v, func(w io.Writer) error {
				for i, info := range infos {
					if i > 0 {
						fmt.Fprintln(w)
					}
					if err := a.renderSSHInfo(w, info); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
}

type sshKeyView = views.SSHKey

func toSSHView(k *database.SSHKey) sshKeyView { return views.NewSSHKey(k) }

func (a *app) renderSSHTable(w io.Writer, ks []sshKeyView) error {
	st := a.out.Style
	t := output.NewTable("ID", "NAME", "TYPE", "BITS", "FINGERPRINT", "PRIVATE", "COMMENT")
	for _, k := range ks {
		priv := st.Dim("no")
		if k.HasPrivate {
			priv = "yes"
			if k.Passphrase {
				priv += st.Dim(" (passphrase)")
			}
		}
		t.Row(st.Dim(k.ID[:8]), k.Name, k.Type, fmt.Sprint(k.Bits), k.Fingerprint, priv, truncate(k.Comment, 30))
	}
	return t.Render(w, st)
}

func newSSHImportCmd(a *app) *cobra.Command {
	var name, comment string
	var tags []string
	var yes, publicOnly bool
	cmd := &cobra.Command{
		Use:   "import <file>...",
		Short: "Store SSH keys in the vault",
		Long: `Store SSH public keys, or private keys after confirmation. Private keys are
stored exactly as the file (a passphrase-protected key stays protected by its
passphrase) inside the encrypted vault. --public-only stores just the public
key of a private key file.`,
		Example: `  sslknife ssh import ~/.ssh/id_ed25519
  sslknife ssh import ~/.ssh/id_ed25519 --public-only
  sslknife ssh import ~/.ssh/authorized_keys --tag servers`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			inv, err := a.inventory(ctx)
			if err != nil {
				return err
			}
			var views []sshKeyView
			for _, arg := range args {
				data, err := a.readInput(config.ExpandHome(arg))
				if err != nil {
					return err
				}
				items, err := sshkeys.Parse(data)
				if err != nil {
					return exitcode.New(exitcode.Usage, "%s: no SSH key found", displayName(arg))
				}
				for i, it := range items {
					withPrivate := false
					if it.Kind == sshkeys.KindPrivate && !publicOnly {
						if err := a.confirmPrivateImport(1, yes); err != nil {
							return err
						}
						withPrivate = true
					}
					if it.Kind == sshkeys.KindPrivate && it.Public == nil {
						pass, err := a.sshPassphrase("", displayName(arg))
						if err != nil {
							return err
						}
						// Decrypting only derives the public key; the stored file stays as is.
						err = it.Decrypt(pass)
						skcrypto.Zero(pass)
						if err != nil {
							return exitcode.With(exitcode.Auth, err)
						}
					}
					o := inventory.ImportOptions{Name: name, Tags: tags, Comment: comment, Source: "file:" + displayName(arg)}
					if i > 0 {
						o.Name = ""
					}
					k, created, err := inv.ImportSSHKey(ctx, it, o, withPrivate)
					if err != nil {
						return err
					}
					if !created {
						a.out.Infof("%s already stored as %s", k.FingerprintSHA256, k.ID)
					}
					views = append(views, toSSHView(k))
				}
			}
			return a.out.Emit(views, func(w io.Writer) error { return a.renderSSHTable(w, views) })
		},
	}
	f := cmd.Flags()
	f.StringVar(&name, "name", "", "friendly name")
	f.StringVar(&comment, "comment", "", "override the key comment")
	f.StringSliceVar(&tags, "tag", nil, "tags")
	f.BoolVarP(&yes, "yes", "y", false, "store private keys without asking")
	f.BoolVar(&publicOnly, "public-only", false, "store only the public key")
	return cmd
}

func newSSHListCmd(a *app) *cobra.Command {
	var query string
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List stored SSH keys",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			inv, err := a.inventory(cmd.Context())
			if err != nil {
				return err
			}
			res, err := inv.Search(cmd.Context(), strings.TrimSpace("type:ssh "+query))
			if err != nil {
				return usageError{err}
			}
			views := []sshKeyView{}
			for _, k := range res.SSHKeys {
				views = append(views, toSSHView(k))
			}
			return a.out.Emit(views, func(w io.Writer) error {
				if len(views) == 0 {
					fmt.Fprintln(w, "No SSH keys stored.")
					return nil
				}
				return a.renderSSHTable(w, views)
			})
		},
	}
	cmd.Flags().StringVar(&query, "filter", "", "search query")
	return cmd
}

func (a *app) getSSHKey(ctx context.Context, ref string) (*vault, *database.SSHKey, error) {
	v, err := a.requireVault(ctx)
	if err != nil {
		return nil, nil, err
	}
	k, err := v.db.GetSSHKey(ctx, ref)
	if err != nil {
		return nil, nil, mapLookupErr(err, ref)
	}
	return v, k, nil
}

func newSSHShowCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "show <id|name|fingerprint>",
		Short: "Show a stored SSH key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, k, err := a.getSSHKey(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			v := toSSHView(k)
			return a.out.Emit(v, func(w io.Writer) error {
				kv := output.NewKV(a.out.Style)
				kv.Add("ID", v.ID).Add("Name", v.Name).Add("Type", v.Type).Addf("Bits", "%d", v.Bits).
					Add("Fingerprint", v.Fingerprint).Add("Comment", v.Comment).
					Addf("Private key", "%s", yesNo(v.HasPrivate)).Addf("Passphrase", "%s", yesNo(v.Passphrase)).
					Add("Tags", strings.Join(v.Tags, ", ")).Add("Source", v.Source).Add("Imported", v.ImportedAt.Format(time.RFC3339)).
					Add("Public key", v.PublicKey)
				return kv.Render(w)
			})
		},
	}
}

func newSSHExportCmd(a *app) *cobra.Command {
	var out string
	var public, toStdout, showSecret, force bool
	cmd := &cobra.Command{
		Use:   "export <id|name>",
		Short: "Write a stored SSH key to a file",
		Long: `Write the stored private key file exactly as imported (mode 0600, still
passphrase-protected if it was), or the public key with --public. Private
keys go to stdout only with --stdout --show-secret.`,
		Example: `  sslknife ssh export deploy-key -o ~/.ssh/deploy
  sslknife ssh export deploy-key --public >> ~/.ssh/authorized_keys`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, k, err := a.getSSHKey(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if public {
				line := []byte(k.PublicKey + map[bool]string{true: " " + k.Comment, false: ""}[k.Comment != ""] + "\n")
				if out != "" {
					return writeNewFile(config.ExpandHome(out), line, 0o644, force)
				}
				_, err := a.stdout.Write(line)
				return err
			}
			if toStdout != showSecret {
				return usagef("printing a private key requires both --stdout and --show-secret")
			}
			data, err := v.db.SSHPrivateKey(cmd.Context(), k)
			if err != nil {
				return exitcode.With(exitcode.NotFound, err)
			}
			defer skcrypto.Zero(data)
			if toStdout {
				_, err = a.stdout.Write(data)
				return err
			}
			if out == "" {
				out = "id_" + sanitizeFileName(firstNonEmpty(k.Name, k.ID))
			}
			if err := writeNewFile(config.ExpandHome(out), data, 0o600, force); err != nil {
				return err
			}
			a.out.Infof("Private key written to %s (mode 0600)", out)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&out, "out", "o", "", "output file")
	f.BoolVar(&public, "public", false, "export the public key")
	f.BoolVar(&toStdout, "stdout", false, "write the private key to stdout (requires --show-secret)")
	f.BoolVar(&showSecret, "show-secret", false, "confirm that secret material may be printed")
	f.BoolVar(&force, "force", false, "overwrite the output file")
	return cmd
}

func newSSHDeleteCmd(a *app) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:     "delete <id|name>",
		Aliases: []string{"rm"},
		Short:   "Delete a stored SSH key",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, k, err := a.getSSHKey(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if err := a.confirm(fmt.Sprintf("Delete SSH key %s (%s)?", k.ID, k.FingerprintSHA256), yes); err != nil {
				return err
			}
			return v.db.DeleteSSHKey(cmd.Context(), k.ID)
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask for confirmation")
	return cmd
}

func newSSHFingerprintCmd(a *app) *cobra.Command {
	var md5 bool
	return &cobra.Command{
		Use:     "fingerprint <file|id>",
		Aliases: []string{"fp"},
		Short:   "Print SSH key fingerprints (SHA256; MD5 with --md5)",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			items, _, err := a.loadSSHItems(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			var infos []sshkeys.Info
			for _, it := range items {
				infos = append(infos, sshkeys.Describe(it))
			}
			return a.out.Emit(infos, func(w io.Writer) error {
				for _, i := range infos {
					fp := i.FingerprintSHA256
					if md5 {
						fp = "MD5:" + i.FingerprintMD5
					}
					fmt.Fprintf(w, "%d %s %s (%s)\n", i.Bits, fp, firstNonEmpty(i.Comment, "no comment"), strings.ToUpper(strings.TrimPrefix(i.Type, "ssh-")))
				}
				return nil
			})
		},
	}
}

func newSSHPublicCmd(a *app) *cobra.Command {
	var passphraseFile string
	cmd := &cobra.Command{
		Use:   "public <file|id>",
		Short: "Print the public key (authorized_keys line) of a private key",
		Example: `  sslknife ssh public ~/.ssh/id_ed25519
  sslknife ssh public server.key   # a PEM/PKCS#8 key works too`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			items, _, err := a.loadSSHItems(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			for _, it := range items {
				if it.Public == nil {
					pass, err := a.sshPassphrase(passphraseFile, displayName(args[0]))
					if err != nil {
						return err
					}
					err = it.Decrypt(pass)
					skcrypto.Zero(pass)
					if err != nil {
						return exitcode.With(exitcode.Auth, err)
					}
				}
				pub := it.Public
				if it.Cert != nil {
					pub = it.Cert.Key
				}
				if _, err := a.stdout.Write(sshkeys.AuthorizedKey(pub, it.Comment)); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&passphraseFile, "passphrase-file", "", "passphrase for legacy encrypted PEM keys")
	return cmd
}

func newSSHConvertCmd(a *app) *cobra.Command {
	var to, out, passphraseFile string
	var toStdout, showSecret, force, encrypt bool
	cmd := &cobra.Command{
		Use:   "convert <file>",
		Short: "Convert SSH keys: openssh, pkcs8, pem, ssh (authorized_keys), rfc4716",
		Long: `Convert between SSH key formats. Private keys: openssh (new OpenSSH format),
pkcs8 and pem (PKCS#8 PEM). Public keys: ssh (authorized_keys) and rfc4716.
Encrypted keys are decrypted with --passphrase-file, $SSLKNIFE_SSH_PASSPHRASE
or a prompt; add --encrypt to protect the output.`,
		Example: `  sslknife ssh convert id_rsa --to pkcs8 -o id_rsa.pem
  sslknife ssh convert id_ed25519.pub --to rfc4716 --stdout
  sslknife ssh convert key.pem --to openssh --encrypt -o id_new`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := converter.ParseTarget(to)
			if err != nil {
				return usageError{err}
			}
			switch target {
			case converter.FormatOpenSSH, converter.FormatPKCS8, converter.FormatPEM, converter.FormatSSHPublic, converter.FormatRFC4716:
			default:
				return usagef("--to must be openssh, pkcs8, pem, ssh or rfc4716")
			}
			items, _, err := a.loadSSHItems(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			b := &converter.Bundle{}
			for _, it := range items {
				switch {
				case it.Kind == sshkeys.KindPrivate:
					if it.Private == nil {
						pass, err := a.sshPassphrase(passphraseFile, displayName(args[0]))
						if err != nil {
							return err
						}
						err = it.Decrypt(pass)
						skcrypto.Zero(pass)
						if err != nil {
							return exitcode.With(exitcode.Auth, err)
						}
					}
					b.Objects = append(b.Objects, converter.Object{Kind: converter.KindPrivateKey, Key: it.Private, Comment: it.Comment})
				case it.Cert != nil:
					return exitcode.New(exitcode.Unsupported, "OpenSSH certificates cannot be converted to other formats; use 'ssh public' for the certified key")
				default:
					cpk, ok := it.Public.(ssh.CryptoPublicKey)
					if !ok {
						return exitcode.New(exitcode.Unsupported, "%s keys cannot be converted", it.Public.Type())
					}
					b.Objects = append(b.Objects, converter.Object{Kind: converter.KindPublicKey, Public: cpk.CryptoPublicKey(), Comment: it.Comment})
				}
			}
			if target == converter.FormatPKCS8 && b.Count(converter.KindPrivateKey) == 0 {
				target = converter.FormatSPKI
			}
			var opts converter.EncodeOptions
			if encrypt {
				if opts.Password, err = a.outPassword(passphraseFile, "the converted key"); err != nil {
					return err
				}
				defer skcrypto.Zero(opts.Password)
			}
			res, err := converter.Encode(b, target, opts)
			if err != nil {
				return exitcode.With(exitcode.Unsupported, err)
			}
			for _, n := range res.Notes {
				a.out.Warnf("%s", n)
			}
			return a.writeOutput(res, args[0], convertOpts{out: out, stdout: toStdout, showSecret: showSecret, force: force})
		},
	}
	f := cmd.Flags()
	f.StringVarP(&to, "to", "t", "", "target format")
	f.StringVarP(&out, "out", "o", "", "output file")
	f.BoolVar(&toStdout, "stdout", false, "write to standard output")
	f.BoolVar(&showSecret, "show-secret", false, "allow private keys on standard output")
	f.BoolVar(&encrypt, "encrypt", false, "protect the output private key with a passphrase")
	f.StringVar(&passphraseFile, "passphrase-file", "", "passphrase for the input key")
	f.BoolVar(&force, "force", false, "overwrite the output file")
	_ = cmd.MarkFlagRequired("to")
	return cmd
}

func newSSHTagCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "tag <id|name> <tag>...",
		Short: "Tag a stored SSH key",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, k, err := a.getSSHKey(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if err := v.db.AddTags(cmd.Context(), "ssh", k.ID, args[1:]); err != nil {
				return usageError{err}
			}
			return nil
		},
	}
}

func newSSHCertCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Inspect, sign and create OpenSSH certificates",
	}
	cmd.AddCommand(&cobra.Command{
		Use:     "inspect <cert-file>",
		Short:   "Describe an OpenSSH certificate (principals, validity, options, CA)",
		Example: "  sslknife ssh cert inspect ~/.ssh/id_ed25519-cert.pub",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			items, _, err := a.loadSSHItems(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			for _, it := range items {
				if it.Cert == nil {
					continue
				}
				info := sshkeys.Describe(it)
				err := a.out.Emit(info, func(w io.Writer) error { return a.renderSSHInfo(w, info) })
				if err != nil || info.Certificate.Status != "valid" {
					if err == nil {
						return exitcode.Silent(exitcode.CheckFailed)
					}
					return err
				}
				return nil
			}
			return exitcode.New(exitcode.Usage, "%s contains no OpenSSH certificate", displayName(args[0]))
		},
	})
	cmd.AddCommand(newSSHCertSignCmd(a, false), newSSHCertSignCmd(a, true))
	return cmd
}

// loadSSHSigner loads a CA private key from a file or the vault.
func (a *app) loadSSHSigner(ctx context.Context, ref, passphraseFile string) (crypto.Signer, error) {
	var data []byte
	if fileExists(config.ExpandHome(ref)) {
		var err error
		if data, err = a.readInput(config.ExpandHome(ref)); err != nil {
			return nil, err
		}
	} else {
		v, k, err := a.getSSHKey(ctx, ref)
		if err != nil {
			return nil, err
		}
		if data, err = v.db.SSHPrivateKey(ctx, k); err != nil {
			return nil, exitcode.With(exitcode.NotFound, err)
		}
		defer skcrypto.Zero(data)
	}
	items, err := sshkeys.Parse(data)
	if err != nil || items[0].Kind != sshkeys.KindPrivate {
		// Also accept PKCS#8/PEM keys usable as SSH CAs.
		s, lerr := a.loadSigner(ctx, ref, passphraseFile)
		if lerr != nil {
			return nil, exitcode.New(exitcode.Usage, "%s is not a private key", ref)
		}
		return s, nil
	}
	it := items[0]
	if it.Private == nil {
		pass, err := a.sshPassphrase(passphraseFile, "the CA key")
		if err != nil {
			return nil, err
		}
		err = it.Decrypt(pass)
		skcrypto.Zero(pass)
		if err != nil {
			return nil, exitcode.With(exitcode.Auth, err)
		}
	}
	s, ok := it.Private.(crypto.Signer)
	if !ok {
		return nil, exitcode.New(exitcode.Unsupported, "CA key cannot sign")
	}
	return s, nil
}

func newSSHCertSignCmd(a *app, create bool) *cobra.Command {
	var caRef, keyFile, keyID, validity, out, passphraseFile, alg string
	var principals, extensions, options []string
	var host, force, noPass bool
	var serial uint64
	use, short := "sign", "Sign a public key with an SSH CA"
	if create {
		use, short = "create", "Generate a new key pair and certify it in one step"
	}
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Long: short + `.

User certificates get OpenSSH's default permissions (pty, forwarding, user rc)
unless --extension is given; host certificates carry none. RSA CAs sign with
rsa-sha2-512. --option sets critical options such as force-command=/bin/true
or source-address=10.0.0.0/8.`,
		Example: `  sslknife ssh cert sign --ca ca_key --key id_ed25519.pub --principal alice --id alice@corp --validity 8h
  sslknife ssh cert sign --ca ssh-ca --key host_key.pub --host --principal web01.example.com --validity 52w
  sslknife ssh cert create --ca ssh-ca --principal deploy --validity 1h -o deploy_key --no-passphrase`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if caRef == "" {
				return usagef("--ca is required")
			}
			var dur time.Duration
			if validity != "" && validity != "forever" {
				var err error
				if dur, err = config.ParseDuration(validity); err != nil {
					return usageError{err}
				}
			}
			ca, err := a.loadSSHSigner(ctx, caRef, passphraseFile)
			if err != nil {
				return err
			}
			var pub ssh.PublicKey
			comment := keyID
			if create {
				algo, err := sshkeys.ParseAlgorithm(alg)
				if err != nil {
					return usageError{err}
				}
				if out == "" {
					return usagef("--out is required for 'ssh cert create'")
				}
				var pass []byte
				if !noPass {
					if pass, err = a.outPassword("", "the new key"); err != nil {
						return err
					}
					defer skcrypto.Zero(pass)
				}
				_, priv, pubLine, err := sshkeys.Generate(algo, comment, pass)
				if err != nil {
					return err
				}
				defer skcrypto.Zero(priv)
				if err := writeNewFile(config.ExpandHome(out), priv, 0o600, force); err != nil {
					return err
				}
				if err := writeNewFile(config.ExpandHome(out)+".pub", pubLine, 0o644, force); err != nil {
					return err
				}
				items, _ := sshkeys.Parse(pubLine)
				pub = items[0].Public
				keyFile = out + ".pub"
			} else {
				if keyFile == "" {
					return usagef("--key is required")
				}
				items, _, err := a.loadSSHItems(ctx, keyFile)
				if err != nil {
					return err
				}
				if pub = items[0].Public; pub == nil {
					return exitcode.New(exitcode.Usage, "cannot read the public key of %s; pass the .pub file", keyFile)
				}
				if items[0].Cert != nil {
					pub = items[0].Cert.Key
				}
				comment = firstNonEmpty(items[0].Comment, keyID)
			}
			crit := map[string]string{}
			for _, o := range options {
				k, v, _ := strings.Cut(o, "=")
				crit[k] = v
			}
			req := sshkeys.CertRequest{Key: pub, Host: host, KeyID: keyID, Serial: serial, Principals: principals,
				Validity: dur, CriticalOptions: crit}
			if cmd.Flags().Changed("extension") {
				req.Extensions = extensions
			}
			cert, err := sshkeys.SignCert(req, ca)
			if err != nil {
				return usageError{err}
			}
			certFile := strings.TrimSuffix(config.ExpandHome(keyFile), ".pub") + "-cert.pub"
			if !create && out != "" {
				certFile = config.ExpandHome(out)
			}
			if err := writeNewFile(certFile, sshkeys.AuthorizedKey(cert, comment), 0o644, force); err != nil {
				return err
			}
			info := sshkeys.DescribeCert(cert)
			return a.out.Emit(map[string]any{"certificate_file": certFile, "certificate": info}, func(w io.Writer) error {
				fmt.Fprintf(w, "Signed %s certificate %s for %s (serial %d)\n", info.CertType, filepath.Base(certFile),
					strings.Join(info.Principals, ", "), info.Serial)
				if info.ValidBefore != nil {
					fmt.Fprintf(w, "  valid until %s\n", info.ValidBefore.Format(time.RFC3339))
				} else {
					fmt.Fprintln(w, "  valid forever (consider --validity)")
				}
				return nil
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&caRef, "ca", "", "CA private key (file or stored SSH key)")
	if !create {
		f.StringVar(&keyFile, "key", "", "public key to certify (.pub file or stored key)")
	} else {
		f.StringVarP(&alg, "type", "t", "ed25519", "type of the new key")
		f.BoolVar(&noPass, "no-passphrase", false, "do not protect the new private key")
	}
	f.StringSliceVarP(&principals, "principal", "n", nil, "user or host names (repeatable)")
	f.StringVarP(&keyID, "id", "I", "", "certificate key ID (appears in server logs)")
	f.StringVarP(&validity, "validity", "V", "", "validity period, e.g. 8h, 30d, forever")
	f.BoolVar(&host, "host", false, "issue a host certificate")
	f.Uint64Var(&serial, "serial", 0, "serial number (default random)")
	f.StringSliceVar(&extensions, "extension", nil, "user certificate extensions (default OpenSSH set)")
	f.StringSliceVarP(&options, "option", "O", nil, "critical options, e.g. force-command=/bin/ls")
	f.StringVarP(&out, "out", "o", "", "output file")
	f.StringVar(&passphraseFile, "passphrase-file", "", "passphrase for the CA key")
	f.BoolVar(&force, "force", false, "overwrite output files")
	return cmd
}

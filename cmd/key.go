package cmd

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/matusso/sslknife/internal/certificate"
	"github.com/matusso/sslknife/internal/converter"
	skcrypto "github.com/matusso/sslknife/internal/crypto"
	"github.com/matusso/sslknife/internal/database"
	"github.com/matusso/sslknife/internal/exitcode"
	"github.com/matusso/sslknife/internal/inventory"
	"github.com/matusso/sslknife/internal/keys"
	"github.com/matusso/sslknife/internal/output"
	"github.com/matusso/sslknife/internal/views"
)

func spkiHash(spki []byte) string {
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}

func isNoKey(err error) bool { return errors.Is(err, keys.ErrNoKey) }

// anyPublicKey extracts a public key description from private or public key data.
func (a *app) anyPublicKey(data []byte, arg string) (keys.PublicKeyInfo, string, error) {
	if pk, err := keys.ParsePrivateKey(data, a.keyPassword("", displayName(arg))); err == nil {
		return keys.Describe(pk.Public()), "private key", nil
	} else if !isNoKey(err) {
		return keys.PublicKeyInfo{}, "", err
	}
	pub, err := keys.ParsePublicKey(data)
	if err != nil {
		return keys.PublicKeyInfo{}, "", err
	}
	return keys.Describe(pub.Key), "public key", nil
}

// sshFingerprint returns the OpenSSH SHA256 fingerprint, when the key type
// is representable in SSH.
func sshFingerprint(pub crypto.PublicKey) string {
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(sp)
}

type keyView = views.Key

func toKeyView(k *database.Key) keyView { return views.NewKey(k) }

func (a *app) renderKeyTable(w io.Writer, ks []keyView) error {
	st := a.out.Style
	t := output.NewTable("ID", "NAME", "ALGORITHM", "PRIVATE", "SPKI SHA-256", "TAGS")
	for _, k := range ks {
		priv := st.Dim("no")
		if k.HasPrivate {
			priv = "yes"
		}
		t.Row(st.Dim(k.ID[:8]), k.Name, k.Description, priv, k.SPKISHA256[:16]+"…", strings.Join(k.Tags, ","))
	}
	return t.Render(w, st)
}

func newKeyCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "key",
		Aliases: []string{"keys"},
		Short:   "Generate, inspect and manage private and public keys",
	}
	cmd.AddCommand(newKeyGenerateCmd(a), newKeyInspectCmd(a), newKeyImportCmd(a), newKeyListCmd(a), newKeyShowCmd(a),
		newKeyExportCmd(a), newKeyPublicCmd(a), newKeyMatchCmd(a), newKeyDeleteCmd(a),
		newKeyTagCmd(a, true), newKeyTagCmd(a, false), newKeyRenameCmd(a))
	return cmd
}

func algorithmHelp() string {
	var s []string
	for _, a := range keys.Algorithms {
		s = append(s, string(a))
	}
	return strings.Join(s, ", ")
}

func newKeyGenerateCmd(a *app) *cobra.Command {
	var alg, out, name, passwordFile string
	var tags []string
	var store, encrypt, force bool
	cmd := &cobra.Command{
		Use:     "generate",
		Aliases: []string{"gen", "create", "new"},
		Short:   "Generate a new private key",
		Long: `Generate a private key with the operating system's CSPRNG.

The key is written as PKCS#8 PEM with mode 0600, optionally encrypted
(PBKDF2-HMAC-SHA256 + AES-256-CBC), and/or stored in the encrypted vault.

Algorithms: ` + algorithmHelp(),
		Example: `  sslknife key generate -o server.key
  sslknife key generate --algorithm rsa-4096 -o legacy.key --encrypt
  sslknife key generate --algorithm ed25519 --store --name signing-key`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			algo, err := keys.ParseAlgorithm(alg)
			if err != nil {
				return usageError{err}
			}
			if !store && out == "" {
				out = "key.pem"
			}
			k, err := keys.Generate(algo)
			if err != nil {
				return err
			}
			view := map[string]any{"algorithm": algo, "public_key": keys.Describe(k.Public())}
			if out != "" {
				var pw []byte
				if encrypt {
					if pw, err = a.newSecretPassword(passwordFile); err != nil {
						return err
					}
					defer skcrypto.Zero(pw)
				}
				data, err := keys.MarshalPrivateKeyPEM(k, pw)
				if err != nil {
					return err
				}
				defer skcrypto.Zero(data)
				if err := writeNewFile(out, data, 0o600, force); err != nil {
					return err
				}
				view["file"] = out
				view["encrypted"] = encrypt
			}
			if store {
				inv, err := a.inventory(cmd.Context())
				if err != nil {
					return err
				}
				res, err := inv.ImportPrivateKey(cmd.Context(), k, inventory.ImportOptions{Name: name, Tags: tags, Source: "generated"})
				if err != nil {
					return err
				}
				view["id"] = res.Key.ID
			}
			return a.out.Emit(view, func(w io.Writer) error {
				info := keys.Describe(k.Public())
				fmt.Fprintf(w, "Generated %s key\n", info.Description)
				if out != "" {
					fmt.Fprintf(w, "Written to %s (mode 0600%s)\n", out, map[bool]string{true: ", encrypted", false: ""}[encrypt])
				}
				if id, ok := view["id"]; ok {
					fmt.Fprintf(w, "Stored in vault as %s\n", id)
				}
				fmt.Fprintf(w, "SPKI SHA-256: %s\n", info.SPKISHA256)
				return nil
			})
		},
	}
	f := cmd.Flags()
	f.StringVarP(&alg, "algorithm", "a", string(keys.ECDSAP256), "key algorithm")
	f.StringVarP(&out, "out", "o", "", "output file (default key.pem unless --store)")
	f.BoolVar(&encrypt, "encrypt", false, "encrypt the key file with a password")
	f.StringVar(&passwordFile, "password-file", "", "read the encryption password from a file")
	f.BoolVar(&store, "store", false, "store the key in the vault")
	f.StringVar(&name, "name", "", "friendly name in the vault")
	f.StringSliceVar(&tags, "tag", nil, "tags in the vault (repeatable)")
	f.BoolVar(&force, "force", false, "overwrite the output file")
	_ = cmd.RegisterFlagCompletionFunc("algorithm", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return algorithmList(), cobra.ShellCompDirectiveNoFileComp
	})
	return cmd
}

func algorithmList() []string {
	var s []string
	for _, a := range keys.Algorithms {
		s = append(s, string(a)+"\t"+a.Label())
	}
	return s
}

type keyInspectView struct {
	Source         string             `json:"source"`
	Kind           string             `json:"kind"` // private, public
	Format         string             `json:"format"`
	Encrypted      bool               `json:"encrypted"`
	Comment        string             `json:"comment,omitempty"`
	PublicKey      keys.PublicKeyInfo `json:"public_key"`
	SSHFingerprint string             `json:"ssh_fingerprint,omitempty"`
}

func newKeyInspectCmd(a *app) *cobra.Command {
	var passwordFile string
	cmd := &cobra.Command{
		Use:   "inspect <file|->",
		Short: "Describe a private or public key (never prints key material)",
		Long: `Detect the format of a key file and describe the key. Supported: PKCS#8
(plain and encrypted), PKCS#1, SEC1, legacy encrypted PEM, OpenSSH private
keys, PKIX and PKCS#1 public keys, authorized_keys and RFC 4716 SSH keys.`,
		Example: `  sslknife key inspect server.key
  sslknife key inspect ~/.ssh/id_ed25519.pub --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := a.readInput(args[0])
			if err != nil {
				return err
			}
			view := keyInspectView{Source: displayName(args[0])}
			var pub crypto.PublicKey
			if pk, err := keys.ParsePrivateKey(data, a.keyPassword(passwordFile, displayName(args[0]))); err == nil {
				view.Kind, view.Format, view.Encrypted, view.Comment = "private", pk.Format, pk.Encrypted, pk.Comment
				pub = pk.Public()
			} else if !isNoKey(err) {
				return exitcode.With(exitcode.Auth, err)
			} else if p, err := keys.ParsePublicKey(data); err == nil {
				view.Kind, view.Format, view.Comment = "public", p.Format, p.Comment
				pub = p.Key
			} else {
				return exitcode.New(exitcode.Usage, "%s: no supported key found", displayName(args[0]))
			}
			view.PublicKey = keys.Describe(pub)
			view.SSHFingerprint = sshFingerprint(pub)
			return a.out.Emit(view, func(w io.Writer) error {
				kv := output.NewKV(a.out.Style)
				kv.Add("Type", view.Kind+" key").Add("Format", view.Format).Addf("Encrypted", "%v", view.Encrypted).
					Add("Comment", view.Comment).Add("Algorithm", view.PublicKey.Description).Add("Curve", view.PublicKey.Curve)
				if view.PublicKey.Exponent != 0 {
					kv.Addf("Exponent", "%d", view.PublicKey.Exponent)
				}
				kv.Addf("Bits", "%d", view.PublicKey.Bits).
					Add("Strength", a.out.Style.Level(strings.ToUpper(view.PublicKey.Strength))).
					Add("SPKI SHA-256", view.PublicKey.SPKISHA256).
					Add("SSH SHA256", view.SSHFingerprint)
				kv.List("Notes", view.PublicKey.Notes)
				return kv.Render(w)
			})
		},
	}
	cmd.Flags().StringVar(&passwordFile, "password-file", "", "password for encrypted keys")
	return cmd
}

func newKeyImportCmd(a *app) *cobra.Command {
	var name, passwordFile, comment string
	var tags []string
	var yes bool
	cmd := &cobra.Command{
		Use:   "import <file|->",
		Short: "Store keys from a file in the encrypted vault",
		Long: `Import private keys (or a public key) into the vault. Private keys are
converted to PKCS#8 and sealed with AES-256-GCM inside the encrypted database.
Certificates already stored that use the same key are linked automatically.

You are asked to confirm before private key material is stored; pass --yes in
automation.`,
		Example: `  sslknife key import server.key --name api-prod
  SSLKNIFE_KEY_PASSWORD=... sslknife key import encrypted.key --yes`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := a.readInput(args[0])
			if err != nil {
				return err
			}
			opts := inventory.ImportOptions{Name: name, Tags: tags, Source: "file:" + displayName(args[0]), Comment: comment}
			privs, err := keys.ParsePrivateKeys(data, a.keyPassword(passwordFile, displayName(args[0])))
			if err != nil && !isNoKey(err) {
				return exitcode.With(exitcode.Auth, err)
			}
			var results []inventory.KeyResult
			if len(privs) > 0 {
				if err := a.confirmPrivateImport(len(privs), yes); err != nil {
					return err
				}
				inv, err := a.inventory(cmd.Context())
				if err != nil {
					return err
				}
				for i, pk := range privs {
					o := opts
					if i > 0 {
						o.Name = ""
					}
					r, err := inv.ImportPrivateKey(cmd.Context(), pk.Key, o)
					if err != nil {
						return err
					}
					results = append(results, r)
				}
			} else {
				pub, err := keys.ParsePublicKey(data)
				if err != nil {
					return exitcode.New(exitcode.Usage, "%s: no supported key found", displayName(args[0]))
				}
				inv, err := a.inventory(cmd.Context())
				if err != nil {
					return err
				}
				if opts.Comment == "" {
					opts.Comment = pub.Comment
				}
				r, err := inv.ImportPublicKey(cmd.Context(), pub.Key, opts)
				if err != nil {
					return err
				}
				results = append(results, r)
			}
			return a.emitKeyResults(results)
		},
	}
	f := cmd.Flags()
	f.StringVar(&name, "name", "", "friendly name")
	f.StringSliceVar(&tags, "tag", nil, "tags (repeatable)")
	f.StringVar(&comment, "comment", "", "free-text comment")
	f.StringVar(&passwordFile, "password-file", "", "password for encrypted keys")
	f.BoolVarP(&yes, "yes", "y", false, "store private key material without asking")
	return cmd
}

// confirmPrivateImport implements the import protection prompt (Roadmap §35).
func (a *app) confirmPrivateImport(n int, yes bool) error {
	if yes {
		return nil
	}
	what := "private key material"
	if n > 1 {
		what = fmt.Sprintf("%d private keys", n)
	}
	fmt.Fprintf(a.stderr, "This file contains %s.\n\n", what)
	return a.confirm("Store it inside the encrypted SSLKnife vault?", false)
}

func (a *app) emitKeyResults(results []inventory.KeyResult) error {
	var views []keyView
	for _, r := range results {
		views = append(views, toKeyView(r.Key))
	}
	return a.out.Emit(views, func(w io.Writer) error {
		for _, r := range results {
			state := "stored"
			switch {
			case r.Upgraded:
				state = "added private key to existing"
			case !r.Created:
				state = "already stored"
			}
			fmt.Fprintf(w, "%s %s key %s", state, r.Key.Description, r.Key.ID)
			if r.Key.Name != "" {
				fmt.Fprintf(w, " (%s)", r.Key.Name)
			}
			if r.LinkedCerts > 0 {
				fmt.Fprintf(w, ", linked to %d certificate(s)", r.LinkedCerts)
			}
			fmt.Fprintln(w)
		}
		return nil
	})
}

func newKeyListCmd(a *app) *cobra.Command {
	var query string
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List stored keys",
		Example: `  sslknife key list
  sslknife key list --filter 'tag:production' --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			inv, err := a.inventory(cmd.Context())
			if err != nil {
				return err
			}
			res, err := inv.Search(cmd.Context(), strings.TrimSpace("type:key "+query))
			if err != nil {
				return usageError{err}
			}
			views := []keyView{}
			for _, k := range res.Keys {
				views = append(views, toKeyView(k))
			}
			return a.out.Emit(views, func(w io.Writer) error {
				if len(views) == 0 {
					fmt.Fprintln(w, "No keys stored.")
					return nil
				}
				return a.renderKeyTable(w, views)
			})
		},
	}
	cmd.Flags().StringVar(&query, "filter", "", "search query (see 'sslknife search --help')")
	return cmd
}

func (a *app) getKey(ctx context.Context, ref string) (*inventory.Service, *database.Key, error) {
	inv, err := a.inventory(ctx)
	if err != nil {
		return nil, nil, err
	}
	k, err := inv.DB.GetKey(ctx, ref)
	if err != nil {
		return nil, nil, mapLookupErr(err, ref)
	}
	return inv, k, nil
}

func newKeyShowCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:               "show <id|name>",
		Short:             "Show a stored key's metadata",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: a.completeKeys,
		RunE: func(cmd *cobra.Command, args []string) error {
			inv, k, err := a.getKey(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			v := toKeyView(k)
			certs, err := inv.DB.QueryCertificates(cmd.Context(), "c.key_id = ?", []any{k.ID}, "")
			if err != nil {
				return err
			}
			for _, c := range certs {
				v.Certificates = append(v.Certificates, c.ID)
			}
			return a.out.Emit(v, func(w io.Writer) error {
				kv := output.NewKV(a.out.Style)
				kv.Add("ID", v.ID).Add("Name", v.Name).Add("Algorithm", v.Description).
					Addf("Private key", "%v", v.HasPrivate).Add("SPKI SHA-256", v.SPKISHA256).Add("SSH SHA256", v.SSHFingerprint).
					Add("Source", v.Source).Add("Comment", v.Comment).Add("Tags", strings.Join(v.Tags, ", ")).
					Add("Imported", v.ImportedAt.Format(time.RFC3339))
				var cl []string
				for _, c := range certs {
					cl = append(cl, c.ID[:8]+"  "+c.SubjectCN+"  expires "+c.NotAfter.Format(time.DateOnly))
				}
				kv.List("Certificates", cl)
				return kv.Render(w)
			})
		},
	}
}

func newKeyExportCmd(a *app) *cobra.Command {
	var out, passwordFile, keyFormat string
	var encrypt, toStdout, showSecret, public, force bool
	cmd := &cobra.Command{
		Use:   "export <id|name>",
		Short: "Export a stored key to a file",
		Long: `Write a stored private key as PKCS#8 PEM to a file with mode 0600.

Private keys are never written to the terminal unless both --stdout and
--show-secret are given. Use --public to export only the public key.`,
		Example: `  sslknife key export api-prod -o api.key
  sslknife key export api-prod -o api.key --encrypt
  sslknife key export api-prod --public
  sslknife key export api-prod --stdout --show-secret | kubectl create secret ...`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: a.completeKeys,
		RunE: func(cmd *cobra.Command, args []string) error {
			inv, k, err := a.getKey(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if public {
				pub, err := inv.PublicKey(k)
				if err != nil {
					return err
				}
				data, err := keys.MarshalPublicKeyPEM(pub)
				if err != nil {
					return err
				}
				if out != "" {
					return writeNewFile(out, data, 0o644, force)
				}
				_, err = a.stdout.Write(data)
				return err
			}
			if toStdout != showSecret {
				return usagef("printing a private key requires both --stdout and --show-secret")
			}
			if !toStdout && out == "" {
				out = keyFileName(k)
			}
			if !k.HasPrivate() {
				return exitcode.New(exitcode.NotFound, "key %s has no private material stored (use --public)", k.ID)
			}
			priv, err := inv.PrivateKey(cmd.Context(), k)
			if err != nil {
				return err
			}
			var pw []byte
			if encrypt {
				if pw, err = a.newSecretPassword(passwordFile); err != nil {
					return err
				}
				defer skcrypto.Zero(pw)
			}
			target, err := converter.ParseTarget(keyFormat)
			if err != nil || (target != converter.FormatPKCS8 && target != converter.FormatPKCS1 && target != converter.FormatSEC1 && target != converter.FormatOpenSSH) {
				return usagef("--key-format must be pkcs8, pkcs1, sec1 or openssh")
			}
			res, err := converter.Encode(&converter.Bundle{Objects: []converter.Object{{Kind: converter.KindPrivateKey, Key: priv, Comment: k.Name}}},
				target, converter.EncodeOptions{Password: pw})
			if err != nil {
				if errors.Is(err, converter.ErrImpossible) {
					return exitcode.With(exitcode.Unsupported, err)
				}
				return err
			}
			data := res.Data
			defer skcrypto.Zero(data)
			a.log.Info("private key exported", "key_id", k.ID, "stdout", toStdout)
			if toStdout {
				_, err = a.stdout.Write(data)
				return err
			}
			if err := writeNewFile(out, data, 0o600, force); err != nil {
				return err
			}
			a.out.Infof("Private key written to %s (mode 0600%s)", out, map[bool]string{true: ", encrypted", false: ""}[encrypt])
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&out, "out", "o", "", "output file (default <name>.key)")
	f.BoolVar(&encrypt, "encrypt", false, "encrypt with a password (PBES2 AES-256)")
	f.StringVar(&passwordFile, "password-file", "", "read the encryption password from a file")
	f.BoolVar(&toStdout, "stdout", false, "write to standard output (requires --show-secret)")
	f.BoolVar(&showSecret, "show-secret", false, "confirm that secret material may be printed")
	f.BoolVar(&public, "public", false, "export the public key only")
	f.StringVar(&keyFormat, "key-format", "pkcs8", "private key format: pkcs8, pkcs1 (RSA), sec1 (EC), openssh")
	f.BoolVar(&force, "force", false, "overwrite the output file")
	return cmd
}

func keyFileName(k *database.Key) string {
	base := k.Name
	if base == "" {
		base = k.ID
	}
	return sanitizeFileName(base) + ".key"
}

func sanitizeFileName(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		case r == '*':
			return '_'
		}
		return '-'
	}, s)
	s = strings.Trim(s, ".-")
	if s == "" {
		return "output"
	}
	return s
}

func newKeyPublicCmd(a *app) *cobra.Command {
	var sshFormat bool
	cmd := &cobra.Command{
		Use:   "public <file|id>",
		Short: "Print the public key of a private key, certificate or stored key",
		Example: `  sslknife key public server.key
  sslknife key public server.crt
  sslknife key public ~/.ssh/id_ed25519 --ssh`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pub, err := a.resolvePublicKey(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if sshFormat {
				sp, err := ssh.NewPublicKey(pub)
				if err != nil {
					return exitcode.New(exitcode.Unsupported, "this key type cannot be represented as an SSH key: %v", err)
				}
				_, err = a.stdout.Write(ssh.MarshalAuthorizedKey(sp))
				return err
			}
			data, err := keys.MarshalPublicKeyPEM(pub)
			if err != nil {
				return err
			}
			_, err = a.stdout.Write(data)
			return err
		},
	}
	cmd.Flags().BoolVar(&sshFormat, "ssh", false, "print in OpenSSH authorized_keys format")
	return cmd
}

// resolvePublicKey finds a public key in a file (private key, public key,
// certificate or CSR) or in the inventory (key or certificate reference).
func (a *app) resolvePublicKey(ctx context.Context, arg string) (crypto.PublicKey, error) {
	pub, _, err := a.publicKeyOf(ctx, arg)
	return pub, err
}

// publicKeyOf returns the public key of arg and whether arg held a private key.
func (a *app) publicKeyOf(ctx context.Context, arg string) (crypto.PublicKey, string, error) {
	if arg == "-" || fileExists(arg) {
		data, err := a.readInput(arg)
		if err != nil {
			return nil, "", err
		}
		if pk, err := keys.ParsePrivateKey(data, a.keyPassword("", displayName(arg))); err == nil {
			return pk.Public(), "private key", nil
		} else if !isNoKey(err) {
			return nil, "", exitcode.With(exitcode.Auth, err)
		}
		if certs, err := certificate.Parse(data); err == nil {
			return certs[0].PublicKey, "certificate", nil
		}
		if csr, err := certificate.ParseCSR(data); err == nil {
			return csr.PublicKey, "certificate request", nil
		}
		if p, err := keys.ParsePublicKey(data); err == nil {
			return p.Key, "public key", nil
		}
		return nil, "", exitcode.New(exitcode.Usage, "%s: no key, certificate or request found", displayName(arg))
	}
	if !database.Exists(a.cfg.Database.Path) {
		return nil, "", exitcode.New(exitcode.NotFound, "%s: no such file", arg)
	}
	inv, err := a.inventory(ctx)
	if err != nil {
		return nil, "", err
	}
	if k, err := inv.DB.GetKey(ctx, arg); err == nil {
		pub, err := inv.PublicKey(k)
		kind := "stored public key"
		if k.HasPrivate() {
			kind = "stored private key"
		}
		return pub, kind, err
	}
	_, c, err := inv.Certificate(ctx, arg)
	if err != nil {
		return nil, "", mapLookupErr(err, arg)
	}
	return c.PublicKey, "stored certificate", nil
}

type matchView struct {
	A     string `json:"a"`
	AKind string `json:"a_kind"`
	B     string `json:"b"`
	BKind string `json:"b_kind"`
	Match bool   `json:"match"`
	SPKIA string `json:"a_spki_sha256"`
	SPKIB string `json:"b_spki_sha256"`
}

func newKeyMatchCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "match <key> <certificate|csr|key>",
		Short: "Check whether a private key belongs to a certificate",
		Long: `Compare the public keys of two objects: private keys, public keys,
certificates, CSRs, or stored keys/certificates, in any order.

Exit status is 0 when they match and 5 when they do not.`,
		Example: `  sslknife key match server.key server.crt
  sslknife key match api-prod-key api-prod`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			pa, ka, err := a.publicKeyOf(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			pb, kb, err := a.publicKeyOf(cmd.Context(), args[1])
			if err != nil {
				return err
			}
			v := matchView{A: args[0], AKind: ka, B: args[1], BKind: kb, Match: keys.Equal(pa, pb),
				SPKIA: keys.Describe(pa).SPKISHA256, SPKIB: keys.Describe(pb).SPKISHA256}
			err = a.out.Emit(v, func(w io.Writer) error {
				if v.Match {
					fmt.Fprintf(w, "%s  %s (%s) and %s (%s) share the same public key\n", a.out.Style.Level("MATCH"), v.A, v.AKind, v.B, v.BKind)
				} else {
					fmt.Fprintf(w, "%s  %s (%s) and %s (%s) have different keys\n", a.out.Style.Level("MISMATCH"), v.A, v.AKind, v.B, v.BKind)
				}
				fmt.Fprintf(w, "  %s  %s\n  %s  %s\n", a.out.Style.Dim("SPKI A"), v.SPKIA, a.out.Style.Dim("SPKI B"), v.SPKIB)
				return nil
			})
			if err == nil && !v.Match {
				return exitcode.Silent(exitcode.CheckFailed)
			}
			return err
		},
	}
}

func newKeyDeleteCmd(a *app) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:               "delete <id|name>",
		Aliases:           []string{"rm"},
		Short:             "Delete a stored key and its private material",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: a.completeKeys,
		RunE: func(cmd *cobra.Command, args []string) error {
			inv, k, err := a.getKey(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if err := a.confirm(fmt.Sprintf("Delete %s key %s permanently?", k.Description, k.ID), yes); err != nil {
				return err
			}
			if err := inv.DB.DeleteKey(cmd.Context(), k.ID); err != nil {
				return err
			}
			a.out.Infof("Deleted key %s", k.ID)
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask for confirmation")
	return cmd
}

func newKeyTagCmd(a *app, add bool) *cobra.Command {
	use, short := "tag <id|name> <tag>...", "Add tags to a stored key"
	if !add {
		use, short = "untag <id|name> <tag>...", "Remove tags from a stored key"
	}
	return &cobra.Command{
		Use:               use,
		Short:             short,
		Args:              cobra.MinimumNArgs(2),
		ValidArgsFunction: a.completeKeys,
		RunE: func(cmd *cobra.Command, args []string) error {
			inv, k, err := a.getKey(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if add {
				err = inv.DB.AddTags(cmd.Context(), "key", k.ID, args[1:])
			} else {
				err = inv.DB.RemoveTags(cmd.Context(), "key", k.ID, args[1:])
			}
			if err != nil {
				return usageError{err}
			}
			return nil
		},
	}
}

func newKeyRenameCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:               "rename <id|name> <new-name>",
		Short:             "Change a stored key's friendly name",
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: a.completeKeys,
		RunE: func(cmd *cobra.Command, args []string) error {
			inv, k, err := a.getKey(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return inv.DB.UpdateKeyMeta(cmd.Context(), k.ID, &args[1], nil)
		},
	}
}

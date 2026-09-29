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

// EnvOutPassword supplies the password for keystores and keys written by convert.
const EnvOutPassword = "SSLKNIFE_OUT_PASSWORD"

type convertOpts struct {
	to, out, passwordFile, outPasswordFile, alias string
	stdout, showSecret, der, certsOnly, keysOnly  bool
	encrypt, force                                bool
}

// decodeInputs reads and merges all inputs.
func (a *app) decodeInputs(args []string, passwordFile string) (*converter.Bundle, error) {
	var b *converter.Bundle
	for _, arg := range args {
		data, err := a.readInput(arg)
		if err != nil {
			return nil, err
		}
		one, err := converter.Decode(data, converter.DecodeOptions{
			Password:    a.keyPassword(passwordFile, displayName(arg)),
			KeyPassword: a.keyPassword("", "the key entry in "+displayName(arg)),
		})
		if err != nil {
			switch {
			case errors.Is(err, converter.ErrUnsupported):
				return nil, exitcode.With(exitcode.Unsupported, fmt.Errorf("%s: %w", displayName(arg), err))
			case errors.Is(err, keys.ErrIncorrectPassword), errors.Is(err, keys.ErrPasswordRequired):
				return nil, exitcode.With(exitcode.Auth, fmt.Errorf("%s: %w", displayName(arg), err))
			}
			return nil, fmt.Errorf("%s: %w", displayName(arg), err)
		}
		for _, n := range one.Notes {
			a.out.Warnf("%s: %s", displayName(arg), n)
		}
		if b == nil {
			b = one
		} else {
			b.Merge(one)
		}
	}
	return b, nil
}

// outPassword returns the password for protected outputs.
func (a *app) outPassword(file string, what string) ([]byte, error) {
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		return []byte(strings.TrimRight(string(data), "\r\n")), nil
	}
	if p := os.Getenv(EnvOutPassword); p != "" {
		return []byte(p), nil
	}
	if !a.prompt.Interactive() {
		return nil, exitcode.New(exitcode.Usage, "%s needs a password: use --out-password-file or %s", what, EnvOutPassword)
	}
	return a.prompt.NewPassword("Password for "+what, 6)
}

func newConvertCmd(a *app) *cobra.Command {
	var o convertOpts
	var targets []string
	for _, t := range converter.Targets {
		targets = append(targets, fmt.Sprintf("  %-8s %s", t.Name, t.Description))
	}
	cmd := &cobra.Command{
		Use:   "convert <input>... --to <format>",
		Short: "Convert certificates, keys and keystores between formats",
		Long: `Convert between certificate, key and keystore formats. The input format is
detected from the content (PEM, DER, PKCS#7, PKCS#8, PKCS#1, SEC1, PKCS#12,
JKS, OpenSSH, authorized_keys, RFC 4716). Several inputs are merged, so a
certificate and a key can be combined into one PKCS#12 or JKS file.

Target formats:
` + strings.Join(targets, "\n") + `

When the target cannot represent the input (DER with several objects, a
private key in a certificate bundle, an EC key as PKCS#1, ...) the command
fails with exit status 7 and explains why; nothing is dropped silently.

Output goes to a file (default: input name with a new extension; mode 0600
when it contains private keys). --stdout prints non-secret results; secret
results also need --show-secret.

Passwords: input passwords come from --password-file, $SSLKNIFE_KEY_PASSWORD
or a prompt; output passwords from --out-password-file, $SSLKNIFE_OUT_PASSWORD
or a prompt. They are never accepted as command-line values.`,
		Example: `  sslknife convert server.der --to pem --stdout
  sslknife convert server.p12 --to pem -o server.pem
  sslknife convert cert.pem key.pem chain.pem --to pkcs12 -o bundle.p12
  sslknife convert keystore.jks --to pkcs12
  sslknife convert truststore.jks --to pem --certs-only --stdout
  sslknife convert id_ed25519 --to ssh --stdout`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if o.to == "" {
				return usagef("--to is required")
			}
			to, err := converter.ParseTarget(o.to)
			if err != nil {
				return usageError{err}
			}
			b, err := a.decodeInputs(args, o.passwordFile)
			if err != nil {
				return err
			}
			switch {
			case o.certsOnly && o.keysOnly:
				return usagef("--certs-only and --keys-only are mutually exclusive")
			case o.certsOnly:
				b = b.Filter(converter.KindCertificate)
			case o.keysOnly:
				b = b.Filter(converter.KindPrivateKey, converter.KindPublicKey)
			}
			enc := converter.EncodeOptions{DER: o.der, Alias: o.alias}
			needsPW := to == converter.FormatPKCS12 || to == converter.FormatJKS
			if needsPW || o.encrypt {
				if o.encrypt && to != converter.FormatPEM && to != converter.FormatPKCS8 && to != converter.FormatOpenSSH && !needsPW {
					return usagef("--encrypt applies to pem, pkcs8 and openssh outputs")
				}
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
			defer skcrypto.Zero(res.Data)
			for _, n := range res.Notes {
				a.out.Warnf("%s", n)
			}
			return a.writeOutput(res, args[0], o)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&o.to, "to", "t", "", "target format")
	f.StringVarP(&o.out, "out", "o", "", "output file")
	f.BoolVar(&o.stdout, "stdout", false, "write to standard output")
	f.BoolVar(&o.showSecret, "show-secret", false, "allow private key material on standard output")
	f.BoolVar(&o.der, "der", false, "binary DER output for pkcs1/pkcs8/sec1/spki/pkcs7")
	f.BoolVar(&o.certsOnly, "certs-only", false, "convert only the certificates")
	f.BoolVar(&o.keysOnly, "keys-only", false, "convert only the keys")
	f.BoolVar(&o.encrypt, "encrypt", false, "encrypt private keys in pem/pkcs8/openssh output")
	f.StringVar(&o.alias, "alias", "", "alias for the key entry in a JKS output")
	f.StringVar(&o.passwordFile, "password-file", "", "password for encrypted inputs")
	f.StringVar(&o.outPasswordFile, "out-password-file", "", "password for the output")
	f.BoolVar(&o.force, "force", false, "overwrite the output file")
	_ = cmd.RegisterFlagCompletionFunc("to", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		var out []string
		for _, t := range converter.Targets {
			out = append(out, t.Name+"\t"+t.Description)
		}
		return out, cobra.ShellCompDirectiveNoFileComp
	})
	return cmd
}

func (a *app) writeOutput(res *converter.Output, firstInput string, o convertOpts) error {
	if o.stdout {
		if o.out != "" {
			return usagef("--stdout and --out are mutually exclusive")
		}
		if res.Secret && !o.showSecret {
			return usagef("the output contains private key material; add --show-secret to print it, or write a file with --out")
		}
		_, err := a.stdout.Write(res.Data)
		return err
	}
	path := o.out
	if path == "" {
		base := "converted"
		if firstInput != "-" {
			base = strings.TrimSuffix(filepath.Base(firstInput), filepath.Ext(firstInput))
		}
		path = base + "." + res.Extension
		if abs, _ := filepath.Abs(path); firstInput != "-" {
			if in, _ := filepath.Abs(firstInput); in == abs {
				path = base + ".converted." + res.Extension
			}
		}
	}
	perm := os.FileMode(0o644)
	if res.Secret {
		perm = 0o600
	}
	if err := writeNewFile(path, res.Data, perm, o.force); err != nil {
		return err
	}
	a.out.Infof("Wrote %s (%d bytes%s)", path, len(res.Data), map[bool]string{true: ", contains private keys, mode 0600", false: ""}[res.Secret])
	return nil
}

type fileInspectView struct {
	File      string             `json:"file"`
	Format    string             `json:"format"`
	FormatID  converter.Format   `json:"format_id"`
	Encrypted bool               `json:"password_protected"`
	Contents  converter.Contents `json:"contents"`
	Entries   []entryView        `json:"entries"`
	Error     string             `json:"error,omitempty"`
}

type entryView struct {
	Kind        converter.Kind `json:"kind"`
	Alias       string         `json:"alias,omitempty"`
	Subject     string         `json:"subject,omitempty"`
	Issuer      string         `json:"issuer,omitempty"`
	NotAfter    *time.Time     `json:"not_after,omitempty"`
	Algorithm   string         `json:"algorithm"`
	SPKISHA256  string         `json:"spki_sha256"`
	SHA256      string         `json:"sha256,omitempty"`
	Role        string         `json:"role,omitempty"` // leaf, intermediate, root
	Trusted     bool           `json:"trusted_entry,omitempty"`
	Comment     string         `json:"comment,omitempty"`
	MatchesCert bool           `json:"matches_certificate,omitempty"`
}

func entries(b *converter.Bundle) []entryView {
	var out []entryView
	certs := b.Certificates()
	for _, o := range b.Objects {
		pk := keys.Describe(o.PublicKey())
		e := entryView{Kind: o.Kind, Alias: o.Alias, Algorithm: pk.Description, SPKISHA256: pk.SPKISHA256, Trusted: o.Trusted, Comment: o.Comment}
		switch o.Kind {
		case converter.KindCertificate:
			na := o.Cert.NotAfter.UTC()
			e.Subject, e.Issuer, e.NotAfter = o.Cert.Subject.String(), o.Cert.Issuer.String(), &na
			e.SHA256 = certificate.Fingerprint(o.Cert).SHA256
			switch {
			case o.Cert.IsCA && certificate.IsSelfSigned(o.Cert):
				e.Role = "root"
			case o.Cert.IsCA:
				e.Role = "intermediate"
			default:
				e.Role = "leaf"
			}
		case converter.KindCSR:
			e.Subject = o.CSR.Subject.String()
		case converter.KindPrivateKey:
			for _, c := range certs {
				if keys.Equal(c.PublicKey, o.PublicKey()) {
					e.MatchesCert = true
				}
			}
		}
		out = append(out, e)
	}
	return out
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func (a *app) renderFileInspect(w io.Writer, v fileInspectView) error {
	st := a.out.Style
	kv := output.NewKV(st)
	kv.Add("File", v.File).Add("Detected format", v.Format)
	var contains []string
	c := v.Contents
	for _, p := range []struct {
		n    int
		word string
	}{{c.PrivateKeys, "private key"}, {c.Leaf, "leaf certificate"}, {c.Intermediates, "intermediate certificate"},
		{c.Roots, "root certificate"}, {c.PublicKeys, "public key"}, {c.CSRs, "certificate request"}} {
		if p.n > 0 {
			contains = append(contains, plural(p.n, p.word))
		}
	}
	if v.Error != "" {
		contains = []string{st.Yellow(v.Error)}
	}
	kv.List("Contains", contains)
	kv.Add("Password protected", yesNo(v.Encrypted))
	if err := kv.Render(w); err != nil {
		return err
	}
	if len(v.Entries) == 0 {
		return nil
	}
	fmt.Fprintln(w)
	t := output.NewTable("#", "KIND", "ALIAS", "SUBJECT", "ALGORITHM", "EXPIRES")
	for i, e := range v.Entries {
		kind := strings.ReplaceAll(string(e.Kind), "_", " ")
		if e.Role != "" {
			kind = e.Role + " cert"
		}
		if e.Kind == converter.KindPrivateKey && e.MatchesCert {
			kind += st.Dim(" (matches cert)")
		}
		exp := ""
		if e.NotAfter != nil {
			exp = e.NotAfter.Format(time.DateOnly)
		}
		t.Row(fmt.Sprint(i+1), kind, e.Alias, truncate(shortDN(e.Subject), 40), e.Algorithm, exp)
	}
	return t.Render(w, st)
}

func newInspectCmd(a *app) *cobra.Command {
	var passwordFile string
	cmd := &cobra.Command{
		Use:   "inspect <file|->",
		Short: "Detect a file's format and list what it contains",
		Long: `Identify any certificate, key or keystore file by its content and list the
objects inside, without printing key material. Password-protected containers
(PKCS#12, JKS, encrypted keys) are opened when a password is available;
otherwise only the format is reported.`,
		Example: `  sslknife inspect mycert
  sslknife inspect keystore.jks --json
  SSLKNIFE_KEY_PASSWORD=changeit sslknife inspect bundle.p12`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := a.readInput(args[0])
			if err != nil {
				return err
			}
			f := converter.Detect(data)
			v := fileInspectView{File: displayName(args[0]), Format: f.Description(), FormatID: f}
			pwf := func() ([]byte, error) {
				if passwordFile == "" && os.Getenv(EnvKeyPassword) == "" && !a.prompt.Interactive() {
					return nil, keys.ErrPasswordRequired
				}
				return a.keyPassword(passwordFile, displayName(args[0]))()
			}
			b, err := converter.Decode(data, converter.DecodeOptions{Password: pwf})
			switch {
			case err == nil:
				v.Encrypted = b.Encrypted
				v.Contents = b.Summarize()
				v.Entries = entries(b)
			case errors.Is(err, keys.ErrPasswordRequired):
				v.Encrypted, v.Error = true, "contents need a password (use --password-file or "+EnvKeyPassword+")"
			case errors.Is(err, keys.ErrIncorrectPassword):
				return exitcode.With(exitcode.Auth, err)
			case errors.Is(err, converter.ErrUnsupported):
				v.Error = err.Error()
			default:
				return err
			}
			if b != nil && b.Format != "" {
				v.Format, v.FormatID = b.Format.Description(), b.Format
			}
			if v.FormatID == converter.FormatUnknown {
				_ = a.out.Emit(v, func(w io.Writer) error { return a.renderFileInspect(w, v) })
				return exitcode.New(exitcode.Unsupported, "%s: format not recognised", displayName(args[0]))
			}
			return a.out.Emit(v, func(w io.Writer) error { return a.renderFileInspect(w, v) })
		},
	}
	cmd.Flags().StringVar(&passwordFile, "password-file", "", "password for protected files")
	return cmd
}

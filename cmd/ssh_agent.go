package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/matusso/sslknife/internal/config"
	skcrypto "github.com/matusso/sslknife/internal/crypto"
	"github.com/matusso/sslknife/internal/database"
	"github.com/matusso/sslknife/internal/exitcode"
	"github.com/matusso/sslknife/internal/inventory"
	"github.com/matusso/sslknife/internal/output"
	"github.com/matusso/sslknife/internal/sshagent"
	"github.com/matusso/sslknife/internal/sshkeys"
)

func newSSHAgentCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Load stored SSH keys into ssh-agent, or run a built-in agent",
		Long: `Make SSH keys from the vault usable by ssh without writing them to disk.

'add', 'list' and 'remove' talk to the agent at $SSH_AUTH_SOCK (or --socket),
such as OpenSSH's ssh-agent. 'serve' runs an agent inside sslknife that holds
only the selected keys, for one command or until it is stopped.

Keys are chosen by vault ID, name or fingerprint, by --tag, or with --all;
private key files work too. Passphrase-protected keys are decrypted with
--passphrase-file, $SSLKNIFE_SSH_PASSPHRASE or a prompt, and a passphrase
that opened one key is tried on the next before asking again.`,
	}
	cmd.AddCommand(newSSHAgentAddCmd(a), newSSHAgentListCmd(a), newSSHAgentRemoveCmd(a), newSSHAgentServeCmd(a))
	return cmd
}

// agentSelection is the key selection shared by 'agent add' and 'agent serve'.
type agentSelection struct {
	all            bool
	tags           []string
	certs          []string
	passphraseFile string
	lifetime       string
}

func (s *agentSelection) register(f interface {
	BoolVar(*bool, string, bool, string)
	StringSliceVar(*[]string, string, []string, string)
	StringVar(*string, string, string, string)
}) {
	f.BoolVar(&s.all, "all", false, "every stored SSH key that has a private key")
	f.StringSliceVar(&s.tags, "tag", nil, "stored SSH keys with this tag (repeatable)")
	f.StringSliceVar(&s.certs, "cert", nil, "OpenSSH certificate to load with its key (repeatable)")
	f.StringVar(&s.passphraseFile, "passphrase-file", "", "read key passphrases from a file")
	f.StringVar(&s.lifetime, "lifetime", "", "remove the keys from the agent after this long, e.g. 8h, 1d")
}

func (s *agentSelection) lifetimeSecs() (uint32, error) {
	if s.lifetime == "" {
		return 0, nil
	}
	d, err := config.ParseDuration(s.lifetime)
	if err != nil {
		return 0, usageError{err}
	}
	if d < time.Second || d.Seconds() > math.MaxUint32 {
		return 0, usagef("--lifetime must be between 1s and %d seconds", uint32(math.MaxUint32))
	}
	return uint32(d / time.Second), nil
}

// agentKey is a decrypted key ready to hand to an agent.
type agentKey struct {
	item    sshkeys.Item
	cert    *ssh.Certificate
	label   string
	comment string
}

func (k agentKey) added(lifetime uint32, confirm bool) []agent.AddedKey {
	out := []agent.AddedKey{{PrivateKey: k.item.Private, Comment: k.comment, LifetimeSecs: lifetime, ConfirmBeforeUse: confirm}}
	if k.cert != nil {
		c := out[0]
		c.Certificate = k.cert
		out = append(out, c)
	}
	return out
}

// loadAgentKeys resolves refs (files or stored keys), tags and --all into
// decrypted keys, deduplicated by fingerprint.
func (a *app) loadAgentKeys(ctx context.Context, refs []string, sel *agentSelection) ([]agentKey, error) {
	if len(refs) == 0 && !sel.all && len(sel.tags) == 0 {
		return nil, usagef("name the keys to load, or use --tag or --all")
	}
	var keys []agentKey
	seen := map[string]bool{}
	var passphrases [][]byte
	defer func() {
		for _, p := range passphrases {
			skcrypto.Zero(p)
		}
	}()
	addKey := func(data []byte, label, comment, certFile string) error {
		items, err := sshkeys.Parse(data)
		if err != nil || items[0].Kind != sshkeys.KindPrivate {
			return exitcode.New(exitcode.Usage, "%s is not an SSH private key", label)
		}
		it := items[0]
		if it.Private == nil {
			if passphrases, err = a.decryptAgentKey(&it, label, sel.passphraseFile, passphrases); err != nil {
				return err
			}
		}
		fp := ssh.FingerprintSHA256(it.Public)
		if seen[fp] {
			return nil
		}
		seen[fp] = true
		k := agentKey{item: it, label: label, comment: firstNonEmpty(comment, it.Comment, label)}
		if certFile != "" {
			if k.cert, err = readSSHCert(certFile); err != nil {
				return err
			}
		}
		keys = append(keys, k)
		return nil
	}

	var stored []*database.SSHKey
	if sel.all || len(sel.tags) > 0 {
		v, err := a.requireVault(ctx)
		if err != nil {
			return nil, err
		}
		ks, err := v.db.QuerySSHKeys(ctx, "", nil)
		if err != nil {
			return nil, err
		}
		for _, k := range ks {
			if k.HasPrivate() && (sel.all || slices.ContainsFunc(sel.tags, func(t string) bool { return slices.Contains(k.Tags, t) })) {
				stored = append(stored, k)
			}
		}
		if len(stored) == 0 && len(refs) == 0 {
			return nil, exitcode.New(exitcode.NotFound, "no stored SSH keys with a private key match")
		}
	}
	for _, ref := range refs {
		if p := config.ExpandHome(ref); fileExists(p) {
			data, err := a.readInput(p)
			if err != nil {
				return nil, err
			}
			// Like ssh-add, pick up <key>-cert.pub next to the key.
			cert := p + "-cert.pub"
			if !fileExists(cert) {
				cert = ""
			}
			err = addKey(data, displayName(ref), "", cert)
			skcrypto.Zero(data)
			if err != nil {
				return nil, err
			}
			continue
		}
		_, k, err := a.getSSHKey(ctx, ref)
		if err != nil {
			return nil, err
		}
		if !k.HasPrivate() {
			return nil, exitcode.New(exitcode.NotFound, "SSH key %s has no private key stored (it was imported with --public-only or from a .pub file)", ref)
		}
		stored = append(stored, k)
	}
	for _, k := range stored {
		data, err := a.vault.db.SSHPrivateKey(ctx, k)
		if err != nil {
			return nil, exitcode.With(exitcode.NotFound, err)
		}
		err = addKey(data, firstNonEmpty(k.Name, k.ID[:8]), firstNonEmpty(k.Comment, k.Name), "")
		skcrypto.Zero(data)
		if err != nil {
			return nil, err
		}
	}
	return keys, attachCerts(keys, sel.certs)
}

// decryptAgentKey tries passphrases that opened earlier keys, then asks.
func (a *app) decryptAgentKey(it *sshkeys.Item, label, passphraseFile string, known [][]byte) ([][]byte, error) {
	for _, p := range known {
		if it.Decrypt(p) == nil {
			return known, nil
		}
	}
	pass, err := a.sshPassphrase(passphraseFile, label)
	if err != nil {
		return known, err
	}
	if err := it.Decrypt(pass); err != nil {
		skcrypto.Zero(pass)
		return known, exitcode.New(exitcode.Auth, "%s: %v", label, err)
	}
	return append(known, pass), nil
}

func readSSHCert(file string) (*ssh.Certificate, error) {
	data, err := os.ReadFile(config.ExpandHome(file))
	if err != nil {
		return nil, err
	}
	items, err := sshkeys.Parse(data)
	if err != nil || items[0].Cert == nil {
		return nil, exitcode.New(exitcode.Usage, "%s is not an OpenSSH certificate", file)
	}
	return items[0].Cert, nil
}

// attachCerts pairs each --cert with the loaded key it certifies.
func attachCerts(keys []agentKey, files []string) error {
	for _, f := range files {
		c, err := readSSHCert(f)
		if err != nil {
			return err
		}
		fp := ssh.FingerprintSHA256(c.Key)
		i := slices.IndexFunc(keys, func(k agentKey) bool { return ssh.FingerprintSHA256(k.item.Public) == fp })
		if i < 0 {
			return exitcode.New(exitcode.Usage, "%s certifies %s, which is not among the selected keys", f, fp)
		}
		keys[i].cert = c
	}
	return nil
}

// agentIdentity describes one identity held by an agent.
type agentIdentity struct {
	Type        string `json:"type"`
	Bits        int    `json:"bits"`
	Fingerprint string `json:"fingerprint_sha256"`
	Comment     string `json:"comment,omitempty"`
	Certificate bool   `json:"certificate"`
	Source      string `json:"source,omitempty"`
}

func identityOf(pub ssh.PublicKey, comment string) agentIdentity {
	it := sshkeys.Item{Kind: sshkeys.KindPublic, Public: pub}
	if c, ok := pub.(*ssh.Certificate); ok {
		it.Kind, it.Cert = sshkeys.KindCertificate, c
	}
	info := sshkeys.Describe(it)
	return agentIdentity{Type: info.Type, Bits: info.Bits, Fingerprint: info.FingerprintSHA256, Comment: comment, Certificate: it.Cert != nil}
}

func (a *app) renderIdentities(w io.Writer, ids []agentIdentity) error {
	st := a.out.Style
	t := output.NewTable("TYPE", "BITS", "FINGERPRINT", "COMMENT")
	for _, id := range ids {
		typ := id.Type
		if id.Certificate {
			typ += st.Dim(" (cert)")
		}
		t.Row(typ, fmt.Sprint(id.Bits), id.Fingerprint, truncate(id.Comment, 40))
	}
	return t.Render(w, st)
}

func newSSHAgentAddCmd(a *app) *cobra.Command {
	var sel agentSelection
	var socket string
	var confirm bool
	cmd := &cobra.Command{
		Use:   "add [<id|name|fingerprint|file>...]",
		Short: "Load stored SSH keys into the running ssh-agent (like ssh-add)",
		Long: `Decrypt the selected keys and hand them to the agent at $SSH_AUTH_SOCK or
--socket. The keys stay in the agent's memory only. A certificate named
<file>-cert.pub next to a key file is loaded with it, as ssh-add does; use
--cert for stored keys.`,
		Example: `  sslknife ssh agent add deploy-key
  sslknife ssh agent add --tag servers --lifetime 8h
  sslknife ssh agent add --all --confirm
  sslknife ssh agent add laptop --cert ~/.ssh/id_ed25519-cert.pub`,
		ValidArgsFunction: a.completeSSHKeys,
		RunE: func(cmd *cobra.Command, args []string) error {
			lifetime, err := sel.lifetimeSecs()
			if err != nil {
				return err
			}
			keys, err := a.loadAgentKeys(cmd.Context(), args, &sel)
			if err != nil {
				return err
			}
			c, err := sshagent.Dial(socket)
			if err != nil {
				return exitcode.With(exitcode.NotFound, err)
			}
			defer c.Close()
			var added []agentIdentity
			for _, k := range keys {
				for _, ak := range k.added(lifetime, confirm) {
					if err := c.Add(ak); err != nil {
						return fmt.Errorf("add %s to the agent: %w", k.label, err)
					}
					pub := k.item.Public
					if ak.Certificate != nil {
						pub = ak.Certificate
					}
					id := identityOf(pub, k.comment)
					id.Source = k.label
					added = append(added, id)
				}
			}
			return a.out.Emit(added, func(w io.Writer) error {
				for _, id := range added {
					what := "Identity"
					if id.Certificate {
						what = "Certificate"
					}
					fmt.Fprintf(w, "%s added: %s %s (%s)\n", what, id.Source, id.Fingerprint, id.Comment)
				}
				if lifetime > 0 {
					fmt.Fprintf(w, "Lifetime set to %s\n", time.Duration(lifetime)*time.Second)
				}
				return nil
			})
		},
	}
	f := cmd.Flags()
	sel.register(f)
	f.StringVar(&socket, "socket", "", "agent socket (default $SSH_AUTH_SOCK)")
	f.BoolVarP(&confirm, "confirm", "c", false, "require confirmation (ssh-askpass) each time a key is used")
	return cmd
}

func newSSHAgentListCmd(a *app) *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List the identities held by the agent (like ssh-add -l)",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := sshagent.Dial(socket)
			if err != nil {
				return exitcode.With(exitcode.NotFound, err)
			}
			defer c.Close()
			ks, err := c.List()
			if err != nil {
				return err
			}
			ids := []agentIdentity{}
			for _, k := range ks {
				pub, err := ssh.ParsePublicKey(k.Blob)
				if err != nil {
					continue
				}
				ids = append(ids, identityOf(pub, k.Comment))
			}
			return a.out.Emit(ids, func(w io.Writer) error {
				if len(ids) == 0 {
					fmt.Fprintln(w, "The agent has no identities.")
					return nil
				}
				return a.renderIdentities(w, ids)
			})
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", "agent socket (default $SSH_AUTH_SOCK)")
	return cmd
}

func newSSHAgentRemoveCmd(a *app) *cobra.Command {
	var socket string
	var all bool
	cmd := &cobra.Command{
		Use:     "remove [<id|name|fingerprint|file>...]",
		Aliases: []string{"rm", "delete"},
		Short:   "Remove identities from the agent (like ssh-add -d / -D)",
		Long: `Remove keys, and certificates of those keys, from the agent. A SHA256:
fingerprint is matched against the agent directly, without the vault.`,
		Example: `  sslknife ssh agent remove deploy-key
  sslknife ssh agent remove SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s
  sslknife ssh agent remove --all`,
		ValidArgsFunction: a.completeSSHKeys,
		RunE: func(cmd *cobra.Command, args []string) error {
			if all == (len(args) > 0) {
				return usagef("name the keys to remove, or use --all")
			}
			c, err := sshagent.Dial(socket)
			if err != nil {
				return exitcode.With(exitcode.NotFound, err)
			}
			defer c.Close()
			if all {
				if err := c.RemoveAll(); err != nil {
					return err
				}
				a.out.Infof("All identities removed.")
				return nil
			}
			want := map[string]string{}
			for _, ref := range args {
				fp, err := a.agentFingerprint(cmd.Context(), ref)
				if err != nil {
					return err
				}
				want[fp] = ref
			}
			ks, err := c.List()
			if err != nil {
				return err
			}
			removed := map[string]bool{}
			for _, k := range ks {
				pub, err := ssh.ParsePublicKey(k.Blob)
				if err != nil {
					continue
				}
				base := pub
				if cert, ok := pub.(*ssh.Certificate); ok {
					base = cert.Key
				}
				fp := ssh.FingerprintSHA256(base)
				if _, ok := want[fp]; !ok {
					continue
				}
				if err := c.Remove(pub); err != nil {
					return fmt.Errorf("remove %s: %w", fp, err)
				}
				removed[fp] = true
			}
			for fp, ref := range want {
				if !removed[fp] {
					return exitcode.New(exitcode.NotFound, "%s (%s) is not in the agent", ref, fp)
				}
				a.out.Infof("Identity removed: %s %s", ref, fp)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&socket, "socket", "", "agent socket (default $SSH_AUTH_SOCK)")
	f.BoolVar(&all, "all", false, "remove every identity from the agent")
	return cmd
}

// agentFingerprint resolves a fingerprint, key file or stored key reference.
func (a *app) agentFingerprint(ctx context.Context, ref string) (string, error) {
	if strings.HasPrefix(ref, "SHA256:") {
		return ref, nil
	}
	items, _, err := a.loadSSHItems(ctx, ref)
	if err != nil {
		return "", err
	}
	it := items[0]
	if it.Public == nil {
		return "", exitcode.New(exitcode.Usage, "%s does not include its public key; pass the .pub file or the fingerprint", ref)
	}
	if it.Cert != nil {
		return ssh.FingerprintSHA256(it.Cert.Key), nil
	}
	return ssh.FingerprintSHA256(it.Public), nil
}

func newSSHAgentServeCmd(a *app) *cobra.Command {
	var sel agentSelection
	var socket string
	cmd := &cobra.Command{
		Use:   "serve [<id|name|fingerprint|file>...] [-- <command> [args...]]",
		Short: "Run a built-in ssh-agent holding the selected keys",
		Long: `Start an SSH agent inside sslknife that holds the selected keys in memory.

With a command after --, the command runs with $SSH_AUTH_SOCK pointing at the
agent, and the agent stops when it exits (its exit status is returned).
Without one, the agent runs until interrupted (Ctrl-C or SIGTERM); point ssh at
it with SSH_AUTH_SOCK, or permanently in ~/.ssh/config with a fixed --socket:

  Host *.example.com
      IdentityAgent ~/.ssh/sslknife-agent.sock

The socket is created with mode 0600; by default it lives in a new private
temporary directory. Clients may add and remove keys while it runs; nothing
is written back to the vault.`,
		Example: `  sslknife ssh agent serve deploy-key -- ssh deploy@web01
  sslknife ssh agent serve --tag prod -- ansible-playbook site.yml
  sslknife ssh agent serve --all --socket ~/.ssh/sslknife-agent.sock --lifetime 8h`,
		ValidArgsFunction: a.completeSSHKeys,
		RunE: func(cmd *cobra.Command, args []string) error {
			refs, command := args, []string(nil)
			if n := cmd.ArgsLenAtDash(); n >= 0 {
				refs, command = args[:n], args[n:]
				if len(command) == 0 {
					return usagef("no command after --")
				}
			}
			lifetime, err := sel.lifetimeSecs()
			if err != nil {
				return err
			}
			keys, err := a.loadAgentKeys(cmd.Context(), refs, &sel)
			if err != nil {
				return err
			}
			kr := agent.NewKeyring()
			var ids []agentIdentity
			for _, k := range keys {
				for _, ak := range k.added(lifetime, false) {
					if err := kr.Add(ak); err != nil {
						return fmt.Errorf("load %s: %w", k.label, err)
					}
				}
				ids = append(ids, identityOf(k.item.Public, k.comment))
			}
			l, path, cleanup, err := sshagent.Listen(config.ExpandHome(socket))
			if err != nil {
				return err
			}
			defer cleanup()

			if command != nil {
				return a.runWithAgent(l, kr, path, command)
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGTERM)
			defer stop()
			err = a.out.Emit(map[string]any{"socket": path, "pid": os.Getpid(), "keys": ids}, func(w io.Writer) error {
				fmt.Fprintf(w, "Serving %d key(s) on %s (Ctrl-C to stop). In another shell:\n  %s\n", len(ids), path, exportLine(path))
				return nil
			})
			if err != nil {
				return err
			}
			// Serve returns nil once stopped: an interrupt is a normal end here.
			return sshagent.Serve(ctx, l, kr)
		},
	}
	f := cmd.Flags()
	sel.register(f)
	f.StringVar(&socket, "socket", "", "socket path (default: a new private temporary directory)")
	return cmd
}

// runWithAgent runs command with SSH_AUTH_SOCK set and serves the agent until
// it exits. Interrupts reach the command through the terminal, so the agent
// keeps answering until the command has finished.
func (a *app) runWithAgent(l net.Listener, kr agent.Agent, path string, command []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- sshagent.Serve(ctx, l, kr) }()

	c := exec.Command(command[0], command[1:]...) //nolint:gosec // runs the command the user asked for
	c.Env = append(os.Environ(), sshagent.EnvSocket+"="+path)
	c.Stdin, c.Stdout, c.Stderr = a.stdin, a.stdout, a.stderr
	err := c.Run()
	cancel()
	<-done
	var ee *exec.ExitError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &ee):
		if code := ee.ExitCode(); code > 0 {
			return exitcode.Silent(code)
		}
		return exitcode.Silent(exitcode.Interrupted)
	case errors.Is(err, exec.ErrNotFound):
		return exitcode.New(exitcode.NotFound, "%s: command not found", command[0])
	}
	return err
}

// exportLine is the shell statement that points ssh at the agent.
func exportLine(path string) string {
	switch filepath.Base(os.Getenv("SHELL")) {
	case "fish":
		return "set -x " + sshagent.EnvSocket + " " + shellQuote(path)
	case "csh", "tcsh":
		return "setenv " + sshagent.EnvSocket + " " + shellQuote(path)
	}
	return "export " + sshagent.EnvSocket + "=" + shellQuote(path)
}

func shellQuote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && !strings.ContainsRune("/._-+:@%", r)
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// completeSSHKeys offers stored SSH keys that have a private key, and files.
func (a *app) completeSSHKeys(cmd *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	out, _ := a.completeObjects(cmd, func(inv *inventory.Service) []string {
		ks, err := inv.DB.QuerySSHKeys(cmd.Context(), "", nil)
		if err != nil {
			return nil
		}
		var out []string
		for _, k := range ks {
			if !k.HasPrivate() {
				continue
			}
			label := k.Type + " " + k.FingerprintSHA256
			if k.Name != "" {
				out = append(out, k.Name+"\t"+label)
			}
			out = append(out, k.ID+"\t"+label)
		}
		return out
	})
	return out, cobra.ShellCompDirectiveDefault
}

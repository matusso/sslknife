package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/matusso/sslknife/internal/config"
	skcrypto "github.com/matusso/sslknife/internal/crypto"
	"github.com/matusso/sslknife/internal/exitcode"
	"github.com/matusso/sslknife/internal/output"
	"github.com/matusso/sslknife/internal/remotesync"
	"github.com/matusso/sslknife/internal/secrets"
	"github.com/matusso/sslknife/internal/vaultkv"
)

// remoteClient builds a Vault client from configuration, falling back to
// the standard VAULT_* environment variables. It does not authenticate.
func (a *app) remoteClient() (*vaultkv.Client, error) {
	rc := a.cfg.Remote
	if !rc.Enabled() {
		return nil, exitcode.New(exitcode.Usage, "no remote configured: set remote.type: vault and remote.address in %s", a.configFile())
	}
	return vaultkv.New(vaultkv.Options{
		Address:   firstNonEmpty(rc.Address, os.Getenv(vaultkv.EnvAddr)),
		Namespace: firstNonEmpty(rc.Namespace, os.Getenv(vaultkv.EnvNamespace)),
		CACert:    firstNonEmpty(rc.CACert, config.ExpandHome(os.Getenv(vaultkv.EnvCACert))),
		Timeout:   max(a.cfg.TLS.Timeout.D(), 30*time.Second),
	})
}

func (a *app) configFile() string {
	if a.flags.configPath != "" {
		return a.flags.configPath
	}
	p, _ := config.DefaultConfigPath()
	return p
}

// vaultTokenAccount is the OS keychain account holding the Vault token.
func vaultTokenAccount(c *vaultkv.Client, namespace string) string {
	return "vault-token|" + c.Address() + "|" + namespace
}

// remoteAuth finds a token: $VAULT_TOKEN, an AppRole login, the OS
// keychain (`remote login`), then the token file (~/.vault-token).
func (a *app) remoteAuth(ctx context.Context, c *vaultkv.Client) (string, error) {
	rc := a.cfg.Remote
	if t := os.Getenv(vaultkv.EnvToken); t != "" {
		c.SetToken(t)
		return "VAULT_TOKEN", nil
	}
	if rc.AuthMethod == "approle" {
		roleID := firstNonEmpty(os.Getenv(config.EnvVaultRoleID), rc.RoleID)
		secretID := os.Getenv(config.EnvVaultSecretID)
		if secretID == "" && rc.SecretIDFile != "" {
			b, err := os.ReadFile(rc.SecretIDFile)
			if err != nil {
				return "", exitcode.With(exitcode.Auth, fmt.Errorf("read AppRole secret ID: %w", err))
			}
			secretID = strings.TrimSpace(string(b))
		}
		if secretID == "" {
			return "", exitcode.New(exitcode.Auth, "AppRole login needs $%s or remote.secret_id_file", config.EnvVaultSecretID)
		}
		if _, err := c.LoginAppRole(ctx, rc.AuthMount, roleID, secretID); err != nil {
			return "", exitcode.With(exitcode.Auth, err)
		}
		return "approle", nil
	}
	ns := firstNonEmpty(rc.Namespace, os.Getenv(vaultkv.EnvNamespace))
	if kr := a.keyring(); kr != nil {
		if t, err := kr.Get(secrets.KeyringService, vaultTokenAccount(c, ns)); err == nil && len(t) > 0 {
			c.SetToken(string(t))
			skcrypto.Zero(t)
			return "keychain", nil
		}
	}
	path := rc.TokenFile
	if path == "" {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, ".vault-token")
		}
	}
	if path != "" {
		if b, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(b))) > 0 {
			c.SetToken(strings.TrimSpace(string(b)))
			return path, nil
		}
	}
	return "", exitcode.New(exitcode.Auth, "no Vault token: run 'sslknife remote login', or set %s", vaultkv.EnvToken)
}

// newRemoteStore returns the store for the configured remote, without
// authenticating.
func (a *app) newRemoteStore() (*remotesync.VaultStore, error) {
	c, err := a.remoteClient()
	if err != nil {
		return nil, err
	}
	rc := a.cfg.Remote
	st := &remotesync.VaultStore{Client: c, Mount: rc.Mount, Path: rc.Path,
		Namespace: firstNonEmpty(rc.Namespace, os.Getenv(vaultkv.EnvNamespace))}
	if rc.TransitKey != "" {
		st.Transit = c.Transit(rc.TransitMount, rc.TransitKey)
	}
	return st, nil
}

// remoteStore returns an authenticated store and where its token came from.
func (a *app) remoteStore(ctx context.Context) (*remotesync.VaultStore, string, error) {
	st, err := a.newRemoteStore()
	if err != nil {
		return nil, "", err
	}
	via, err := a.remoteAuth(ctx, st.Client)
	if err != nil {
		return nil, "", err
	}
	return st, via, nil
}

// autoSyncEnabled reports whether this invocation syncs implicitly.
func (a *app) autoSyncEnabled() bool {
	if !a.cfg.Remote.Enabled() || !a.cfg.Remote.AutoSync || a.flags.noSync {
		return false
	}
	// These commands sync explicitly or on their own schedule.
	for _, p := range []string{"sslknife remote", "sslknife server"} {
		if a.cmdPath == p || strings.HasPrefix(a.cmdPath, p+" ") {
			return false
		}
	}
	return true
}

// runSync syncs with the remote and returns the report.
func (a *app) runSync(ctx context.Context, v *vault, st *remotesync.VaultStore, dryRun bool) (*remotesync.Report, error) {
	if st == nil {
		var via string
		var err error
		if st, via, err = a.remoteStore(ctx); err != nil {
			return nil, err
		}
		a.log.Debug("remote auth", "via", via)
	}
	a.log.Debug("remote sync", "remote", st.Identity(), "dry_run", dryRun)
	rep, err := remotesync.Sync(ctx, v.inv, st, remotesync.Options{DryRun: dryRun})
	if err != nil {
		if errors.Is(err, vaultkv.ErrPermission) {
			return nil, exitcode.With(exitcode.Auth, err)
		}
		if errors.Is(err, vaultkv.ErrUnavailable) {
			return nil, exitcode.With(exitcode.Network, err)
		}
		return nil, err
	}
	return rep, nil
}

// autoSync runs an implicit sync. Failures only warn: the local vault keeps
// working offline and the next sync catches up.
func (a *app) autoSync(ctx context.Context, v *vault) {
	rep, err := a.runSync(ctx, v, nil, false)
	if err != nil {
		a.out.Warnf("remote sync failed, continuing with the local vault: %v", err)
		return
	}
	if s := syncSummary(rep); s != "" {
		a.out.Infof("Synced with Vault: %s", s)
	}
	for _, c := range rep.Changes {
		if c.Error != "" {
			a.out.Warnf("remote sync: %s %s %s: %s", c.Action, c.Kind, c.Label, c.Error)
		}
	}
}

// finishVault pushes changes made by the command, then records the
// change counter so later calls only push new changes.
func (a *app) finishVault(ctx context.Context) {
	v := a.vault
	if v == nil || !v.autoSync || ctx.Err() != nil {
		return
	}
	n, err := v.db.TotalChanges(ctx)
	if err != nil || n == v.changes {
		return
	}
	a.autoSync(ctx, v)
	v.changes, _ = v.db.TotalChanges(ctx)
}

func syncSummary(rep *remotesync.Report) string {
	var parts []string
	for _, x := range []struct {
		act  remotesync.Action
		verb string
	}{
		{remotesync.ActPull, "pulled"}, {remotesync.ActPush, "pushed"}, {remotesync.ActMerge, "merged"},
		{remotesync.ActDeleteLocal, "deleted here"}, {remotesync.ActDeleteRemote, "deleted on remote"},
	} {
		if n := rep.Count(x.act); n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, x.verb))
		}
	}
	if rep.Failed > 0 {
		parts = append(parts, fmt.Sprintf("%d failed", rep.Failed))
	}
	return strings.Join(parts, ", ")
}

func newRemoteCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remote",
		Short: "Share the inventory between devices through HashiCorp Vault",
		Long: `Share certificates, keys and SSH keys between devices through a HashiCorp
Vault KV version 2 secrets engine.

Every device keeps its own encrypted local vault (search, TLS history and CT
monitoring stay local) and syncs its inventory with Vault: certificates,
private and public keys, SSH keys, names, comments, tags and notes. Changes
merge in both directions, and deletions propagate. With remote.auto_sync
(the default) every command that opens the vault syncs before it runs and
pushes its changes afterwards; 'sslknife server' syncs every remote.interval.

Configure it in the config file ('sslknife config path'):

  remote:
    type: vault
    address: https://vault.example.com:8200
    mount: secret          # KV v2 mount
    path: sslknife         # prefix inside the mount
    auth_method: token     # token | userpass | ldap | approle
    transit_key: sslknife  # optional: encrypt private keys with Transit

Private keys are stored in Vault as PKCS#8 PEM (SSH keys as the original
file), protected by Vault's encryption at rest and ACL policies. Set
remote.transit_key to encrypt them with a Transit key first, so that reading
the KV path alone does not reveal them.

Tokens come from $VAULT_TOKEN, an AppRole login, the OS keychain ('sslknife
remote login') or ~/.vault-token, never from flags or the config file.`,
		Example: `  sslknife remote login
  sslknife remote login --method userpass --username alice
  sslknife remote status
  sslknife remote sync --dry-run
  sslknife remote sync`,
	}
	cmd.AddCommand(newRemoteSyncCmd(a), newRemoteStatusCmd(a), newRemoteLoginCmd(a), newRemoteLogoutCmd(a), newRemoteForgetCmd(a))
	return cmd
}

func newRemoteSyncCmd(a *app) *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Merge the local inventory with the Vault remote",
		Long: `Merge the local inventory with the Vault remote.

Objects are matched by content (certificate SHA-256, key SPKI SHA-256, SSH
key fingerprint). An object changed on one side since the last sync is
copied to the other. When both sides changed it, tags and notes are united
and the remote name and comment win. An object deleted on one side is
deleted on the other, unless the other side changed it in the meantime.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			v, err := a.requireVault(ctx)
			if err != nil {
				return err
			}
			rep, err := a.runSync(ctx, v, nil, dryRun)
			if err != nil {
				return err
			}
			err = a.out.Emit(rep, func(w io.Writer) error {
				st := a.out.Style
				if len(rep.Changes) == 0 {
					fmt.Fprintf(w, "Already in sync (%d objects on the remote).\n", rep.Objects)
					return nil
				}
				t := output.NewTable("ACTION", "KIND", "OBJECT", "IDENT", "RESULT")
				for _, c := range rep.Changes {
					result := st.Green("ok")
					if dryRun {
						result = st.Dim("planned")
					}
					if c.Error != "" {
						result = st.Red(c.Error)
					}
					t.Row(string(c.Action), c.Kind, c.Label, c.Ident[:16], result)
				}
				if err := t.Render(w, st); err != nil {
					return err
				}
				if dryRun {
					fmt.Fprintf(w, "\nDry run: nothing was changed.\n")
				} else {
					fmt.Fprintf(w, "\n%s; %d objects on the remote.\n", syncSummary(rep), rep.Objects)
				}
				return nil
			})
			if err == nil && rep.Failed > 0 {
				return exitcode.New(exitcode.Error, "%d objects failed to sync", rep.Failed)
			}
			return err
		},
	}
	cmd.Flags().BoolVarP(&dryRun, "dry-run", "n", false, "show what would change without changing anything")
	return cmd
}

func newRemoteStatusCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the remote configuration, token and pending changes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			rc := a.cfg.Remote
			st, via, err := a.remoteStore(ctx)
			if err != nil {
				return err
			}
			view := map[string]any{
				"type": rc.Type, "address": st.Client.Address(), "namespace": st.Namespace, "mount": rc.Mount, "path": rc.Path,
				"auth": via, "auto_sync": rc.AutoSync, "transit_key": rc.TransitKey,
			}
			ti, err := st.Client.LookupSelf(ctx)
			if err != nil {
				return exitcode.With(exitcode.Auth, err)
			}
			view["token"] = ti
			v, err := a.requireVault(ctx)
			if err != nil {
				return err
			}
			rep, err := a.runSync(ctx, v, st, true)
			if err != nil {
				return err
			}
			view["objects"] = rep.Objects
			view["pending"] = rep.Changes
			return a.out.Emit(view, func(w io.Writer) error {
				kv := output.NewKV(a.out.Style)
				kv.Add("Remote", "HashiCorp Vault "+st.Client.Address())
				if st.Namespace != "" {
					kv.Add("Namespace", st.Namespace)
				}
				kv.Add("Location", rc.Mount+"/"+strings.Trim(rc.Path, "/")+" (KV v2)")
				kv.Add("Token from", via)
				kv.Add("Token", tokenSummary(ti))
				if rc.TransitKey != "" {
					kv.Add("Private keys", "Transit-encrypted with "+st.Transit.Name())
				} else {
					kv.Add("Private keys", "stored in KV (no Transit key)")
				}
				kv.Add("Auto sync", fmt.Sprintf("%t", rc.AutoSync))
				kv.Addf("Remote objects", "%d", rep.Objects)
				if len(rep.Changes) == 0 {
					kv.Add("Pending", "none, in sync")
				} else {
					var lines []string
					for _, c := range rep.Changes {
						lines = append(lines, fmt.Sprintf("%s %s %s", c.Action, c.Kind, c.Label))
					}
					kv.List("Pending", lines)
				}
				return kv.Render(w)
			})
		},
	}
}

func tokenSummary(ti *vaultkv.TokenInfo) string {
	s := ti.DisplayName
	if len(ti.Policies) > 0 {
		s += "  policies=" + strings.Join(ti.Policies, ",")
	}
	switch {
	case ti.TTL > 0:
		s += "  expires in " + (time.Duration(ti.TTL) * time.Second).String()
	case ti.ExpireTime.IsZero():
		s += "  no expiry"
	}
	return s
}

func newRemoteLoginCmd(a *app) *cobra.Command {
	var method, username string
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to Vault and keep the token in the OS keychain",
		Long: `Log in to Vault and store the resulting token in the OS keychain, so later
commands on this device can sync without prompting.

With --method token (the default) you paste an existing token. With userpass
or ldap you enter your password and SSLKnife exchanges it for a token. The
password is read from the terminal only.

AppRole (remote.auth_method: approle) logs in on every run instead and needs
no 'login'.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			rc := a.cfg.Remote
			if method == "" {
				method = rc.AuthMethod
			}
			kr := a.keyring()
			if kr == nil {
				return exitcode.New(exitcode.Usage, "keychain disabled by %s; set %s instead", EnvNoKeyring, vaultkv.EnvToken)
			}
			if !a.prompt.Interactive() {
				return exitcode.New(exitcode.Usage, "no terminal: set %s instead of logging in", vaultkv.EnvToken)
			}
			c, err := a.remoteClient()
			if err != nil {
				return err
			}
			switch method {
			case "token":
				t, err := a.prompt.Password("Vault token")
				if err != nil {
					return err
				}
				c.SetToken(strings.TrimSpace(string(t)))
				skcrypto.Zero(t)
			case "userpass", "ldap":
				if username == "" {
					username = rc.Username
				}
				if username == "" {
					if username, err = a.prompt.Line("Username", ""); err != nil {
						return err
					}
				}
				pw, err := a.prompt.Password("Password for " + username)
				if err != nil {
					return err
				}
				_, err = c.LoginPassword(ctx, firstNonEmpty(rc.AuthMount, method), username, pw)
				skcrypto.Zero(pw)
				if err != nil {
					return exitcode.With(exitcode.Auth, err)
				}
			case "approle":
				return usagef("AppRole needs no login; set $%s or remote.secret_id_file", config.EnvVaultSecretID)
			default:
				return usagef("unknown --method %q (token, userpass, ldap)", method)
			}
			ti, err := c.LookupSelf(ctx)
			if err != nil {
				return exitcode.With(exitcode.Auth, err)
			}
			ns := firstNonEmpty(rc.Namespace, os.Getenv(vaultkv.EnvNamespace))
			if err := kr.Set(secrets.KeyringService, vaultTokenAccount(c, ns), []byte(c.Token())); err != nil {
				return fmt.Errorf("store token in keychain: %w", err)
			}
			a.out.Infof("Logged in to %s as %s; token stored in the OS keychain", c.Address(), tokenSummary(ti))
			return nil
		},
	}
	cmd.Flags().StringVar(&method, "method", "", "auth method: token, userpass or ldap (default remote.auth_method)")
	cmd.Flags().StringVar(&username, "username", "", "username for userpass/ldap (default remote.username)")
	return cmd
}

func newRemoteLogoutCmd(a *app) *cobra.Command {
	var revoke bool
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Remove the stored Vault token from the OS keychain",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.remoteClient()
			if err != nil {
				return err
			}
			kr := a.keyring()
			if kr == nil {
				return exitcode.New(exitcode.Usage, "keychain disabled by %s", EnvNoKeyring)
			}
			ns := firstNonEmpty(a.cfg.Remote.Namespace, os.Getenv(vaultkv.EnvNamespace))
			account := vaultTokenAccount(c, ns)
			t, err := kr.Get(secrets.KeyringService, account)
			if err != nil {
				return exitcode.New(exitcode.NotFound, "no Vault token stored for %s", c.Address())
			}
			if revoke {
				c.SetToken(string(t))
				if err := c.RevokeSelf(cmd.Context()); err != nil {
					a.out.Warnf("could not revoke the token: %v", err)
				}
			}
			skcrypto.Zero(t)
			if err := kr.Delete(secrets.KeyringService, account); err != nil {
				return err
			}
			a.out.Infof("Removed the Vault token for %s from the OS keychain", c.Address())
			return nil
		},
	}
	cmd.Flags().BoolVar(&revoke, "revoke", false, "also revoke the token in Vault")
	return cmd
}

func newRemoteForgetCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "forget",
		Short: "Forget what was last synced, so the next sync merges both sides from scratch",
		Long: `Forget the local record of what this device last synced with the remote.

The next sync then treats every object as new on both sides: nothing is
deleted, objects present on only one side are copied to the other, and
objects present on both are merged. Use it after restoring the local vault
from a backup, or when pointing it at a different remote.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			v, err := a.requireVault(ctx)
			if err != nil {
				return err
			}
			st, err := a.newRemoteStore()
			if err != nil {
				return err
			}
			if err := v.db.ForgetRemote(ctx, st.Identity()); err != nil {
				return err
			}
			a.out.Infof("Forgot the sync state for %s", st.Client.Address())
			return nil
		},
	}
}

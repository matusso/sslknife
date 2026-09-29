package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	skcrypto "github.com/matusso/sslknife/internal/crypto"
	"github.com/matusso/sslknife/internal/database"
	"github.com/matusso/sslknife/internal/exitcode"
	"github.com/matusso/sslknife/internal/inventory"
	"github.com/matusso/sslknife/internal/output"
	"github.com/matusso/sslknife/internal/secrets"
)

// EnvNoKeyring disables OS keychain access (useful in CI and containers).
const EnvNoKeyring = "SSLKNIFE_NO_KEYRING"

const minPasswordLen = 10

type vault struct {
	db      *database.DB
	kf      *secrets.KeyFile
	inv     *inventory.Service
	keyPath string
	method  string
	root    []byte // kept for keyslot management; zeroed on Close
}

func (v *vault) Close() {
	skcrypto.Zero(v.root)
	if v.db != nil {
		v.db.Close()
	}
}

func (a *app) keyring() secrets.Keyring {
	if os.Getenv(EnvNoKeyring) != "" {
		return nil
	}
	return secrets.OSKeyring{}
}

// requireVault opens and unlocks the database, once per invocation.
func (a *app) requireVault(ctx context.Context) (*vault, error) {
	if a.vault != nil {
		return a.vault, nil
	}
	path := a.cfg.Database.Path
	keyPath := database.KeyFilePath(path)
	if !database.Exists(path) {
		return nil, exitcode.New(exitcode.NotFound, "no SSLKnife vault at %s; run 'sslknife init' first", path)
	}
	kf, err := secrets.LoadKeyFile(keyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, exitcode.New(exitcode.Auth, "key file %s is missing; the database cannot be decrypted without it", keyPath)
		}
		return nil, err
	}
	u := secrets.Unlocker{Getenv: os.Getenv, Keyring: a.keyring()}
	if a.prompt.Interactive() {
		u.Prompt = func() ([]byte, error) { return a.prompt.Password("Vault password") }
	}
	root, method, err := u.Unlock(kf)
	if err != nil {
		return nil, exitcode.With(exitcode.Auth, err)
	}
	a.log.Debug("vault unlocked", "method", method)
	db, err := database.Open(ctx, path, root)
	if err != nil {
		skcrypto.Zero(root)
		return nil, err
	}
	a.vault = &vault{db: db, kf: kf, inv: inventory.New(db), keyPath: keyPath, method: method, root: root}
	a.checkPermissions(path, keyPath)
	return a.vault, nil
}

// checkPermissions warns when vault files or their directory are readable
// by other users. SQLite journals inherit the directory's exposure, so the
// directory should be private (0700) even though journal pages are encrypted.
func (a *app) checkPermissions(dbPath, keyPath string) {
	if runtime.GOOS == "windows" {
		return
	}
	for _, p := range []string{filepath.Dir(dbPath), dbPath, keyPath} {
		st, err := os.Stat(p)
		if err == nil && st.Mode().Perm()&0o077 != 0 {
			a.out.Warnf("%s is accessible by other users (mode %04o); run: chmod go-rwx %s", p, st.Mode().Perm(), p)
		}
	}
}

// inventory is a shortcut for commands that only need the service.
func (a *app) inventory(ctx context.Context) (*inventory.Service, error) {
	v, err := a.requireVault(ctx)
	if err != nil {
		return nil, err
	}
	return v.inv, nil
}

// newPassword obtains a new vault password from the environment or TTY.
func (a *app) newPassword() ([]byte, error) {
	if pw, ok, err := secrets.EnvPasswordValue(os.Getenv); err != nil || ok {
		if ok && len(pw) < minPasswordLen {
			a.out.Warnf("the password from the environment is shorter than %d characters", minPasswordLen)
		}
		return pw, err
	}
	if !a.prompt.Interactive() {
		return nil, exitcode.New(exitcode.Usage, "no terminal: set %s or %s to provide the vault password", secrets.EnvPassword, secrets.EnvPasswordFile)
	}
	return a.prompt.NewPassword("New vault password", minPasswordLen)
}

func newInitCmd(a *app) *cobra.Command {
	var keychain, keychainOnly bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create the encrypted SSLKnife vault",
		Long: `Create the encrypted database and its key file.

A random 256-bit root key encrypts the database. The root key is stored only
in wrapped form, protected by your password (Argon2id) and optionally by the
OS keychain so that everyday commands do not prompt.

The password is read from the terminal, or from SSLKNIFE_PASSWORD /
SSLKNIFE_PASSWORD_FILE for automation. It is never accepted as a flag.`,
		Example: `  sslknife init
  sslknife init --keychain
  SSLKNIFE_PASSWORD_FILE=/run/secrets/sslknife sslknife init`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path := a.cfg.Database.Path
			keyPath := database.KeyFilePath(path)
			if database.Exists(path) || database.Exists(keyPath) {
				return exitcode.New(exitcode.Usage, "a vault already exists at %s", path)
			}
			kf, root := secrets.NewKeyFile()
			defer skcrypto.Zero(root)
			if !keychainOnly {
				pw, err := a.newPassword()
				if err != nil {
					return err
				}
				_, err = kf.AddPasswordSlot(root, pw, skcrypto.DefaultArgon2)
				skcrypto.Zero(pw)
				if err != nil {
					return err
				}
			}
			if keychain || keychainOnly {
				kr := a.keyring()
				if kr == nil {
					return exitcode.New(exitcode.Usage, "keychain disabled by %s", EnvNoKeyring)
				}
				if _, err := kf.AddKeyringSlot(root, kr); err != nil {
					return err
				}
				if keychainOnly {
					a.out.Warnf("the vault can only be unlocked from this user's OS keychain; add a password with 'sslknife vault add-password' to avoid data loss")
				}
			}
			db, err := database.Create(cmd.Context(), path, root)
			if err != nil {
				return err
			}
			db.Close()
			if err := kf.Save(keyPath); err != nil {
				os.Remove(path)
				return err
			}
			return a.out.Emit(map[string]any{"database": path, "key_file": keyPath, "slots": slotViews(kf)}, func(w io.Writer) error {
				fmt.Fprintf(w, "Vault created: %s\n", path)
				fmt.Fprintf(w, "Key file:      %s\n", keyPath)
				fmt.Fprintf(w, "Back up both files together; the database cannot be decrypted without the key file.\n")
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&keychain, "keychain", false, "also store an unlock key in the OS keychain")
	cmd.Flags().BoolVar(&keychainOnly, "keychain-only", false, "protect the vault with the OS keychain only (no password)")
	cmd.MarkFlagsMutuallyExclusive("keychain", "keychain-only")
	return cmd
}

type slotView struct {
	ID      string    `json:"id"`
	Type    string    `json:"type"`
	Created time.Time `json:"created"`
	Detail  string    `json:"detail,omitempty"`
}

func slotViews(kf *secrets.KeyFile) []slotView {
	var out []slotView
	for _, s := range kf.Slots {
		v := slotView{ID: s.ID, Type: s.Type, Created: s.Created}
		if s.KDF != nil {
			v.Detail = fmt.Sprintf("%s t=%d m=%dMiB p=%d", s.KDF.Name, s.KDF.Params.Time, s.KDF.Params.MemoryKiB/1024, s.KDF.Params.Threads)
		}
		if s.Keyring != nil {
			v.Detail = "service=" + s.Keyring.Service
		}
		out = append(out, v)
	}
	return out
}

func newVaultCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vault",
		Short: "Manage the encrypted vault and its unlock methods",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show vault location, keyslots and contents",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v, err := a.requireVault(cmd.Context())
			if err != nil {
				return err
			}
			ver, err := v.db.SchemaVersion(cmd.Context())
			if err != nil {
				return err
			}
			st, err := v.inv.Stats(cmd.Context(), a.cfg.Expiry.WarningDays)
			if err != nil {
				return err
			}
			view := map[string]any{
				"database": v.db.Path(), "key_file": v.keyPath, "db_id": v.kf.DBID, "schema_version": ver,
				"unlocked_by": v.method, "slots": slotViews(v.kf), "counts": st,
			}
			return a.out.Emit(view, func(w io.Writer) error {
				kv := output.NewKV(a.out.Style)
				kv.Add("Database", v.db.Path()).Add("Key file", v.keyPath).Add("Vault ID", v.kf.DBID).
					Addf("Schema", "%d", ver).Add("Unlocked by", v.method)
				kv.Heading("Keyslots")
				for _, s := range slotViews(v.kf) {
					kv.Add(s.ID, s.Type+"  "+s.Detail)
				}
				kv.Heading("Contents")
				kv.Addf("Certificates", "%d", st.Certificates).Addf("Private keys", "%d", st.PrivateKeys).
					Addf("Public keys", "%d", st.PublicKeys).Addf("SSH keys", "%d", st.SSHKeys).
					Addf("Expiring", "%d (within %d days)", st.Expiring, a.cfg.Expiry.WarningDays).
					Addf("Expired", "%d", st.Expired).Addf("TLS endpoints", "%d", st.TLSEndpoints).Addf("CT watches", "%d", st.CTWatches)
				return kv.Render(w)
			})
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "add-password",
		Short: "Add a password keyslot",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.withRoot(cmd.Context(), func(v *vault, root []byte) error {
				pw, err := a.newPassword()
				if err != nil {
					return err
				}
				defer skcrypto.Zero(pw)
				id, err := v.kf.AddPasswordSlot(root, pw, skcrypto.DefaultArgon2)
				if err != nil {
					return err
				}
				a.out.Infof("Added password keyslot %s", id)
				return v.kf.Save(v.keyPath)
			})
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "add-keychain",
		Short: "Store an unlock key in the OS keychain",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.withRoot(cmd.Context(), func(v *vault, root []byte) error {
				kr := a.keyring()
				if kr == nil {
					return exitcode.New(exitcode.Usage, "keychain disabled by %s", EnvNoKeyring)
				}
				id, err := v.kf.AddKeyringSlot(root, kr)
				if err != nil {
					return err
				}
				a.out.Infof("Added keychain keyslot %s", id)
				return v.kf.Save(v.keyPath)
			})
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "remove-slot <slot-id>",
		Short: "Remove a keyslot (the last slot cannot be removed)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.requireVault(cmd.Context())
			if err != nil {
				return err
			}
			if err := v.kf.RemoveSlot(args[0], a.keyring()); err != nil {
				return exitcode.With(exitcode.Usage, err)
			}
			a.out.Infof("Removed keyslot %s", args[0])
			return v.kf.Save(v.keyPath)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "change-password",
		Short: "Replace all password keyslots with a new password",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.withRoot(cmd.Context(), func(v *vault, root []byte) error {
				var old []string
				for _, s := range v.kf.Slots {
					if s.Type == secrets.SlotPassword {
						old = append(old, s.ID)
					}
				}
				pw, err := a.newPassword()
				if err != nil {
					return err
				}
				defer skcrypto.Zero(pw)
				if _, err := v.kf.AddPasswordSlot(root, pw, skcrypto.DefaultArgon2); err != nil {
					return err
				}
				for _, id := range old {
					if err := v.kf.RemoveSlot(id, nil); err != nil {
						return err
					}
				}
				a.out.Infof("Password changed")
				return v.kf.Save(v.keyPath)
			})
		},
	})
	return cmd
}

// withRoot unlocks the vault and passes the root key to fn. The root key is
// needed to add keyslots.
func (a *app) withRoot(ctx context.Context, fn func(v *vault, root []byte) error) error {
	v, err := a.requireVault(ctx)
	if err != nil {
		return err
	}
	return fn(v, v.root)
}

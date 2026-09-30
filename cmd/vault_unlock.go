package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/matusso/sslknife/internal/config"
	skcrypto "github.com/matusso/sslknife/internal/crypto"
	"github.com/matusso/sslknife/internal/exitcode"
	"github.com/matusso/sslknife/internal/keycache"
)

const defaultUnlockCache = 15 * time.Minute

func newVaultUnlockCmd(a *app) *cobra.Command {
	var dur string
	cmd := &cobra.Command{
		Use:   "unlock",
		Short: "Keep the vault unlocked for a while, so commands do not ask again",
		Long: `Unlock the vault once and keep it unlocked in a background process, like
sudo's timestamp. Every command that uses the cached key extends the time;
'sslknife vault lock' ends it at once.

The root key stays only in that process's memory (locked against swapping
where possible) and is handed out over a Unix socket in a private directory,
to processes running as your user.

Set vault.unlock_cache in the config to start the cache automatically
whenever a command asks for the password or Touch ID.`,
		Example: `  sslknife vault unlock
  sslknife vault unlock --for 1h
  sslknife vault lock`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !keycache.Supported {
				return exitcode.New(exitcode.Usage, "the unlock cache is not supported on this platform")
			}
			ttl := a.cfg.Vault.UnlockCache.D()
			if ttl <= 0 {
				ttl = defaultUnlockCache
			}
			if dur != "" {
				d, err := config.ParseDuration(dur)
				if err != nil {
					return usageError{err}
				}
				if d < time.Second {
					return usagef("--for must be at least 1s")
				}
				ttl = d
			}
			kf, _, err := a.loadKeyFile()
			if err != nil {
				return err
			}
			root, method, err := a.unlockRoot(kf, false)
			if err != nil {
				return err
			}
			defer skcrypto.Zero(root)
			if err := a.startUnlockCache(kf.DBID, root, ttl); err != nil {
				return err
			}
			exp := time.Now().Add(ttl)
			return a.out.Emit(map[string]any{"unlocked_by": method, "idle_timeout": ttl.String(), "expires": exp}, func(w io.Writer) error {
				fmt.Fprintf(w, "Vault unlocked for %s after its last use (now until %s).\n", ttl, exp.Format("15:04:05"))
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&dur, "for", "", "idle time before locking again, e.g. 30m, 8h (default vault.unlock_cache or 15m)")
	return cmd
}

func newVaultLockCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Forget the cached vault key started by 'vault unlock'",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			kf, _, err := a.loadKeyFile()
			if err != nil {
				return err
			}
			err = keycache.Lock(kf.DBID)
			if errors.Is(err, keycache.ErrNotCached) {
				a.out.Infof("Vault was not unlocked")
				return nil
			}
			if err != nil {
				return err
			}
			a.out.Infof("Vault locked")
			return nil
		},
	}
}

// newVaultCacheDaemonCmd is the background process started by
// startUnlockCache. It reads the key from stdin and needs no configuration.
func newVaultCacheDaemonCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "cache-daemon",
		Hidden:            true,
		Args:              cobra.NoArgs,
		PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
		RunE: func(*cobra.Command, []string) error {
			return keycache.RunDaemon(os.Stdin, os.Stdout)
		},
	}
}

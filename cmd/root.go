// Package cmd implements the sslknife command-line interface.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/cobra"

	"github.com/matusso/sslknife/internal/config"
	"github.com/matusso/sslknife/internal/exitcode"
	"github.com/matusso/sslknife/internal/logging"
	"github.com/matusso/sslknife/internal/output"
	"github.com/matusso/sslknife/internal/prompt"
)

// globalFlags are the persistent flags shared by all commands.
type globalFlags struct {
	configPath string
	database   string
	json       bool
	yaml       bool
	format     string
	quiet      bool
	verbose    bool
	debug      bool
	logLevel   string
	timeout    time.Duration
	proxy      string
	noColor    bool
}

// app is the per-invocation context passed to every command. It replaces
// global state: commands receive it through their constructor closures.
type app struct {
	flags  globalFlags
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer

	cfg    *config.Config
	out    *output.Printer
	log    *slog.Logger
	prompt *prompt.Prompter

	vault *vault // opened lazily by requireVault
}

// Execute runs the CLI and returns the process exit code.
func Execute(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	a := &app{stdin: stdin, stdout: stdout, stderr: stderr}
	root := newRootCmd(a)
	root.SetArgs(args)
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)
	err := root.ExecuteContext(ctx)
	if a.vault != nil {
		a.vault.Close()
	}
	if err == nil {
		return exitcode.OK
	}
	if ctx.Err() != nil {
		err = context.Canceled
	}
	code := exitcode.Code(err)
	if isUsageError(err) {
		code = exitcode.Usage
	}
	if !exitcode.IsSilent(err) {
		msg := err.Error()
		if a.out != nil {
			msg = a.out.Style.Red("error:") + " " + msg
		} else {
			msg = "error: " + msg
		}
		fmt.Fprintln(stderr, msg)
		if isUsageError(err) {
			fmt.Fprintln(stderr, "Run 'sslknife --help' for usage.")
		}
	}
	return code
}

type usageError struct{ error }

func (u usageError) Unwrap() error { return u.error }

func usagef(format string, args ...any) error {
	return usageError{fmt.Errorf(format, args...)}
}

func isUsageError(err error) bool {
	var u usageError
	return errors.As(err, &u)
}

func newRootCmd(a *app) *cobra.Command {
	root := &cobra.Command{
		Use:   "sslknife",
		Short: "Swiss-army knife for TLS, certificates, PKI and SSH keys",
		Long: `SSLKnife inspects, creates, converts and inventories X.509 certificates,
private keys and SSH keys, and analyses remote TLS endpoints.

Everything stored by SSLKnife lives in a local encrypted database.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return a.setup(cmd)
		},
	}
	f := &a.flags
	pf := root.PersistentFlags()
	pf.StringVar(&f.configPath, "config", "", "config file (default: platform config dir, or $SSLKNIFE_CONFIG)")
	pf.StringVar(&f.database, "database", "", "database file (default from config, or $SSLKNIFE_DATABASE)")
	pf.BoolVar(&f.json, "json", false, "output JSON")
	pf.BoolVar(&f.yaml, "yaml", false, "output YAML")
	pf.StringVar(&f.format, "format", "text", "output format: text|table|json|yaml|raw")
	pf.BoolVarP(&f.quiet, "quiet", "q", false, "suppress non-essential output")
	pf.BoolVarP(&f.verbose, "verbose", "v", false, "verbose logging")
	pf.BoolVar(&f.debug, "debug", false, "debug logging (secrets are always redacted)")
	pf.StringVar(&f.logLevel, "log-level", "", "log level: error|warn|info|debug|trace")
	pf.DurationVar(&f.timeout, "timeout", 0, "network timeout (default from config, 10s)")
	pf.StringVar(&f.proxy, "proxy", "", "proxy for outbound connections (http://, socks5://)")
	pf.BoolVar(&f.noColor, "no-color", false, "disable coloured output (also honours NO_COLOR)")
	root.MarkFlagsMutuallyExclusive("json", "yaml")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageError{err} })

	root.AddGroup(
		&cobra.Group{ID: "pki", Title: "Certificates and keys:"},
		&cobra.Group{ID: "net", Title: "Network:"},
		&cobra.Group{ID: "tools", Title: "Tools:"},
	)
	for _, c := range []*cobra.Command{newCertCmd(a), newKeyCmd(a), newFingerprintCmd(a), newInspectCmd(a), newConvertCmd(a), newJKSCmd(a), newSSHCmd(a)} {
		c.GroupID = "pki"
		root.AddCommand(c)
	}
	tlsCmd := newTLSCmd(a)
	tlsCmd.GroupID = "net"
	ctCmd := newCTCmd(a)
	ctCmd.GroupID = "net"
	root.AddCommand(tlsCmd, ctCmd)
	for _, c := range []*cobra.Command{newSearchCmd(a), newServerCmd(a), newVaultCmd(a), newInitCmd(a), newConfigCmd(a), newVersionCmd(a), newDocsCmd(root)} {
		if c.GroupID == "" && !c.Hidden {
			c.GroupID = "tools"
		}
		root.AddCommand(c)
	}
	root.SetCompletionCommandGroupID("tools")
	root.SetHelpCommandGroupID("tools")
	return root
}

// setup resolves configuration, output and logging for the invocation.
func (a *app) setup(cmd *cobra.Command) error {
	f := &a.flags
	format, err := output.ParseFormat(f.format)
	if err != nil {
		return usageError{err}
	}
	if f.json {
		format = output.JSON
	}
	if f.yaml {
		format = output.YAML
	}
	a.out = output.New(a.stdout, a.stderr, format, f.noColor, f.quiet)

	level := slog.LevelWarn
	if f.verbose {
		level = slog.LevelInfo
	}
	if f.debug {
		level = slog.LevelDebug
	}
	if f.logLevel != "" {
		l, ok := logging.ParseLevel(f.logLevel)
		if !ok {
			return usagef("invalid --log-level %q", f.logLevel)
		}
		level = l
	}
	a.log = logging.New(a.stderr, level)
	a.prompt = prompt.New(a.stdin, a.stderr)

	// A file named with --config must exist (except for `config init`,
	// which creates it); the default or $SSLKNIFE_CONFIG location may be absent.
	path := f.configPath
	mustExist := path != "" && cmd.CommandPath() != "sslknife config init"
	if path == "" {
		if path, err = config.DefaultConfigPath(); err != nil {
			return err
		}
	}
	a.cfg, err = config.Load(config.ExpandHome(path), mustExist)
	if err != nil {
		return err
	}
	if f.database != "" {
		a.cfg.Database.Path = config.ExpandHome(f.database)
	}
	if f.timeout > 0 {
		a.cfg.TLS.Timeout = config.Duration(f.timeout)
	}
	if f.proxy != "" {
		a.cfg.TLS.Proxy = f.proxy
	}
	a.log.Debug("configuration", "config", path, "database", a.cfg.Database.Path, "command", cmd.CommandPath())
	return nil
}

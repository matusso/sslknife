package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/matusso/sslknife/internal/buildinfo"
	"github.com/matusso/sslknife/internal/certificate"
	"github.com/matusso/sslknife/internal/exitcode"
	"github.com/matusso/sslknife/internal/server"
	"github.com/matusso/sslknife/web"
)

// EnvServerToken fixes the server access token (for scripts and containers).
const EnvServerToken = "SSLKNIFE_SERVER_TOKEN"

func newServerCmd(a *app) *cobra.Command {
	var listen, certFile, keyFile, tokenFile string
	var plainHTTP, allowInsecure, noJobs bool
	var allowedHosts []string
	cmd := &cobra.Command{
		Use:     "server",
		Aliases: []string{"serve", "ui"},
		Short:   "Run the local web interface and REST API",
		Long: `Start the SSLKnife web interface and REST API on https://127.0.0.1:8443.

The server listens on loopback by default. Open the printed URL: it contains
a one-time access token that is exchanged for a session cookie. API clients
send the token as "Authorization: Bearer <token>". The token is random for
every start unless --token-file or $SSLKNIFE_SERVER_TOKEN sets it; there is
no default password.

HTTPS uses a self-signed certificate that is generated once and stored
encrypted in the vault, so its fingerprint stays the same across restarts;
--cert/--key use your own certificate instead.

While running, the server polls Certificate Transparency (ct.interval),
re-inspects recorded TLS endpoints (server.refresh_interval) and logs
certificates entering the critical expiry window. With a Vault remote it
also syncs the inventory every remote.interval. --no-jobs disables this.

Exposing the server beyond loopback (--listen 0.0.0.0:8443) prints a warning;
plain HTTP is then refused unless --allow-insecure-http is given.`,
		Example: `  sslknife server
  sslknife server --listen 127.0.0.1:9443 --http
  sslknife server --listen 0.0.0.0:8443 --cert srv.pem --key srv.key --token-file /run/secrets/sslknife-token`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if listen == "" {
				listen = a.cfg.Server.Listen
			}
			loopback := server.IsLoopback(listen)
			if !loopback {
				a.out.Warnf("the server will accept connections from other machines on %s", listen)
				a.out.Warnf("anyone who obtains the access token can read the inventory and run scans from this host")
				if plainHTTP && !allowInsecure {
					return usagef("refusing plain HTTP on a non-loopback address; use HTTPS or --allow-insecure-http")
				}
			}
			if (certFile == "") != (keyFile == "") {
				return usagef("--cert and --key must be given together")
			}
			token := os.Getenv(EnvServerToken)
			if tokenFile != "" {
				data, err := os.ReadFile(tokenFile)
				if err != nil {
					return err
				}
				token = strings.TrimSpace(string(data))
			}
			if token != "" && len(token) < 16 {
				return usagef("the access token must be at least 16 characters")
			}
			v, err := a.requireVault(ctx)
			if err != nil {
				return err
			}
			var syncFn func(context.Context) error
			if a.cfg.Remote.Enabled() && !a.flags.noSync {
				syncFn = func(ctx context.Context) error {
					rep, err := a.runSync(ctx, v, nil, false)
					if err == nil && len(rep.Changes) > 0 {
						a.log.Info("remote sync", "changes", syncSummary(rep))
					}
					return err
				}
			}
			srv, err := server.New(ctx, v.db, server.Options{
				Listen: listen, PlainHTTP: plainHTTP, CertFile: certFile, KeyFile: keyFile, Token: token,
				AllowedHosts: allowedHosts, Config: a.cfg, Logger: a.log, Dialer: a.dialer(),
				CTToken: os.Getenv(EnvCertSpotterToken), CTBaseURL: os.Getenv(EnvCTBaseURL),
				Version: buildinfo.Get().Version, Jobs: !noJobs, Static: web.Static(),
				Sync: syncFn, SyncInterval: a.cfg.Remote.Interval.D(),
			})
			if err != nil {
				return exitcode.With(exitcode.Error, fmt.Errorf("start server: %w", err))
			}
			view := map[string]string{"url": srv.URL(), "listen": srv.Addr(), "certificate_sha256": srv.Fingerprint()}
			_ = a.out.Emit(view, func(w io.Writer) error {
				st := a.out.Style
				fmt.Fprintln(w, st.Bold("SSLKnife server started"))
				fmt.Fprintln(w, srv.URL())
				if fp := srv.Fingerprint(); fp != "" && certFile == "" {
					fmt.Fprintf(w, "%s self-signed certificate SHA-256 %s\n", st.Dim("TLS:"), certificate.Colon(fp))
				}
				fmt.Fprintln(w, st.Dim("Press Ctrl+C to stop."))
				return nil
			})
			err = srv.Run(ctx)
			a.out.Infof("Server stopped")
			return err
		},
	}
	f := cmd.Flags()
	f.StringVar(&listen, "listen", "", "address to listen on (default from config, 127.0.0.1:8443)")
	f.BoolVar(&plainHTTP, "http", false, "serve plain HTTP instead of HTTPS")
	f.BoolVar(&allowInsecure, "allow-insecure-http", false, "allow plain HTTP on a non-loopback address")
	f.StringVar(&certFile, "cert", "", "TLS certificate file (PEM) instead of the self-signed one")
	f.StringVar(&keyFile, "key", "", "TLS private key file (PEM)")
	f.StringVar(&tokenFile, "token-file", "", "read the access token from a file")
	f.StringSliceVar(&allowedHosts, "allowed-host", nil, "additional Host header values to accept (DNS-rebinding protection)")
	f.BoolVar(&noJobs, "no-jobs", false, "disable background CT polling and endpoint refresh")
	return cmd
}

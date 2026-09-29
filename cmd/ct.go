package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/matusso/sslknife/internal/ct"
	"github.com/matusso/sslknife/internal/database"
	"github.com/matusso/sslknife/internal/exitcode"
	"github.com/matusso/sslknife/internal/output"
	"github.com/matusso/sslknife/internal/views"
)

// Environment variables for CT providers.
const (
	EnvCertSpotterToken = "SSLKNIFE_CERTSPOTTER_TOKEN" // optional Cert Spotter API key
	EnvCTBaseURL        = "SSLKNIFE_CT_BASE_URL"       // alternative provider endpoint (self-hosted or test)
)

func newCTCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ct",
		Short: "Monitor Certificate Transparency for your domains",
		Long: `Watch domains in Certificate Transparency and record every certificate
issued for them. SSLKnife queries CT search services (Cert Spotter by
default, or crt.sh) for watched names only; it never mirrors CT logs.

Observations are classified against the inventory:

  known       the certificate, its key or its serial is stored in SSLKnife
  changed     same names as a stored certificate, but a different certificate
  new         not stored, from a CA already used for these names
  unexpected  not stored, from a CA not seen before for these names
  expired     no longer valid

"unexpected" does not mean malicious; it means worth a look.`,
	}
	cmd.AddCommand(newCTWatchCmd(a), newCTUnwatchCmd(a), newCTListCmd(a), newCTCheckCmd(a), newCTHistoryCmd(a), newCTAckCmd(a))
	return cmd
}

func newCTWatchCmd(a *app) *cobra.Command {
	var subdomains bool
	cmd := &cobra.Command{
		Use:   "watch <domain>...",
		Short: "Watch domains (use *.example.com to include subdomains)",
		Example: `  sslknife ct watch example.com
  sslknife ct watch '*.example.com'
  sslknife ct watch example.com --subdomains`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.requireVault(cmd.Context())
			if err != nil {
				return err
			}
			for _, arg := range args {
				domain, sub, err := ct.NormalizePattern(arg, subdomains)
				if err != nil {
					return usageError{err}
				}
				w, created, err := v.db.AddCTWatch(cmd.Context(), domain, sub, "manual")
				if err != nil {
					return err
				}
				if created {
					a.out.Infof("Watching %s", w.Pattern())
				} else {
					a.out.Infof("Already watching %s", w.Pattern())
				}
			}
			return v.db.MarkCTMonitored(cmd.Context())
		},
	}
	cmd.Flags().BoolVar(&subdomains, "subdomains", false, "include all subdomains")
	return cmd
}

func newCTUnwatchCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "unwatch <domain>",
		Short: "Stop watching a domain and delete its observations",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.requireVault(cmd.Context())
			if err != nil {
				return err
			}
			domain, sub, err := ct.NormalizePattern(args[0], false)
			if err != nil {
				return usageError{err}
			}
			ws, err := v.db.CTWatchesFor(cmd.Context(), domain)
			if err != nil {
				return err
			}
			removed := 0
			for _, w := range ws {
				// "example.com" removes the exact watch; "*.example.com" the subdomain watch.
				if w.IncludeSubdomains == sub {
					if err := v.db.DeleteCTWatch(cmd.Context(), w.ID); err != nil {
						return err
					}
					removed++
					a.out.Infof("Removed watch %s", w.Pattern())
				}
			}
			if removed == 0 {
				return exitcode.New(exitcode.NotFound, "not watching %s", args[0])
			}
			return nil
		},
	}
}

type watchView struct {
	ID          string         `json:"id"`
	Watch       string         `json:"watch"`
	Source      string         `json:"source"`
	LastChecked *time.Time     `json:"last_checked,omitempty"`
	Total       int            `json:"observations"`
	Counts      map[string]int `json:"by_status"`
}

func newCTListCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List watched domains and what has been seen for them",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v, err := a.requireVault(cmd.Context())
			if err != nil {
				return err
			}
			ws, err := v.db.CTWatches(cmd.Context())
			if err != nil {
				return err
			}
			views := []watchView{}
			for _, w := range ws {
				obs, err := v.db.CTObservations(cmd.Context(), database.CTObservationFilter{WatchIDs: []string{w.ID}})
				if err != nil {
					return err
				}
				wv := watchView{ID: w.ID, Watch: w.Pattern(), Source: w.Source, Total: len(obs), Counts: map[string]int{}}
				if !w.LastCheckedAt.IsZero() {
					t := w.LastCheckedAt
					wv.LastChecked = &t
				}
				for _, o := range obs {
					wv.Counts[o.Status]++
				}
				views = append(views, wv)
			}
			return a.out.Emit(views, func(w io.Writer) error {
				if len(views) == 0 {
					fmt.Fprintln(w, "No watches. Add one with 'sslknife ct watch example.com'.")
					return nil
				}
				st := a.out.Style
				t := output.NewTable("WATCH", "SOURCE", "LAST CHECKED", "SEEN", "KNOWN", "NEW", "CHANGED", "UNEXPECTED")
				for _, v := range views {
					last := st.Dim("never")
					if v.LastChecked != nil {
						last = v.LastChecked.Format(time.DateTime)
					}
					t.Row(v.Watch, v.Source, last, fmt.Sprint(v.Total), fmt.Sprint(v.Counts[ct.StatusKnown]),
						countLabel(st.Yellow, v.Counts[ct.StatusNew]), countLabel(st.Yellow, v.Counts[ct.StatusChanged]),
						countLabel(st.Red, v.Counts[ct.StatusUnexpected]))
				}
				return t.Render(w, st)
			})
		},
	}
}

func countLabel(color func(string) string, n int) string {
	if n == 0 {
		return "0"
	}
	return color(fmt.Sprint(n))
}

func (a *app) ctChecker(v *vault, provider string) (*ct.Checker, error) {
	if provider == "" {
		provider = a.cfg.CT.Provider
	}
	d := a.dialer()
	d.Timeout = 30 * time.Second
	p, err := ct.NewProvider(provider, d, os.Getenv(EnvCertSpotterToken))
	if err != nil {
		return nil, usageError{err}
	}
	if base := os.Getenv(EnvCTBaseURL); base != "" {
		switch pp := p.(type) {
		case *ct.CertSpotter:
			pp.BaseURL = strings.TrimRight(base, "/")
		case *ct.CrtSh:
			pp.BaseURL = strings.TrimRight(base, "/")
		}
	}
	return &ct.Checker{DB: v.db, Provider: p}, nil
}

// runCTCheck polls watches (all, or those for domain) and returns results.
func (a *app) runCTCheck(ctx context.Context, v *vault, chk *ct.Checker, domain string, autoWatch bool) ([]ct.CheckResult, int, error) {
	results, added, err := ct.RunAll(ctx, v.db, chk, domain, autoWatch)
	switch {
	case errors.Is(err, ct.ErrNotWatched), errors.Is(err, ct.ErrNoWatches):
		return nil, added, exitcode.With(exitcode.NotFound, err)
	case err != nil && strings.Contains(err.Error(), "invalid domain"):
		return nil, added, usageError{err}
	}
	return results, added, err
}

type observationView = views.CTObservation

func toObsView(o database.CTObservation, watch string) observationView {
	return views.NewCTObservation(o, watch)
}

func (a *app) ctStatusLabel(s string, acked bool) string {
	st := a.out.Style
	label := s
	switch s {
	case ct.StatusKnown:
		label = st.Green(s)
	case ct.StatusNew, ct.StatusChanged:
		label = st.Yellow(s)
	case ct.StatusUnexpected:
		label = st.Red(s)
	case ct.StatusExpired:
		label = st.Dim(s)
	}
	if acked {
		label += st.Dim(" (ack)")
	}
	return label
}

func (a *app) renderObservations(w io.Writer, obs []observationView) error {
	st := a.out.Style
	t := output.NewTable("ID", "STATUS", "NAMES", "ISSUER", "NOT BEFORE", "NOT AFTER")
	for _, o := range obs {
		names := strings.Join(o.DNSNames, ", ")
		issuer := firstNonEmpty(o.IssuerName, shortDN(o.Issuer))
		if cn := shortDN(o.Issuer); o.IssuerName != "" && cn != o.Issuer {
			issuer += " " + st.Dim(cn)
		}
		status := a.ctStatusLabel(o.Status, o.Acked)
		if o.Revoked != nil && *o.Revoked {
			status += st.Dim(" revoked")
		}
		t.Row(st.Dim(o.ID[:8]), status, truncate(names, 50), truncate(issuer, 40),
			o.NotBefore.Format(time.DateOnly), o.NotAfter.Format(time.DateOnly))
	}
	return t.Render(w, st)
}

func newCTCheckCmd(a *app) *cobra.Command {
	var provider string
	var strict, noAuto bool
	cmd := &cobra.Command{
		Use:   "check [domain]",
		Short: "Poll CT now and record new certificates",
		Long: `Query the CT provider for every watched domain (or one domain) and record
issuances not seen before. When ct.auto_watch_stored_sans is enabled in the
config, the DNS names of stored certificates are watched automatically.

With --strict the exit status is 5 when unexpected or changed certificates
were found (for cron jobs and CI).

Set SSLKNIFE_CERTSPOTTER_TOKEN to use a Cert Spotter API key.`,
		Example: `  sslknife ct check
  sslknife ct check example.com --provider crtsh
  sslknife ct check --strict --json`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			v, err := a.requireVault(ctx)
			if err != nil {
				return err
			}
			chk, err := a.ctChecker(v, provider)
			if err != nil {
				return err
			}
			domain := ""
			if len(args) == 1 {
				domain = args[0]
			}
			results, autoAdded, err := a.runCTCheck(ctx, v, chk, domain, a.cfg.CT.AutoWatchStoredSANs && !noAuto && domain == "")
			if err != nil {
				return err
			}
			type checkView struct {
				Provider    string           `json:"provider"`
				AutoWatched int              `json:"auto_watched"`
				Watches     []ct.CheckResult `json:"watches"`
			}
			view := checkView{Provider: chk.Provider.Name(), AutoWatched: autoAdded, Watches: results}
			var all []observationView
			alert, failures := 0, 0
			for _, r := range results {
				if r.Error != "" {
					failures++
				}
				for _, o := range r.Added {
					all = append(all, toObsView(o, r.Pattern))
					if o.Status == ct.StatusUnexpected || o.Status == ct.StatusChanged {
						alert++
					}
				}
			}
			err = a.out.Emit(view, func(w io.Writer) error {
				st := a.out.Style
				if autoAdded > 0 {
					fmt.Fprintf(w, "Added %d watch(es) for names of stored certificates.\n", autoAdded)
				}
				for _, r := range results {
					line := fmt.Sprintf("%-40s %4d fetched, %d new", r.Pattern, r.Fetched, len(r.Added))
					if r.Error != "" {
						line += "  " + st.Yellow(r.Error)
					}
					fmt.Fprintln(w, line)
				}
				if len(all) > 0 {
					fmt.Fprintln(w)
					return a.renderObservations(w, all)
				}
				return nil
			})
			if err != nil {
				return err
			}
			if failures == len(results) && failures > 0 {
				return exitcode.New(exitcode.Network, "all CT queries failed")
			}
			if strict && alert > 0 {
				return exitcode.Silent(exitcode.CheckFailed)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&provider, "provider", "", "CT provider: certspotter or crtsh (default from config)")
	cmd.Flags().BoolVar(&strict, "strict", false, "exit 5 when unexpected or changed certificates are found")
	cmd.Flags().BoolVar(&noAuto, "no-auto-watch", false, "do not add watches for stored certificate names")
	return cmd
}

func newCTHistoryCmd(a *app) *cobra.Command {
	var status string
	var limit int
	cmd := &cobra.Command{
		Use:     "history [domain]",
		Short:   "List recorded CT observations",
		Example: "  sslknife ct history\n  sslknife ct history example.com --status unexpected",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.requireVault(cmd.Context())
			if err != nil {
				return err
			}
			ws, err := v.db.CTWatches(cmd.Context())
			if err != nil {
				return err
			}
			patterns := map[string]string{}
			var ids []string
			for _, w := range ws {
				patterns[w.ID] = w.Pattern()
				if len(args) == 0 || w.Domain == strings.TrimPrefix(strings.ToLower(args[0]), "*.") {
					ids = append(ids, w.ID)
				}
			}
			if len(args) == 1 && len(ids) == 0 {
				return exitcode.New(exitcode.NotFound, "not watching %s", args[0])
			}
			f := database.CTObservationFilter{WatchIDs: ids, Status: status, Limit: limit}
			if len(ids) == 0 {
				f.WatchIDs = []string{""}
			}
			obs, err := v.db.CTObservations(cmd.Context(), f)
			if err != nil {
				return err
			}
			views := []observationView{}
			for _, o := range obs {
				views = append(views, toObsView(o, patterns[o.WatchID]))
			}
			return a.out.Emit(views, func(w io.Writer) error {
				if len(views) == 0 {
					fmt.Fprintln(w, "No observations. Run 'sslknife ct check'.")
					return nil
				}
				return a.renderObservations(w, views)
			})
		},
	}
	cmd.Flags().StringVar(&status, "status", "", "only this status: known, new, changed, unexpected, expired")
	cmd.Flags().IntVar(&limit, "limit", 100, "maximum number of observations")
	return cmd
}

func newCTAckCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "ack <observation-id>...",
		Short: "Mark observations as expected (their issuer then counts as known)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.requireVault(cmd.Context())
			if err != nil {
				return err
			}
			for _, ref := range args {
				id, err := v.db.AcknowledgeCTObservation(cmd.Context(), ref)
				if err != nil {
					return mapLookupErr(err, ref)
				}
				a.out.Infof("Acknowledged %s", id)
			}
			return nil
		},
	}
}

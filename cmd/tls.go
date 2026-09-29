package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/matusso/sslknife/internal/certificate"
	"github.com/matusso/sslknife/internal/database"
	"github.com/matusso/sslknife/internal/exitcode"
	"github.com/matusso/sslknife/internal/netdial"
	"github.com/matusso/sslknife/internal/output"
	"github.com/matusso/sslknife/internal/protocol"
	"github.com/matusso/sslknife/internal/scanner"
	"github.com/matusso/sslknife/internal/tlsinspect"
)

// tlsFlags are shared by the tls subcommands.
type tlsFlags struct {
	protocol    string
	sni         string
	ip          string
	trustStore  string
	hostname    string
	save        bool
	concurrency int
}

func addTLSFlags(cmd *cobra.Command, f *tlsFlags, withTrust bool) {
	fl := cmd.Flags()
	fl.StringVarP(&f.protocol, "protocol", "p", "", "protocol: "+strings.Join(protocol.Names(), ", ")+" (default: autodetect)")
	fl.StringVar(&f.sni, "sni", "", "server name to send (default: the target host)")
	fl.StringVar(&f.ip, "ip", "", "connect to this IP address instead of resolving the host")
	if withTrust {
		fl.StringVar(&f.trustStore, "truststore", "", "validate against these roots instead of the system store")
		fl.StringVar(&f.hostname, "hostname", "", "hostname to validate (default: SNI or host)")
	}
	_ = cmd.RegisterFlagCompletionFunc("protocol", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return protocol.Names(), cobra.ShellCompDirectiveNoFileComp
	})
}

const tlsTargetHelp = `The target is host, host:port, [ipv6]:port or a URL such as smtp://mail.example.com.
The protocol is taken from --protocol, the URL scheme, the well-known port,
or the server's banner, in that order; otherwise direct TLS is assumed.

Only scan systems you are authorised to test. Probes are non-destructive:
raw probes stop after the server's first reply, and full handshakes send no
application data.`

func (a *app) dialer() netdial.Dialer {
	return netdial.Dialer{Timeout: a.cfg.TLS.Timeout.D(), Proxy: a.cfg.TLS.Proxy}
}

func (a *app) connector(ctx context.Context, arg string, f *tlsFlags) (*tlsinspect.Connector, error) {
	t, err := tlsinspect.ParseTarget(arg)
	if err != nil {
		return nil, usageError{err}
	}
	if f.protocol != "" {
		if _, err := protocol.Lookup(f.protocol); err != nil {
			return nil, usageError{err}
		}
	}
	if f.ip != "" && net.ParseIP(f.ip) == nil {
		return nil, usagef("--ip %q is not an IP address", f.ip)
	}
	a.log.Info("connecting", "target", t.String(), "proxy", a.cfg.TLS.Proxy != "")
	c, err := tlsinspect.NewConnector(ctx, t, tlsinspect.Options{
		Dialer: a.dialer(), Protocol: f.protocol, SNI: f.sni, IP: f.ip, Timeout: a.cfg.TLS.Timeout.D(),
	})
	if err != nil {
		return nil, networkErr(err)
	}
	a.log.Debug("protocol detected", "protocol", c.Detection.Protocol, "via", c.Detection.Via)
	return c, nil
}

// networkErr maps connection failures to exit code 6.
func networkErr(err error) error {
	if err == nil || exitcode.Code(err) != exitcode.Error {
		return err
	}
	var dnsErr *net.DNSError
	var opErr *net.OpError
	if errors.As(err, &dnsErr) || errors.As(err, &opErr) || errors.Is(err, protocol.ErrNotSupported) ||
		strings.Contains(err.Error(), "handshake") || strings.Contains(err.Error(), "upgrade") {
		return exitcode.With(exitcode.Network, err)
	}
	return err
}

func (a *app) inspectOptions(f *tlsFlags) (tlsinspect.InspectOptions, error) {
	o := tlsinspect.InspectOptions{Hostname: f.hostname, WarningDays: a.cfg.Expiry.WarningDays}
	if f.trustStore != "" {
		data, err := a.readInput(f.trustStore)
		if err != nil {
			return o, err
		}
		pool, _, err := certificate.LoadPool(data)
		if err != nil {
			return o, exitcode.New(exitcode.Usage, "truststore %s: %v", f.trustStore, err)
		}
		o.Roots, o.TrustStoreName = pool, f.trustStore
	}
	return o, nil
}

func newTLSCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tls",
		Short: "Inspect and scan remote TLS endpoints (HTTPS, SMTP, IMAP, LDAP, databases, ...)",
		Long:  "Inspect and scan remote TLS endpoints.\n\n" + tlsTargetHelp,
	}
	cmd.AddCommand(newTLSInspectCmd(a), newTLSScanCmd(a), newTLSVersionsCmd(a), newTLSCiphersCmd(a), newTLSGroupsCmd(a),
		newTLSChainCmd(a), newTLSALPNCmd(a), newTLSOCSPCmd(a), newTLSHistoryCmd(a), newTLSDiffCmd(a))
	return cmd
}

func newTLSInspectCmd(a *app) *cobra.Command {
	var f tlsFlags
	var resumption, showTranscript bool
	cmd := &cobra.Command{
		Use:   "inspect <target>",
		Short: "Connect and show the negotiated session and certificate chain",
		Long: `Connect once, perform a TLS handshake, and report the negotiated version,
cipher, key exchange group, ALPN, OCSP stapling, the certificate chain as
sent, and whether it validates against the trust store.

` + tlsTargetHelp,
		Example: `  sslknife tls inspect example.com
  sslknife tls inspect mail.example.com:25
  sslknife tls inspect ldap.example.com:389 --protocol ldap --truststore corp-root.pem
  sslknife tls inspect example.com --json | jq '.certificate.sans'`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			o, err := a.inspectOptions(&f)
			if err != nil {
				return err
			}
			o.Resumption = resumption
			c, err := a.connector(ctx, args[0], &f)
			if err != nil {
				return err
			}
			res, err := c.Inspect(ctx, o)
			if err != nil {
				return networkErr(err)
			}
			if err := a.saveObservation(ctx, &f, c, res.Snapshot(), res); err != nil {
				return err
			}
			return a.out.Emit(res, func(w io.Writer) error { return a.renderInspect(w, res, showTranscript) })
		},
	}
	addTLSFlags(cmd, &f, true)
	cmd.Flags().BoolVar(&resumption, "resumption", false, "also test session resumption (one extra handshake)")
	cmd.Flags().BoolVar(&showTranscript, "transcript", false, "show the STARTTLS negotiation")
	cmd.Flags().BoolVar(&f.save, "save", false, "record the observation in the vault history")
	return cmd
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func (a *app) renderInspect(w io.Writer, r *tlsinspect.Result, transcript bool) error {
	st := a.out.Style
	kv := output.NewKV(st)
	kv.Add("Target", r.Target).Add("Connected to", r.ConnectedTo)
	if len(r.IPs) > 1 {
		kv.Add("Resolved", strings.Join(r.IPs, ", "))
	}
	kv.Add("SNI", r.SNI)
	proto := r.Protocol
	how := "direct TLS"
	if proto.Method == "starttls" {
		how = "STARTTLS"
	}
	kv.Add("Protocol", fmt.Sprintf("%s (%s, detected by %s)", strings.ToUpper(proto.Protocol), how, proto.Via))
	if proto.Banner != "" {
		kv.Add("Banner", proto.Banner)
	}
	if proto.Method == "starttls" {
		kv.Add("STARTTLS", st.Level("SUPPORTED"))
	}
	if transcript {
		kv.List("Transcript", r.Transcript)
	}
	if r.Error != "" {
		kv.Add("Note", st.Yellow(r.Error))
	}

	kv.Heading("TLS")
	t := r.TLS
	if t.Version != "" {
		cipher := t.Cipher
		if t.CipherStrength != "modern" {
			cipher += "  " + st.Level(strings.ToUpper(t.CipherStrength))
		}
		kv.Add("Version", t.Version).Add("Cipher", cipher).Add("Key exchange", t.KeyExchangeGroup)
		alpn := t.ALPN
		if alpn == "" && len(t.OfferedALPN) > 0 {
			alpn = st.Dim("none (offered " + strings.Join(t.OfferedALPN, ", ") + ")")
		}
		kv.Add("ALPN", alpn)
		if t.HelloRetryRequest {
			kv.Add("HelloRetryRequest", "yes")
		}
	}
	if o := r.OCSP; o != nil {
		v := "no"
		if o.Stapled {
			v = "yes"
			if o.Status != "" {
				v += ", " + st.Level(map[string]string{"good": "OK", "revoked": "CRITICAL", "unknown": "WARNING"}[o.Status]) + " " + o.Status
				if !o.NextUpdate.IsZero() {
					v += ", next update " + o.NextUpdate.Format(time.RFC3339)
				}
			}
			if o.Error != "" {
				v += " (" + o.Error + ")"
			}
		}
		kv.Add("OCSP stapling", v)
		if o.MustStaple {
			kv.Add("Must-Staple", "yes")
		}
	}
	if t.SCTsInHandshake > 0 {
		kv.Addf("SCTs (TLS ext)", "%d", t.SCTsInHandshake)
	}
	if t.SessionResumption != nil {
		kv.Add("Resumption", yesNo(*t.SessionResumption))
	}

	if c := r.Certificate; c != nil {
		kv.Heading("Certificate")
		sans := c.SANs.All()
		if len(sans) > 12 {
			sans = append(sans[:10:10], st.Dim(fmt.Sprintf("… and %d more (see --json or 'cert sans %s')", len(sans)-10, r.Target)))
		}
		kv.Add("Subject", c.Subject.DN).Add("Issuer", c.Issuer.DN).
			List("SANs", sans).
			Add("Valid", c.Validity.NotBefore.Format(time.DateOnly)+" → "+c.Validity.NotAfter.Format(time.DateOnly)+
				"  "+st.Level(a.validityLevel(c.Validity))+" "+daysLabel(c.Validity)).
			Add("Key", c.PublicKey.Description).Add("Signature", c.SignatureAlgorithm).
			Add("SHA-256", certificate.Colon(c.Fingerprints.SHA256))
		if len(c.SCTs) > 0 {
			kv.Addf("Embedded SCTs", "%d", len(c.SCTs))
		}
	}
	kv.Heading("Validation")
	v := r.Validation
	trust := st.Level("VALID")
	switch {
	case !v.Trusted:
		trust = st.Level("INVALID") + "  " + v.Error
	case len(v.Missing) > 0:
		trust = st.Level("WARNING") + "  incomplete: the verifier supplied " + strings.Join(v.Missing, ", ")
	}
	kv.Add("Chain ("+v.TrustStore+")", trust)
	host := st.Level("VALID")
	if !v.HostnameValid {
		host = st.Level("INVALID")
	}
	kv.Add("Hostname", host+"  "+v.Hostname)
	order := st.Level("OK")
	if !v.ChainOrdered {
		order = st.Level("WARNING") + "  certificates are not in issuing order"
	}
	kv.Add("Chain order", order)
	if err := kv.Render(w); err != nil {
		return err
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, st.Bold(fmt.Sprintf("Chain as sent (%d)", len(r.Chain))))
	root := &output.Node{Label: "server"}
	cur := root
	for _, c := range r.Chain {
		label := fmt.Sprintf("#%d %s  %s", c.Position, shortDN(c.Subject), st.Dim(c.Key+", expires "+c.NotAfter.Format(time.DateOnly)))
		cur = cur.Add(label)
	}
	if err := output.RenderTree(w, root); err != nil {
		return err
	}
	var important []certificate.Finding
	for _, f := range r.Findings {
		if f.Severity != certificate.SevNotice {
			important = append(important, f)
		}
	}
	if len(important) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, st.Bold("Certificate findings"))
		for _, f := range important {
			fmt.Fprintf(w, "  %s  %s: %s\n", st.Level(strings.ToUpper(f.Severity)), f.ID, f.What)
		}
	}
	return nil
}

func shortDN(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		if strings.HasPrefix(part, "CN=") {
			return strings.TrimPrefix(part, "CN=")
		}
	}
	return dn
}

func (a *app) saveObservation(ctx context.Context, f *tlsFlags, c *tlsinspect.Connector, snap tlsinspect.Snapshot, full any) error {
	if !f.save {
		return nil
	}
	v, err := a.requireVault(ctx)
	if err != nil {
		return err
	}
	snapJSON, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	fullJSON, err := json.Marshal(full)
	if err != nil {
		return err
	}
	ep := database.Endpoint{Host: c.Target.Host, Port: c.Target.Port, SNI: c.SNI, Protocol: c.Detection.Protocol}
	s := &database.Scan{Kind: snap.Kind, ScannedAt: snap.ScannedAt, LeafSHA256: snap.LeafSHA256, Snapshot: snapJSON, Result: fullJSON}
	if err := v.db.RecordScan(ctx, ep, s); err != nil {
		return err
	}
	a.out.Infof("Saved observation %s", s.ID)
	return nil
}

func newTLSScanCmd(a *app) *cobra.Command {
	var f tlsFlags
	var failOn string
	var noCiphers bool
	cmd := &cobra.Command{
		Use:   "scan <target>",
		Short: "Full TLS assessment: versions, ciphers, groups, certificate and behaviour",
		Long: `Run a complete, non-destructive assessment of a TLS endpoint:

  - certificate, chain validation, hostname and expiry
  - protocol versions SSLv2 through TLS 1.3
  - every accepted cipher suite per version, with server order
  - key exchange groups and DH parameter sizes
  - secure renegotiation, TLS_FALLBACK_SCSV, compression, OCSP stapling

Findings carry a severity based on documented weaknesses (CVE, RFC) and
explain what, why and the evidence. There is no aggregate score.

With --fail-on, the exit status is 5 when a finding at or above that
severity exists (for CI pipelines).

` + tlsTargetHelp,
		Example: `  sslknife tls scan example.com
  sslknife tls scan smtp.example.com:25 --protocol smtp
  sslknife tls scan internal.example.com:8443 --truststore corp-root.pem --fail-on high
  sslknife tls scan example.com --json > scan.json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			threshold, err := severityRank(failOn)
			if err != nil {
				return usageError{err}
			}
			o, err := a.inspectOptions(&f)
			if err != nil {
				return err
			}
			o.Resumption = true
			c, err := a.connector(ctx, args[0], &f)
			if err != nil {
				return err
			}
			if !a.out.Machine() {
				a.out.Infof("Scanning %s (%s via %s)...", c.Target, c.Detection.Protocol, c.Detection.Method)
			}
			res, err := c.Scan(ctx, tlsinspect.ScanOptions{Inspect: o, Concurrency: f.concurrency, SkipCiphers: noCiphers})
			if err != nil {
				return networkErr(err)
			}
			if err := a.saveObservation(ctx, &f, c, res.Snapshot(), res); err != nil {
				return err
			}
			if err := a.out.Emit(res, func(w io.Writer) error { return a.renderScan(w, res) }); err != nil {
				return err
			}
			if threshold >= 0 {
				for _, x := range res.Findings {
					if r, _ := severityRank(x.Severity); r <= threshold {
						return exitcode.Silent(exitcode.CheckFailed)
					}
				}
			}
			return nil
		},
	}
	addTLSFlags(cmd, &f, true)
	cmd.Flags().IntVar(&f.concurrency, "concurrency", 0, "parallel probes (default from config, 8)")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "exit 5 if a finding of this severity or worse exists: critical|high|medium|low|info")
	cmd.Flags().BoolVar(&noCiphers, "no-ciphers", false, "skip cipher suite enumeration")
	cmd.Flags().BoolVar(&f.save, "save", false, "record the scan in the vault history")
	return cmd
}

func severityRank(s string) (int, error) {
	switch strings.ToLower(s) {
	case "":
		return -1, nil
	case tlsinspect.Critical:
		return 0, nil
	case tlsinspect.High:
		return 1, nil
	case tlsinspect.Medium:
		return 2, nil
	case tlsinspect.Low:
		return 3, nil
	case tlsinspect.Info:
		return 4, nil
	}
	return -1, fmt.Errorf("unknown severity %q", s)
}

func (a *app) severityLabel(s string) string {
	st := a.out.Style
	u := strings.ToUpper(s)
	switch s {
	case tlsinspect.Critical, tlsinspect.High:
		return st.Red(u)
	case tlsinspect.Medium:
		return st.Yellow(u)
	case tlsinspect.Low:
		return st.Cyan(u)
	}
	return st.Dim(u)
}

func (a *app) levelColor(level, s string) string {
	st := a.out.Style
	switch level {
	case "good":
		return st.Green(s)
	case "bad":
		return st.Red(s)
	case "warn":
		return st.Yellow(s)
	}
	return st.Dim(s)
}

func (a *app) renderScan(w io.Writer, r *tlsinspect.ScanResult) error {
	st := a.out.Style
	c := r.Connection
	fmt.Fprintf(w, "%s  %s  %s\n", st.Bold(c.Target), strings.ToUpper(c.Protocol.Protocol), st.Dim(c.ConnectedTo+", "+r.Duration))
	if c.TLS.Version != "" {
		fmt.Fprintf(w, "Negotiated %s, %s, %s\n", c.TLS.Version, c.TLS.Cipher, c.TLS.KeyExchangeGroup)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, st.Bold("TLS Security Summary"))
	fmt.Fprintln(w)
	t := output.NewTable("CHECK", "STATUS", "DETAIL")
	for _, s := range r.Summary {
		t.Row(s.Check, a.levelColor(s.Level, s.Status), st.Dim(s.Detail))
	}
	if err := t.Render(w, st); err != nil {
		return err
	}
	if len(r.Ciphers) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, st.Bold("Cipher Suites"))
		for i := len(r.Ciphers) - 1; i >= 0; i-- {
			cr := r.Ciphers[i]
			if len(cr.Suites) == 0 {
				continue
			}
			order := ""
			if cr.ServerPreferred != nil {
				order = map[bool]string{true: "server order", false: "client order"}[*cr.ServerPreferred]
			}
			fmt.Fprintf(w, "  %s  %s\n", cr.Version, st.Dim(order))
			for _, s := range cr.Suites {
				kx := ""
				if s.KeyExchange != nil {
					kx = st.Dim(" " + s.KeyExchange.String())
				}
				fmt.Fprintf(w, "    %-50s %s%s\n", s.Name, a.strengthLabel(s.Strength), kx)
			}
		}
	}
	fmt.Fprintln(w)
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, st.Green("No findings."))
		return nil
	}
	fmt.Fprintln(w, st.Bold(fmt.Sprintf("Findings (%d)", len(r.Findings))))
	for _, f := range r.Findings {
		fmt.Fprintf(w, "\n  %s  %s\n", a.severityLabel(f.Severity), st.Bold(f.What))
		fmt.Fprintf(w, "    %s %s\n", st.Dim("why:     "), f.Why)
		if f.Evidence != "" {
			fmt.Fprintf(w, "    %s %s\n", st.Dim("evidence:"), f.Evidence)
		}
		if f.Reference != "" {
			fmt.Fprintf(w, "    %s %s\n", st.Dim("ref:     "), f.Reference)
		}
	}
	return nil
}

func (a *app) strengthLabel(s string) string {
	st := a.out.Style
	pad := strings.Repeat(" ", max(0, 10-len(s)))
	switch s {
	case "modern":
		return st.Green(s) + pad
	case "deprecated":
		return st.Yellow(s) + pad
	case "weak":
		return st.Red(s) + pad
	case "insecure":
		return st.Red("INSECURE") + pad
	}
	return s + pad
}

type versionsView struct {
	Target   string                  `json:"target"`
	Protocol string                  `json:"protocol"`
	Versions []scanner.VersionResult `json:"versions"`
}

func newTLSVersionsCmd(a *app) *cobra.Command {
	var f tlsFlags
	cmd := &cobra.Command{
		Use:   "versions <target>",
		Short: "Test which protocol versions (SSLv2–TLS 1.3) the server accepts",
		Long:  "Probe each protocol version with a dedicated ClientHello.\n\n" + tlsTargetHelp,
		Example: `  sslknife tls versions example.com
  sslknife tls versions imap.example.com:143`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.connector(cmd.Context(), args[0], &f)
			if err != nil {
				return err
			}
			vs := c.Prober(a.concurrency(f.concurrency)).Versions(cmd.Context())
			view := versionsView{Target: c.Target.String(), Protocol: c.Detection.Protocol, Versions: vs}
			return a.out.Emit(view, func(w io.Writer) error {
				for _, v := range vs {
					status := "NOT SUPPORTED"
					level := "good"
					switch {
					case v.Error != "":
						status, level = "ERROR "+v.Error, "warn"
					case v.Supported && v.ID < scanner.VersionTLS12:
						status, level = "SUPPORTED  (insecure legacy version)", "bad"
					case v.Supported:
						status = "SUPPORTED"
					case v.ID >= scanner.VersionTLS12:
						level = "warn"
					}
					fmt.Fprintf(w, "%-9s %s\n", v.Version, a.levelColor(level, status))
				}
				return nil
			})
		},
	}
	addTLSFlags(cmd, &f, false)
	cmd.Flags().IntVar(&f.concurrency, "concurrency", 0, "parallel probes")
	return cmd
}

func (a *app) concurrency(flag int) int {
	if flag > 0 {
		return flag
	}
	return a.cfg.TLS.Concurrency
}

type ciphersView struct {
	Target   string                 `json:"target"`
	Protocol string                 `json:"protocol"`
	Ciphers  []scanner.CipherResult `json:"ciphers"`
}

func parseVersion(s string) (uint16, error) {
	switch strings.ToLower(strings.NewReplacer(" ", "", ".", "", "v", "").Replace(s)) {
	case "ssl3", "ssl30":
		return scanner.VersionSSL3, nil
	case "tls1", "tls10":
		return scanner.VersionTLS10, nil
	case "tls11":
		return scanner.VersionTLS11, nil
	case "tls12":
		return scanner.VersionTLS12, nil
	case "tls13":
		return scanner.VersionTLS13, nil
	}
	return 0, fmt.Errorf("unknown version %q (use ssl3, tls1.0, tls1.1, tls1.2, tls1.3)", s)
}

func newTLSCiphersCmd(a *app) *cobra.Command {
	var f tlsFlags
	var versions []string
	cmd := &cobra.Command{
		Use:   "ciphers <target>",
		Short: "Enumerate accepted cipher suites per protocol version",
		Long: `Enumerate every cipher suite the server accepts, for each supported version,
using SSLKnife's own ClientHello (independent of the local TLS library).
Suites are classified as modern, deprecated, weak or insecure.

` + tlsTargetHelp,
		Example: `  sslknife tls ciphers example.com
  sslknife tls ciphers example.com --version tls1.2 --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			c, err := a.connector(ctx, args[0], &f)
			if err != nil {
				return err
			}
			p := c.Prober(a.concurrency(f.concurrency))
			var vs []uint16
			if len(versions) > 0 {
				for _, s := range versions {
					v, err := parseVersion(s)
					if err != nil {
						return usageError{err}
					}
					vs = append(vs, v)
				}
			} else {
				for _, v := range p.Versions(ctx) {
					if v.Supported && v.ID != scanner.VersionSSL2 {
						vs = append(vs, v.ID)
					}
				}
			}
			view := ciphersView{Target: c.Target.String(), Protocol: c.Detection.Protocol, Ciphers: p.CiphersAll(ctx, vs)}
			return a.out.Emit(view, func(w io.Writer) error {
				st := a.out.Style
				for i := len(view.Ciphers) - 1; i >= 0; i-- {
					cr := view.Ciphers[i]
					order := ""
					if cr.ServerPreferred != nil {
						order = map[bool]string{true: "  (server order)", false: "  (client order)"}[*cr.ServerPreferred]
					}
					fmt.Fprintf(w, "%s%s\n", st.Bold(cr.Version), st.Dim(order))
					if len(cr.Suites) == 0 {
						fmt.Fprintln(w, st.Dim("  no suites accepted"))
					}
					for _, s := range cr.Suites {
						detail := ""
						if s.KeyExchange != nil {
							detail = s.KeyExchange.String()
						}
						if len(s.Reasons) > 0 {
							detail = strings.TrimSpace(detail + "  " + s.Reasons[0])
						}
						fmt.Fprintf(w, "  %-50s %s %s\n", s.Name, a.strengthLabel(s.Strength), st.Dim(detail))
					}
					if cr.Error != "" {
						fmt.Fprintf(w, "  %s %s\n", st.Yellow("error:"), cr.Error)
					}
					fmt.Fprintln(w)
				}
				if len(view.Ciphers) == 0 {
					fmt.Fprintln(w, "No protocol version accepted.")
				}
				return nil
			})
		},
	}
	addTLSFlags(cmd, &f, false)
	cmd.Flags().StringSliceVar(&versions, "version", nil, "only these versions (tls1.2, tls1.3, ...)")
	cmd.Flags().IntVar(&f.concurrency, "concurrency", 0, "parallel probes")
	return cmd
}

func newTLSGroupsCmd(a *app) *cobra.Command {
	var f tlsFlags
	cmd := &cobra.Command{
		Use:     "groups <target>",
		Short:   "List supported key exchange groups (including post-quantum hybrids)",
		Example: "  sslknife tls groups example.com",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			c, err := a.connector(ctx, args[0], &f)
			if err != nil {
				return err
			}
			p := c.Prober(a.concurrency(0))
			res := scanner.GroupResult{TLS13: p.Groups13(ctx)}
			tls12 := p.ProbeVersion(ctx, scanner.VersionTLS12)
			if tls12.Supported {
				cr := p.Ciphers(ctx, scanner.VersionTLS12)
				var ecdhe []uint16
				for _, s := range cr.Suites {
					if s.KeyExch == "ECDHE" {
						ecdhe = append(ecdhe, s.ID)
					}
				}
				res.TLS12 = p.Curves12(ctx, scanner.VersionTLS12, ecdhe)
			}
			return a.out.Emit(res, func(w io.Writer) error {
				kv := output.NewKV(a.out.Style)
				none := func(v []string) []string {
					if len(v) == 0 {
						return []string{a.out.Style.Dim("none")}
					}
					return v
				}
				kv.List("TLS 1.3", none(res.TLS13)).List("TLS 1.2 ECDHE", none(res.TLS12))
				return kv.Render(w)
			})
		},
	}
	addTLSFlags(cmd, &f, false)
	return cmd
}

func newTLSChainCmd(a *app) *cobra.Command {
	var f tlsFlags
	cmd := &cobra.Command{
		Use:     "chain <target>",
		Short:   "Show the certificate chain sent by the server and validate it",
		Example: "  sslknife tls chain example.com\n  sslknife tls chain mail.example.com:587 --truststore corp.pem",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			o, err := a.inspectOptions(&f)
			if err != nil {
				return err
			}
			c, err := a.connector(ctx, args[0], &f)
			if err != nil {
				return err
			}
			res, err := c.Inspect(ctx, o)
			if err != nil {
				return networkErr(err)
			}
			view := map[string]any{"target": res.Target, "chain": res.Chain, "validation": res.Validation}
			err = a.out.Emit(view, func(w io.Writer) error {
				st := a.out.Style
				root := &output.Node{Label: st.Bold(res.Target)}
				cur := root
				for _, cc := range res.Chain {
					flags := []string{cc.Key, "expires " + cc.NotAfter.Format(time.DateOnly)}
					if cc.SelfSigned {
						flags = append(flags, "self-signed")
					}
					if !cc.IssuedByNext && cc.Position+1 < len(res.Chain) {
						flags = append(flags, st.Yellow("next certificate is not its issuer"))
					}
					cur = cur.Add(fmt.Sprintf("#%d %s  %s", cc.Position, shortDN(cc.Subject), st.Dim(strings.Join(flags, ", "))))
				}
				if err := output.RenderTree(w, root); err != nil {
					return err
				}
				v := res.Validation
				if v.Trusted {
					fmt.Fprintf(w, "\nTrusted (%s): %s\n", v.TrustStore, strings.Join(v.VerifiedChain, " → "))
				} else {
					fmt.Fprintf(w, "\n%s (%s trust store): %s\n", st.Level("INVALID"), v.TrustStore, v.Error)
				}
				return nil
			})
			if err == nil && !res.Validation.Trusted {
				return exitcode.Silent(exitcode.CheckFailed)
			}
			return err
		},
	}
	addTLSFlags(cmd, &f, true)
	return cmd
}

// alpnCandidates are ALPN IDs probed by `tls alpn` (IANA registry subset).
var alpnCandidates = []string{"h2", "http/1.1", "http/1.0", "spdy/3.1", "acme-tls/1", "xmpp-client", "xmpp-server",
	"imap", "pop3", "managesieve", "smb", "irc", "dot", "stun.turn", "mqtt", "postgresql", "ftp", "coap", "grpc-exp"}

func newTLSALPNCmd(a *app) *cobra.Command {
	var f tlsFlags
	var extra []string
	cmd := &cobra.Command{
		Use:     "alpn <target>",
		Short:   "List ALPN protocols the server accepts",
		Example: "  sslknife tls alpn example.com\n  sslknife tls alpn example.com --try h3,myproto/1",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			c, err := a.connector(ctx, args[0], &f)
			if err != nil {
				return err
			}
			cands := append(append([]string{}, alpnCandidates...), extra...)
			accepted := make([]bool, len(cands))
			sem := make(chan struct{}, a.concurrency(0))
			done := make(chan struct{})
			for i, p := range cands {
				go func() {
					sem <- struct{}{}
					defer func() { <-sem; done <- struct{}{} }()
					accepted[i] = alpnAccepted(ctx, c, p)
				}()
			}
			for range cands {
				<-done
			}
			var list []string
			for i, ok := range accepted {
				if ok {
					list = append(list, cands[i])
				}
			}
			if list == nil {
				list = []string{}
			}
			return a.out.Emit(map[string]any{"target": c.Target.String(), "alpn": list}, func(w io.Writer) error {
				if len(list) == 0 {
					fmt.Fprintln(w, "No ALPN protocol negotiated (the server may not use ALPN).")
				}
				for _, p := range list {
					fmt.Fprintln(w, p)
				}
				return nil
			})
		},
	}
	addTLSFlags(cmd, &f, false)
	cmd.Flags().StringSliceVar(&extra, "try", nil, "additional ALPN IDs to test")
	return cmd
}

func alpnAccepted(ctx context.Context, c *tlsinspect.Connector, proto string) bool {
	raw, err := c.Dial(ctx)
	if err != nil {
		return false
	}
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{ServerName: c.SNI, InsecureSkipVerify: true, NextProtos: []string{proto}, MinVersion: tls.VersionTLS10}) //nolint:gosec // capability probe only
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	if err := conn.HandshakeContext(ctx); err != nil {
		return false
	}
	return conn.ConnectionState().NegotiatedProtocol == proto
}

func newTLSOCSPCmd(a *app) *cobra.Command {
	var f tlsFlags
	var noQuery bool
	cmd := &cobra.Command{
		Use:   "ocsp <target>",
		Short: "Check OCSP stapling and ask the CA's OCSP responder for the status",
		Long: `Report the OCSP response stapled by the server, then query the OCSP
responder named in the certificate (unless --no-query). Exit status is 5 when
the certificate is revoked.`,
		Example: "  sslknife tls ocsp example.com",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			c, err := a.connector(ctx, args[0], &f)
			if err != nil {
				return err
			}
			res, err := c.Inspect(ctx, tlsinspect.InspectOptions{})
			if err != nil {
				return networkErr(err)
			}
			view := map[string]any{"target": res.Target, "stapled": res.OCSP}
			var live *tlsinspect.OCSPInfo
			var liveErr error
			if !noQuery {
				certs, err := c.Certificates(ctx)
				if err != nil {
					return networkErr(err)
				}
				var issuer *x509.Certificate
				if len(certs) > 1 {
					issuer = certs[1]
				}
				live, liveErr = tlsinspect.QueryOCSP(ctx, certs[0], issuer, a.dialer())
				view["responder"] = live
				if liveErr != nil {
					view["responder_error"] = liveErr.Error()
				}
			}
			err = a.out.Emit(view, func(w io.Writer) error {
				st := a.out.Style
				kv := output.NewKV(st)
				s := res.OCSP
				if s.Stapled {
					kv.Add("Stapled", "yes, status "+s.Status)
					kv.Add("Produced", s.ProducedAt.Format(time.RFC3339)).Add("Next update", s.NextUpdate.Format(time.RFC3339))
				} else {
					kv.Add("Stapled", "no")
				}
				kv.List("Responders", s.Responders)
				if !noQuery {
					if liveErr != nil {
						kv.Add("Responder query", st.Yellow(liveErr.Error()))
					} else {
						label := map[string]string{"good": "OK", "revoked": "CRITICAL", "unknown": "WARNING"}[live.Status]
						kv.Add("Responder says", st.Level(label)+" "+live.Status)
						kv.Add("This update", live.ThisUpdate.Format(time.RFC3339)).Add("Next update", live.NextUpdate.Format(time.RFC3339))
						if live.Status == "revoked" {
							kv.Add("Revoked at", live.RevokedAt.Format(time.RFC3339))
						}
					}
				}
				return kv.Render(w)
			})
			if err == nil && (res.OCSP.Status == "revoked" || live != nil && live.Status == "revoked") {
				return exitcode.Silent(exitcode.CheckFailed)
			}
			return err
		},
	}
	addTLSFlags(cmd, &f, false)
	cmd.Flags().BoolVar(&noQuery, "no-query", false, "only report the stapled response")
	return cmd
}

type historyEntry struct {
	ID        string              `json:"id"`
	Kind      string              `json:"kind"`
	ScannedAt time.Time           `json:"scanned_at"`
	Snapshot  tlsinspect.Snapshot `json:"snapshot"`
}

func newTLSHistoryCmd(a *app) *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "history [target]",
		Short: "Show recorded observations of endpoints (from --save)",
		Example: `  sslknife tls history
  sslknife tls history api.example.com:443`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			v, err := a.requireVault(ctx)
			if err != nil {
				return err
			}
			if len(args) == 0 {
				eps, err := v.db.Endpoints(ctx)
				if err != nil {
					return err
				}
				type epView struct {
					Target    string    `json:"target"`
					SNI       string    `json:"sni,omitempty"`
					Protocol  string    `json:"protocol"`
					FirstSeen time.Time `json:"first_seen"`
					LastSeen  time.Time `json:"last_seen"`
				}
				views := []epView{}
				for _, e := range eps {
					views = append(views, epView{net.JoinHostPort(e.Host, fmt.Sprint(e.Port)), e.SNI, e.Protocol, e.FirstSeen, e.LastSeen})
				}
				return a.out.Emit(views, func(w io.Writer) error {
					if len(views) == 0 {
						fmt.Fprintln(w, "No observations recorded. Use 'tls inspect --save' or 'tls scan --save'.")
						return nil
					}
					t := output.NewTable("TARGET", "PROTOCOL", "FIRST SEEN", "LAST SEEN")
					for _, e := range views {
						t.Row(e.Target, e.Protocol, e.FirstSeen.Format(time.DateOnly), e.LastSeen.Format(time.DateTime))
					}
					return t.Render(w, a.out.Style)
				})
			}
			entries, err := a.historyFor(ctx, v, args[0], limit)
			if err != nil {
				return err
			}
			return a.out.Emit(entries, func(w io.Writer) error {
				st := a.out.Style
				var prev *tlsinspect.Snapshot
				for i := len(entries) - 1; i >= 0; i-- {
					e := entries[i]
					s := e.Snapshot
					fmt.Fprintf(w, "%s  %s  %s\n", st.Bold(e.ScannedAt.Format(time.DateTime)), st.Dim(e.ID), e.Kind)
					vers := s.Negotiated
					if len(s.Versions) > 0 {
						vers = strings.Join(s.Versions, " + ")
					}
					fmt.Fprintf(w, "  %s\n  certificate %s  %s  expires %s\n", vers, s.LeafSHA256[:16], shortDN(s.Subject), s.NotAfter.Format(time.DateOnly))
					if prev != nil {
						for _, ch := range tlsinspect.DiffSnapshots(*prev, s) {
							if ch.Changed {
								fmt.Fprintf(w, "  %s %s changed\n", st.Yellow("!"), ch.Field)
							}
						}
					}
					prev = &entries[i].Snapshot
					fmt.Fprintln(w)
				}
				return nil
			})
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 20, "maximum number of observations")
	return cmd
}

func (a *app) historyFor(ctx context.Context, v *vault, arg string, limit int) ([]historyEntry, error) {
	t, err := tlsinspect.ParseTarget(arg)
	if err != nil {
		return nil, usageError{err}
	}
	port := t.Port
	if !strings.Contains(arg, ":") {
		port = 0
	}
	eps, err := v.db.FindEndpoints(ctx, t.Host, port)
	if err != nil {
		return nil, err
	}
	if len(eps) == 0 {
		return nil, exitcode.New(exitcode.NotFound, "no observations recorded for %s", arg)
	}
	var out []historyEntry
	for _, e := range eps {
		scans, err := v.db.Scans(ctx, e.ID, limit, false)
		if err != nil {
			return nil, err
		}
		for _, s := range scans {
			var snap tlsinspect.Snapshot
			if err := json.Unmarshal(s.Snapshot, &snap); err != nil {
				return nil, err
			}
			out = append(out, historyEntry{ID: s.ID, Kind: s.Kind, ScannedAt: s.ScannedAt, Snapshot: snap})
		}
	}
	return out, nil
}

func newTLSDiffCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff <scan1> <scan2> | diff <target>",
		Short: "Compare two recorded observations",
		Long: `Compare two recorded observations (IDs from 'tls history'), or the two most
recent observations of a target. Detects certificate, issuer, SAN, expiry,
key, version and cipher changes. Exit status is 5 when something changed.`,
		Example: `  sslknife tls diff api.example.com:443
  sslknife tls diff 3f2a9c 81be02`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			v, err := a.requireVault(ctx)
			if err != nil {
				return err
			}
			var snaps [2]tlsinspect.Snapshot
			var ids [2]string
			if len(args) == 1 {
				entries, err := a.historyFor(ctx, v, args[0], 2)
				if err != nil {
					return err
				}
				if len(entries) < 2 {
					return exitcode.New(exitcode.NotFound, "need at least two observations of %s", args[0])
				}
				snaps[0], snaps[1] = entries[1].Snapshot, entries[0].Snapshot
				ids[0], ids[1] = entries[1].ID, entries[0].ID
			} else {
				for i, ref := range args {
					s, err := v.db.GetScan(ctx, ref)
					if err != nil {
						return mapLookupErr(err, ref)
					}
					if err := json.Unmarshal(s.Snapshot, &snaps[i]); err != nil {
						return err
					}
					ids[i] = s.ID
				}
			}
			changes := tlsinspect.DiffSnapshots(snaps[0], snaps[1])
			identical := certificate.Identical(changes)
			view := map[string]any{"a": ids[0], "b": ids[1], "identical": identical, "changes": changes}
			err = a.out.Emit(view, func(w io.Writer) error {
				st := a.out.Style
				fmt.Fprintf(w, "%s (%s) → %s (%s)\n\n", ids[0], snaps[0].ScannedAt.Format(time.DateTime), ids[1], snaps[1].ScannedAt.Format(time.DateTime))
				for _, c := range changes {
					fmt.Fprintf(w, "%s:\n", st.Bold(c.Field))
					for _, l := range certificate.FormatChange(c) {
						switch {
						case strings.HasPrefix(l, "+"):
							l = st.Green(l)
						case strings.HasPrefix(l, "-"):
							l = st.Red(l)
						default:
							l = st.Dim(l)
						}
						fmt.Fprintln(w, l)
					}
				}
				return nil
			})
			if err == nil && !identical {
				return exitcode.Silent(exitcode.CheckFailed)
			}
			return err
		},
	}
	return cmd
}

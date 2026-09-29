package server

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/matusso/sslknife/internal/certificate"
	"github.com/matusso/sslknife/internal/ct"
	"github.com/matusso/sslknife/internal/database"
	"github.com/matusso/sslknife/internal/inventory"
	"github.com/matusso/sslknife/internal/keys"
	"github.com/matusso/sslknife/internal/tlsinspect"
	"github.com/matusso/sslknife/internal/views"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

type apiError struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, apiError{Error: msg})
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, database.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, database.ErrAmbiguous):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, database.ErrIntegrity):
		s.log.Error("database integrity error", "err", err)
		writeError(w, http.StatusInternalServerError, "database integrity error")
	default:
		s.log.Warn("request failed", "err", err)
		writeError(w, http.StatusBadRequest, err.Error())
	}
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

func (s *Server) routes(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/session", s.getSession)
	m.HandleFunc("POST /api/v1/logout", s.postLogout)
	m.HandleFunc("GET /api/v1/dashboard", s.getDashboard)
	m.HandleFunc("GET /api/v1/certificates", s.listCertificates)
	m.HandleFunc("POST /api/v1/certificates", s.importCertificates)
	m.HandleFunc("GET /api/v1/certificates/{id}", s.getCertificate)
	m.HandleFunc("GET /api/v1/certificates/{id}/pem", s.getCertificatePEM)
	m.HandleFunc("DELETE /api/v1/certificates/{id}", s.deleteCertificate)
	m.HandleFunc("POST /api/v1/certificates/{id}/tags", s.addCertificateTags)
	m.HandleFunc("DELETE /api/v1/certificates/{id}/tags/{tag}", s.removeCertificateTag)
	m.HandleFunc("GET /api/v1/keys", s.listKeys)
	m.HandleFunc("GET /api/v1/ssh/keys", s.listSSHKeys)
	m.HandleFunc("GET /api/v1/search", s.search)
	m.HandleFunc("POST /api/v1/tls/inspect", s.tlsInspect)
	m.HandleFunc("POST /api/v1/tls/scan", s.tlsScan)
	m.HandleFunc("GET /api/v1/tls/endpoints", s.listEndpoints)
	m.HandleFunc("GET /api/v1/tls/scans", s.listScans)
	m.HandleFunc("GET /api/v1/tls/scans/{id}", s.getScan)
	m.HandleFunc("GET /api/v1/ct/watches", s.listWatches)
	m.HandleFunc("POST /api/v1/ct/watches", s.addWatch)
	m.HandleFunc("DELETE /api/v1/ct/watches/{id}", s.deleteWatch)
	m.HandleFunc("GET /api/v1/ct/observations", s.listObservations)
	m.HandleFunc("POST /api/v1/ct/observations/{id}/ack", s.ackObservation)
	m.HandleFunc("POST /api/v1/ct/check", s.ctCheck)
	m.HandleFunc("GET /api/v1/openapi.json", s.openAPI)
	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { writeError(w, http.StatusNotFound, "no such endpoint") })
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
	v := map[string]string{"version": s.opts.Version}
	if sess := s.auth.lookup(r); sess != nil {
		v["csrf_token"] = sess.csrf
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) postLogout(w http.ResponseWriter, r *http.Request) {
	s.auth.logout(r)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, //nolint:gosec // Secure is set whenever HTTPS is used; loopback HTTP mode cannot use it
		SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// Dashboard is the /dashboard response.
type Dashboard struct {
	Counts        inventory.Counts      `json:"counts"`
	CT            ctCounts              `json:"ct"`
	Expiring      []views.CertSummary   `json:"expiring"`
	RecentCerts   []views.CertSummary   `json:"recent_certificates"`
	RecentScans   []scanEntry           `json:"recent_scans"`
	CTDiscoveries []views.CTObservation `json:"ct_discoveries"`
	WeakFindings  []endpointFinding     `json:"weak_findings"`
}

type ctCounts struct {
	New        int `json:"new"`
	Changed    int `json:"changed"`
	Unexpected int `json:"unexpected"`
}

type scanEntry struct {
	ID        string              `json:"id"`
	Target    string              `json:"target"`
	Kind      string              `json:"kind"`
	ScannedAt time.Time           `json:"scanned_at"`
	Snapshot  tlsinspect.Snapshot `json:"snapshot"`
}

type endpointFinding struct {
	Target  string             `json:"target"`
	ScanID  string             `json:"scan_id"`
	Finding tlsinspect.Finding `json:"finding"`
}

func (s *Server) getDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var d Dashboard
	var err error
	if d.Counts, err = s.inv.Stats(ctx, s.opts.Config.Expiry.WarningDays); err != nil {
		s.fail(w, err)
		return
	}
	week := time.Now().Add(-7 * 24 * time.Hour)
	d.CT.New, _ = s.db.CountCTObservations(ctx, ct.StatusNew, week)
	d.CT.Changed, _ = s.db.CountCTObservations(ctx, ct.StatusChanged, week)
	d.CT.Unexpected, _ = s.db.CountCTObservations(ctx, ct.StatusUnexpected, week)
	exp, err := s.inv.Expiring(ctx, time.Duration(s.opts.Config.Expiry.WarningDays)*24*time.Hour, true)
	if err != nil {
		s.fail(w, err)
		return
	}
	d.Expiring = views.SummarizeAll(exp, s.expiry())
	recent, err := s.db.RecentCertificates(ctx, 8)
	if err != nil {
		s.fail(w, err)
		return
	}
	d.RecentCerts = views.SummarizeAll(recent, s.expiry())
	scans, err := s.db.RecentScans(ctx, 50, true)
	if err != nil {
		s.fail(w, err)
		return
	}
	d.RecentScans, d.WeakFindings = []scanEntry{}, []endpointFinding{}
	latest := map[string]bool{}
	for _, sc := range scans {
		target := net.JoinHostPort(sc.Host, strconv.Itoa(sc.Port))
		if len(d.RecentScans) < 10 {
			var snap tlsinspect.Snapshot
			_ = json.Unmarshal(sc.Snapshot, &snap)
			d.RecentScans = append(d.RecentScans, scanEntry{ID: sc.ID, Target: target, Kind: sc.Kind, ScannedAt: sc.ScannedAt, Snapshot: snap})
		}
		if sc.Kind != "scan" || latest[target] {
			continue
		}
		latest[target] = true
		var res tlsinspect.ScanResult
		if json.Unmarshal(sc.Result, &res) != nil {
			continue
		}
		for _, f := range res.Findings {
			if f.Severity == tlsinspect.Critical || f.Severity == tlsinspect.High || f.Severity == tlsinspect.Medium {
				d.WeakFindings = append(d.WeakFindings, endpointFinding{Target: target, ScanID: sc.ID, Finding: f})
			}
		}
	}
	obs, err := s.db.CTObservations(ctx, database.CTObservationFilter{Limit: 50})
	if err != nil {
		s.fail(w, err)
		return
	}
	patterns := s.watchPatterns(ctx)
	d.CTDiscoveries = []views.CTObservation{}
	for _, o := range obs {
		if o.Status != ct.StatusKnown && o.Status != ct.StatusExpired && !o.Acknowledged && len(d.CTDiscoveries) < 10 {
			d.CTDiscoveries = append(d.CTDiscoveries, views.NewCTObservation(o, patterns[o.WatchID]))
		}
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) watchPatterns(ctx context.Context) map[string]string {
	m := map[string]string{}
	if ws, err := s.db.CTWatches(ctx); err == nil {
		for _, w := range ws {
			m[w.ID] = w.Pattern()
		}
	}
	return m
}

func (s *Server) listCertificates(w http.ResponseWriter, r *http.Request) {
	certs, err := s.inv.ListCertificates(r.Context(), inventory.ListFilter{Query: r.URL.Query().Get("q")})
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, views.SummarizeAll(certs, s.expiry()))
}

type importRequest struct {
	PEM     string   `json:"pem"`
	Name    string   `json:"name"`
	Tags    []string `json:"tags"`
	Comment string   `json:"comment"`
}

type importResponse struct {
	Certificates []views.CertSummary `json:"certificates"`
	Created      int                 `json:"created"`
	IgnoredKeys  int                 `json:"ignored_private_keys"`
}

// importCertificates accepts PEM/base64 certificates. Private keys are
// never accepted through the API; they are counted and ignored.
func (s *Server) importCertificates(w http.ResponseWriter, r *http.Request) {
	var req importRequest
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	certs, err := certificate.Parse([]byte(req.PEM))
	if err != nil {
		writeError(w, http.StatusBadRequest, "no certificate found in the submitted text")
		return
	}
	res, err := s.inv.ImportCertificates(r.Context(), certs, inventory.ImportOptions{Name: req.Name, Tags: req.Tags, Comment: req.Comment, Source: "web"})
	if err != nil {
		s.fail(w, err)
		return
	}
	out := importResponse{Certificates: []views.CertSummary{}}
	for _, x := range res {
		out.Certificates = append(out.Certificates, views.Summarize(x.Cert, s.expiry()))
		if x.Created {
			out.Created++
		}
	}
	if ks, err := keys.ParsePrivateKeys([]byte(req.PEM), nil); err == nil || errors.Is(err, keys.ErrPasswordRequired) {
		out.IgnoredKeys = max(len(ks), 1)
	}
	writeJSON(w, http.StatusOK, out)
}

// CertificateDetail is the /certificates/{id} response.
type CertificateDetail struct {
	Summary  views.CertSummary     `json:"summary"`
	Details  certificate.Info      `json:"details"`
	Chain    []views.CertSummary   `json:"chain"`
	Issued   []views.CertSummary   `json:"issued"`
	Notes    []note                `json:"notes"`
	CT       []views.CTObservation `json:"ct"`
	History  []scanEntry           `json:"history"`
	Findings []certificate.Finding `json:"findings"`
}

type note struct {
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Server) getCertificate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	row, c, err := s.inv.Certificate(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	d := CertificateDetail{Summary: views.Summarize(row, s.expiry()),
		Details: certificate.Describe(c, certificate.Options{WarningDays: s.opts.Config.Expiry.WarningDays, IncludePEM: true}),
		Notes:   []note{}, CT: []views.CTObservation{}, History: []scanEntry{}}
	chain, err := s.inv.Chain(ctx, row)
	if err != nil {
		s.fail(w, err)
		return
	}
	d.Chain = views.SummarizeAll(chain, s.expiry())
	var chainCerts []*x509.Certificate
	for _, cr := range chain {
		if pc, err := x509.ParseCertificate(cr.DER); err == nil {
			chainCerts = append(chainCerts, pc)
		}
	}
	d.Findings = certificate.Lint(chainCerts, certificate.LintOptions{})
	if d.Findings == nil {
		d.Findings = []certificate.Finding{}
	}
	children, err := s.inv.Children(ctx, row)
	if err != nil {
		s.fail(w, err)
		return
	}
	d.Issued = views.SummarizeAll(children, s.expiry())
	notes, _ := s.db.Notes(ctx, "cert", row.ID)
	for _, n := range notes {
		d.Notes = append(d.Notes, note{Body: n.Body, CreatedAt: n.CreatedAt})
	}
	obs, _ := s.db.CTObservations(ctx, database.CTObservationFilter{Limit: 1000})
	patterns := s.watchPatterns(ctx)
	for _, o := range obs {
		if o.CertSHA256 == row.SHA256 || o.KnownCertID == row.ID {
			d.CT = append(d.CT, views.NewCTObservation(o, patterns[o.WatchID]))
		}
	}
	scans, _ := s.db.RecentScans(ctx, 500, false)
	for _, sc := range scans {
		if sc.LeafSHA256 == row.SHA256 {
			var snap tlsinspect.Snapshot
			_ = json.Unmarshal(sc.Snapshot, &snap)
			d.History = append(d.History, scanEntry{ID: sc.ID, Target: net.JoinHostPort(sc.Host, strconv.Itoa(sc.Port)), Kind: sc.Kind, ScannedAt: sc.ScannedAt, Snapshot: snap})
		}
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) getCertificatePEM(w http.ResponseWriter, r *http.Request) {
	_, c, err := s.inv.Certificate(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="certificate.pem"`)
	_, _ = w.Write(certificate.EncodePEM(c)) //nolint:gosec // PEM served as an attachment with nosniff, never as HTML
}

func (s *Server) deleteCertificate(w http.ResponseWriter, r *http.Request) {
	id, err := s.db.ResolveCertificate(r.Context(), r.PathValue("id"))
	if err == nil {
		err = s.db.DeleteCertificate(r.Context(), id)
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

func (s *Server) addCertificateTags(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tags []string `json:"tags"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := s.db.ResolveCertificate(r.Context(), r.PathValue("id"))
	if err == nil {
		err = s.db.AddTags(r.Context(), "cert", id, req.Tags)
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "added": req.Tags})
}

func (s *Server) removeCertificateTag(w http.ResponseWriter, r *http.Request) {
	id, err := s.db.ResolveCertificate(r.Context(), r.PathValue("id"))
	if err == nil {
		err = s.db.RemoveTags(r.Context(), "cert", id, []string{r.PathValue("tag")})
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "removed": r.PathValue("tag")})
}

// listKeys returns key metadata only; private material is never served.
func (s *Server) listKeys(w http.ResponseWriter, r *http.Request) {
	ks, err := s.db.QueryKeys(r.Context(), "", nil)
	if err != nil {
		s.fail(w, err)
		return
	}
	out := []views.Key{}
	for _, k := range ks {
		out = append(out, views.NewKey(k))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listSSHKeys(w http.ResponseWriter, r *http.Request) {
	ks, err := s.db.QuerySSHKeys(r.Context(), "", nil)
	if err != nil {
		s.fail(w, err)
		return
	}
	out := []views.SSHKey{}
	for _, k := range ks {
		out = append(out, views.NewSSHKey(k))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	res, err := s.inv.Search(r.Context(), r.URL.Query().Get("q"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	out := map[string]any{"certificates": views.SummarizeAll(res.Certificates, s.expiry())}
	ks := []views.Key{}
	for _, k := range res.Keys {
		ks = append(ks, views.NewKey(k))
	}
	ss := []views.SSHKey{}
	for _, k := range res.SSHKeys {
		ss = append(ss, views.NewSSHKey(k))
	}
	out["keys"], out["ssh_keys"] = ks, ss
	writeJSON(w, http.StatusOK, out)
}

type tlsRequest struct {
	Target   string `json:"target"`
	Protocol string `json:"protocol"`
	SNI      string `json:"sni"`
	Save     bool   `json:"save"`
}

func (s *Server) connector(ctx context.Context, req tlsRequest) (*tlsinspect.Connector, error) {
	t, err := tlsinspect.ParseTarget(req.Target)
	if err != nil {
		return nil, err
	}
	return tlsinspect.NewConnector(ctx, t, tlsinspect.Options{Dialer: s.opts.Dialer, Protocol: req.Protocol, SNI: req.SNI,
		Timeout: s.opts.Config.TLS.Timeout.D()})
}

func (s *Server) acquire(w http.ResponseWriter, r *http.Request) bool {
	select {
	case s.scanSem <- struct{}{}:
		return true
	case <-r.Context().Done():
		return false
	case <-time.After(30 * time.Second):
		writeError(w, http.StatusServiceUnavailable, "too many scans in progress")
		return false
	}
}

func (s *Server) tlsInspect(w http.ResponseWriter, r *http.Request) {
	var req tlsRequest
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.acquire(w, r) {
		return
	}
	defer func() { <-s.scanSem }()
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	c, err := s.connector(ctx, req)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	res, err := c.Inspect(ctx, tlsinspect.InspectOptions{WarningDays: s.opts.Config.Expiry.WarningDays, Resumption: true})
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if req.Save {
		if err := s.record(ctx, c, res.Snapshot(), res); err != nil {
			s.fail(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) tlsScan(w http.ResponseWriter, r *http.Request) {
	var req tlsRequest
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.acquire(w, r) {
		return
	}
	defer func() { <-s.scanSem }()
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()
	c, err := s.connector(ctx, req)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	res, err := c.Scan(ctx, tlsinspect.ScanOptions{Inspect: tlsinspect.InspectOptions{WarningDays: s.opts.Config.Expiry.WarningDays, Resumption: true},
		Concurrency: s.opts.Config.TLS.Concurrency})
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if req.Save {
		if err := s.record(ctx, c, res.Snapshot(), res); err != nil {
			s.fail(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) record(ctx context.Context, c *tlsinspect.Connector, snap tlsinspect.Snapshot, full any) error {
	snapJSON, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	fullJSON, err := json.Marshal(full)
	if err != nil {
		return err
	}
	return s.db.RecordScan(ctx, database.Endpoint{Host: c.Target.Host, Port: c.Target.Port, SNI: c.SNI, Protocol: c.Detection.Protocol},
		&database.Scan{Kind: snap.Kind, ScannedAt: snap.ScannedAt, LeafSHA256: snap.LeafSHA256, Snapshot: snapJSON, Result: fullJSON})
}

func (s *Server) listEndpoints(w http.ResponseWriter, r *http.Request) {
	eps, err := s.db.Endpoints(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	type ep struct {
		Target    string    `json:"target"`
		Host      string    `json:"host"`
		Port      int       `json:"port"`
		SNI       string    `json:"sni,omitempty"`
		Protocol  string    `json:"protocol"`
		FirstSeen time.Time `json:"first_seen"`
		LastSeen  time.Time `json:"last_seen"`
	}
	out := []ep{}
	for _, e := range eps {
		out = append(out, ep{net.JoinHostPort(e.Host, strconv.Itoa(e.Port)), e.Host, e.Port, e.SNI, e.Protocol, e.FirstSeen, e.LastSeen})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	scans, err := s.db.RecentScans(r.Context(), limit, false)
	if err != nil {
		s.fail(w, err)
		return
	}
	target := r.URL.Query().Get("target")
	out := []scanEntry{}
	for _, sc := range scans {
		t := net.JoinHostPort(sc.Host, strconv.Itoa(sc.Port))
		if target != "" && t != target && sc.Host != target {
			continue
		}
		var snap tlsinspect.Snapshot
		_ = json.Unmarshal(sc.Snapshot, &snap)
		out = append(out, scanEntry{ID: sc.ID, Target: t, Kind: sc.Kind, ScannedAt: sc.ScannedAt, Snapshot: snap})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getScan(w http.ResponseWriter, r *http.Request) {
	sc, err := s.db.GetScan(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(sc.Result) //nolint:gosec // stored JSON produced by SSLKnife, served as application/json with nosniff
}

type watchResponse struct {
	ID          string         `json:"id"`
	Watch       string         `json:"watch"`
	Domain      string         `json:"domain"`
	Subdomains  bool           `json:"include_subdomains"`
	Source      string         `json:"source"`
	LastChecked *time.Time     `json:"last_checked,omitempty"`
	Counts      map[string]int `json:"by_status"`
}

func (s *Server) listWatches(w http.ResponseWriter, r *http.Request) {
	ws, err := s.db.CTWatches(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	out := []watchResponse{}
	for _, x := range ws {
		wr := watchResponse{ID: x.ID, Watch: x.Pattern(), Domain: x.Domain, Subdomains: x.IncludeSubdomains, Source: x.Source, Counts: map[string]int{}}
		if !x.LastCheckedAt.IsZero() {
			t := x.LastCheckedAt
			wr.LastChecked = &t
		}
		obs, _ := s.db.CTObservations(r.Context(), database.CTObservationFilter{WatchIDs: []string{x.ID}})
		for _, o := range obs {
			wr.Counts[o.Status]++
		}
		out = append(out, wr)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) addWatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain     string `json:"domain"`
		Subdomains bool   `json:"include_subdomains"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	domain, sub, err := ct.NormalizePattern(req.Domain, req.Subdomains)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	watch, created, err := s.db.AddCTWatch(r.Context(), domain, sub, "manual")
	if err != nil {
		s.fail(w, err)
		return
	}
	_ = s.db.MarkCTMonitored(r.Context())
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, watchResponse{ID: watch.ID, Watch: watch.Pattern(), Domain: watch.Domain, Subdomains: watch.IncludeSubdomains,
		Source: watch.Source, Counts: map[string]int{}})
}

func (s *Server) deleteWatch(w http.ResponseWriter, r *http.Request) {
	if err := s.db.DeleteCTWatch(r.Context(), r.PathValue("id")); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": r.PathValue("id")})
}

func (s *Server) listObservations(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	obs, err := s.db.CTObservations(r.Context(), database.CTObservationFilter{Status: r.URL.Query().Get("status"), Limit: limit})
	if err != nil {
		s.fail(w, err)
		return
	}
	patterns := s.watchPatterns(r.Context())
	out := []views.CTObservation{}
	for _, o := range obs {
		out = append(out, views.NewCTObservation(o, patterns[o.WatchID]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) ackObservation(w http.ResponseWriter, r *http.Request) {
	id, err := s.db.AcknowledgeCTObservation(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"acknowledged": id})
}

func (s *Server) ctChecker() (*ct.Checker, error) {
	p, err := ct.NewProvider(firstNonEmpty(s.opts.CTProvider, s.opts.Config.CT.Provider), s.opts.Dialer, s.opts.CTToken)
	if err != nil {
		return nil, err
	}
	return &ct.Checker{DB: s.db, Provider: p}, nil
}

func (s *Server) ctCheck(w http.ResponseWriter, r *http.Request) {
	chk, err := s.ctChecker()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.opts.CTBaseURL != "" {
		setBaseURL(chk.Provider, s.opts.CTBaseURL)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	results, added, err := ct.RunAll(ctx, s.db, chk, "", s.opts.Config.CT.AutoWatchStoredSANs)
	if err != nil && !errors.Is(err, ct.ErrNoWatches) {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if results == nil {
		results = []ct.CheckResult{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"auto_watched": added, "watches": results})
}

// setBaseURL points a provider at an alternative endpoint.
func setBaseURL(p ct.Provider, base string) {
	base = strings.TrimRight(base, "/")
	switch pp := p.(type) {
	case *ct.CertSpotter:
		pp.BaseURL = base
	case *ct.CrtSh:
		pp.BaseURL = base
	}
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

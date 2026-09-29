package server

import (
	"context"
	"errors"
	"time"

	"github.com/matusso/sslknife/internal/ct"
	"github.com/matusso/sslknife/internal/tlsinspect"
)

// runJobs starts the periodic background work of server mode:
//   - CT polling every ct.interval (when ct.enabled)
//   - re-inspection of known TLS endpoints every server.refresh_interval
//   - an hourly expiry check that logs certificates entering the critical window
func (s *Server) runJobs(ctx context.Context) {
	cfg := s.opts.Config
	if cfg.CT.Enabled {
		go s.every(ctx, 20*time.Second, cfg.CT.Interval.D(), s.pollCT)
	}
	if d := cfg.Server.RefreshInterval.D(); d > 0 {
		go s.every(ctx, time.Minute, d, s.refreshEndpoints)
	}
	go s.every(ctx, 5*time.Second, time.Hour, s.checkExpiry)
}

func (s *Server) every(ctx context.Context, first, interval time.Duration, job func(context.Context)) {
	t := time.NewTimer(first)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			job(ctx)
			t.Reset(interval)
		}
	}
}

func (s *Server) pollCT(ctx context.Context) {
	chk, err := s.ctChecker()
	if err != nil {
		s.log.Warn("CT polling disabled", "err", err)
		return
	}
	if s.opts.CTBaseURL != "" {
		setBaseURL(chk.Provider, s.opts.CTBaseURL)
	}
	results, added, err := ct.RunAll(ctx, s.db, chk, "", s.opts.Config.CT.AutoWatchStoredSANs)
	if err != nil {
		if !errors.Is(err, ct.ErrNoWatches) {
			s.log.Warn("CT poll failed", "err", err)
		}
		return
	}
	for _, r := range results {
		if r.Error != "" {
			s.log.Warn("CT query failed", "watch", r.Pattern, "err", r.Error)
		}
		for _, o := range r.Added {
			if o.Status == ct.StatusUnexpected || o.Status == ct.StatusChanged {
				s.log.Warn("CT: certificate needs review", "watch", r.Pattern, "status", o.Status, "names", o.DNSNames, "issuer", o.Issuer)
			}
		}
	}
	s.log.Info("CT poll complete", "watches", len(results), "auto_watched", added)
}

func (s *Server) refreshEndpoints(ctx context.Context) {
	eps, err := s.db.Endpoints(ctx)
	if err != nil {
		s.log.Warn("endpoint refresh", "err", err)
		return
	}
	for _, e := range eps {
		if ctx.Err() != nil {
			return
		}
		c, err := tlsinspect.NewConnector(ctx, tlsinspect.Target{Host: e.Host, Port: e.Port, Protocol: e.Protocol},
			tlsinspect.Options{Dialer: s.opts.Dialer, SNI: e.SNI, Timeout: s.opts.Config.TLS.Timeout.D()})
		if err != nil {
			s.log.Warn("endpoint refresh", "target", e.Host, "err", err)
			continue
		}
		res, err := c.Inspect(ctx, tlsinspect.InspectOptions{WarningDays: s.opts.Config.Expiry.WarningDays})
		if err != nil {
			s.log.Warn("endpoint refresh", "target", c.Target.String(), "err", err)
			continue
		}
		if err := s.record(ctx, c, res.Snapshot(), res); err != nil {
			s.log.Warn("endpoint refresh", "target", c.Target.String(), "err", err)
		}
	}
}

func (s *Server) checkExpiry(ctx context.Context) {
	days := s.opts.Config.Expiry.CriticalDays
	certs, err := s.inv.Expiring(ctx, time.Duration(days)*24*time.Hour, false)
	if err != nil {
		return
	}
	for _, c := range certs {
		s.log.Warn("certificate expires soon", "id", c.ID, "cn", c.SubjectCN, "not_after", c.NotAfter.Format(time.RFC3339))
	}
}

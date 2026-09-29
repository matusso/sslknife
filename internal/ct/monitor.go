package ct

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/matusso/sslknife/internal/certificate"
	"github.com/matusso/sslknife/internal/database"
)

// Observation statuses. Unknown certificates are never called malicious:
// "unexpected" only means the issuance does not fit what is known.
const (
	StatusKnown      = "known"      // the certificate or its key is in the inventory
	StatusNew        = "new"        // not in the inventory, from an issuer already used for these names
	StatusChanged    = "changed"    // same names as a stored certificate, different certificate
	StatusUnexpected = "unexpected" // not in the inventory and from an issuer not seen before
	StatusExpired    = "expired"
)

// NormalizePattern turns "example.com" or "*.example.com" into a domain
// and subdomain flag.
func NormalizePattern(p string, subdomains bool) (string, bool, error) {
	p = strings.ToLower(strings.TrimSpace(p))
	p = strings.TrimSuffix(p, ".")
	if strings.HasPrefix(p, "*.") {
		p, subdomains = p[2:], true
	}
	if err := certificate.ValidateDNSName(p); err != nil || !strings.Contains(p, ".") {
		return "", false, fmt.Errorf("invalid domain %q", p)
	}
	return p, subdomains, nil
}

// Classify assigns a status to an issuance using the inventory index and
// issuers already seen for the watch.
func Classify(is Issuance, idx *database.CertIndex, seenIssuers map[string]bool, now time.Time) (status, reason, certID string) {
	switch {
	case !is.NotAfter.IsZero() && now.After(is.NotAfter):
		return StatusExpired, "not valid after " + is.NotAfter.Format(time.DateOnly), ""
	}
	if id, ok := idx.BySHA256[is.CertSHA256]; ok && is.CertSHA256 != "" {
		return StatusKnown, "certificate is in the inventory", id
	}
	if id, ok := idx.BySPKI[is.PubkeySHA256]; ok && is.PubkeySHA256 != "" {
		return StatusKnown, "public key belongs to a stored certificate or key", id
	}
	if id, ok := idx.BySerial[database.NormalizeSerial(is.Serial)]; ok && is.Serial != "" {
		return StatusKnown, "serial number matches a stored certificate", id
	}
	if id, ok := idx.NameSets[database.NameSetKey(is.DNSNames)]; ok && len(is.DNSNames) > 0 {
		return StatusChanged, "covers the same names as a stored certificate but is a different certificate", id
	}
	issuer := database.CAKey(is.Issuer)
	if idx.Issuers[issuer] || seenIssuers[issuer] {
		return StatusNew, "not in the inventory; issued by a CA already used for these names", ""
	}
	return StatusUnexpected, "not in the inventory; first issuance seen from " + firstNonEmpty(is.IssuerName, is.Issuer), ""
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// CheckResult reports one watch poll.
type CheckResult struct {
	Watch   database.CTWatch         `json:"-"`
	Pattern string                   `json:"watch"`
	Fetched int                      `json:"fetched"`
	Added   []database.CTObservation `json:"new_observations"`
	Error   string                   `json:"error,omitempty"`
}

// Checker polls providers and stores observations.
type Checker struct {
	DB       *database.DB
	Provider Provider
	Now      func() time.Time
}

// Check polls one watch.
func (c *Checker) Check(ctx context.Context, w database.CTWatch, idx *database.CertIndex) CheckResult {
	res := CheckResult{Watch: w, Pattern: w.Pattern(), Added: []database.CTObservation{}}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	cursor := w.Cursor
	if !strings.HasPrefix(cursor, c.Provider.Name()+":") {
		cursor = "" // cursor from another provider
	}
	issuances, next, err := c.Provider.Search(ctx, Query{Domain: w.Domain, IncludeSubdomains: w.IncludeSubdomains,
		Cursor: strings.TrimPrefix(cursor, c.Provider.Name()+":")})
	res.Fetched = len(issuances)
	if err != nil {
		res.Error = err.Error()
		if len(issuances) == 0 {
			return res
		}
	}
	prior, perr := c.DB.CTObservations(ctx, database.CTObservationFilter{WatchIDs: []string{w.ID}})
	if perr != nil {
		res.Error = perr.Error()
		return res
	}
	seen := map[string]bool{}
	for _, p := range prior {
		if p.Status == StatusKnown || p.Acknowledged {
			seen[database.CAKey(p.Issuer)] = true
		}
	}
	for _, is := range issuances {
		status, reason, certID := Classify(is, idx, seen, now())
		o := &database.CTObservation{
			WatchID: w.ID, Provider: is.Provider, ExternalID: is.ID, Identity: is.Identity, CertSHA256: is.CertSHA256,
			PubkeySHA256: is.PubkeySHA256, Serial: is.Serial, Issuer: is.Issuer, IssuerName: is.IssuerName, DNSNames: is.DNSNames,
			NotBefore: is.NotBefore, NotAfter: is.NotAfter, Revoked: is.Revoked, Status: status, Reason: reason,
			KnownCertID: certID, FirstSeen: now().UTC().Truncate(time.Second),
		}
		added, err := c.DB.InsertCTObservation(ctx, o)
		if err != nil {
			res.Error = err.Error()
			return res
		}
		if added {
			res.Added = append(res.Added, *o)
			if status == StatusKnown {
				seen[database.CAKey(is.Issuer)] = true
			}
		}
	}
	if err == nil {
		if uerr := c.DB.UpdateCTWatchCheck(ctx, w.ID, c.Provider.Name()+":"+next, now()); uerr != nil {
			res.Error = uerr.Error()
		}
	}
	return res
}

// AutoWatch adds watches for DNS SANs of stored certificates (wildcards
// become subdomain watches). It returns the number of watches added.
func AutoWatch(ctx context.Context, db *database.DB, idx *database.CertIndex) (int, error) {
	added := 0
	for _, san := range idx.SANs {
		domain, sub, err := NormalizePattern(san, false)
		if err != nil {
			continue
		}
		_, created, err := db.AddCTWatch(ctx, domain, sub, "stored-san")
		if err != nil {
			return added, err
		}
		if created {
			added++
		}
	}
	return added, nil
}

// ErrNoWatches is returned by commands when nothing is watched.
var ErrNoWatches = errors.New("no CT watches configured; add one with 'sslknife ct watch example.com'")

// ErrNotWatched is returned when a domain filter matches no watch.
var ErrNotWatched = errors.New("domain is not watched")

// RunAll polls every watch (or those for domain), optionally adding
// watches for stored certificate names first. It returns the per-watch
// results and the number of watches added automatically.
func RunAll(ctx context.Context, db *database.DB, chk *Checker, domain string, autoWatch bool) ([]CheckResult, int, error) {
	idx, err := db.CTCertIndex(ctx)
	if err != nil {
		return nil, 0, err
	}
	added := 0
	if autoWatch {
		if added, err = AutoWatch(ctx, db, idx); err != nil {
			return nil, 0, err
		}
		if err := db.MarkCTMonitored(ctx); err != nil {
			return nil, 0, err
		}
	}
	ws, err := db.CTWatches(ctx)
	if err != nil {
		return nil, added, err
	}
	if domain != "" {
		d, _, err := NormalizePattern(domain, false)
		if err != nil {
			return nil, added, err
		}
		var sel []database.CTWatch
		for _, w := range ws {
			if w.Domain == d {
				sel = append(sel, w)
			}
		}
		if len(sel) == 0 {
			return nil, added, fmt.Errorf("%w: %s", ErrNotWatched, domain)
		}
		ws = sel
	}
	if len(ws) == 0 {
		return nil, added, ErrNoWatches
	}
	var results []CheckResult
	for _, w := range ws {
		if ctx.Err() != nil {
			return results, added, ctx.Err()
		}
		results = append(results, chk.Check(ctx, w, idx))
	}
	return results, added, nil
}

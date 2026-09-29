package tlsinspect

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/matusso/sslknife/internal/netdial"
)

// QueryOCSP asks the certificate's OCSP responder for its status. It needs
// the issuer certificate to build the request.
func QueryOCSP(ctx context.Context, leaf, issuer *x509.Certificate, d netdial.Dialer) (*OCSPInfo, error) {
	if len(leaf.OCSPServer) == 0 {
		return nil, errors.New("certificate has no OCSP responder URL")
	}
	if issuer == nil {
		return nil, errors.New("the issuer certificate is required for an OCSP request")
	}
	req, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: d.Timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) { return d.DialContext(ctx, addr) },
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	info := &OCSPInfo{Responders: leaf.OCSPServer}
	var lastErr error
	for _, url := range leaf.OCSPServer {
		hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(req))
		if err != nil {
			lastErr = err
			continue
		}
		hreq.Header.Set("Content-Type", "application/ocsp-request")
		resp, err := client.Do(hreq)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("%s: HTTP %s", url, resp.Status)
			continue
		}
		r, err := ocsp.ParseResponseForCert(body, leaf, issuer)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", url, err)
			continue
		}
		fillOCSP(info, r)
		if !r.NextUpdate.IsZero() && time.Now().After(r.NextUpdate) {
			info.Error = "response is stale (nextUpdate has passed)"
		}
		return info, nil
	}
	return nil, lastErr
}

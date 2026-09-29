// Package netdial opens TCP connections directly or through an HTTP
// CONNECT or SOCKS5 proxy.
package netdial

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// Dialer connects to host:port.
type Dialer struct {
	Timeout time.Duration
	// Proxy is an http://, https:// (CONNECT) or socks5:// URL. Empty means direct.
	Proxy string
}

// DialContext opens a TCP connection to addr.
func (d Dialer) DialContext(ctx context.Context, addr string) (net.Conn, error) {
	base := &net.Dialer{Timeout: d.Timeout, KeepAlive: -1}
	if d.Proxy == "" {
		return base.DialContext(ctx, "tcp", addr)
	}
	u, err := url.Parse(d.Proxy)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid proxy URL %q", d.Proxy)
	}
	switch u.Scheme {
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: pw}
		}
		pd, err := proxy.SOCKS5("tcp", u.Host, auth, base)
		if err != nil {
			return nil, err
		}
		if cd, ok := pd.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, "tcp", addr)
		}
		return pd.Dial("tcp", addr)
	case "http":
		return connect(ctx, base, u, addr)
	}
	return nil, fmt.Errorf("unsupported proxy scheme %q (use http:// or socks5://)", u.Scheme)
}

// connect tunnels through an HTTP proxy with the CONNECT method.
func connect(ctx context.Context, base *net.Dialer, u *url.URL, addr string) (net.Conn, error) {
	conn, err := base.DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return nil, fmt.Errorf("proxy: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: addr}, Host: addr, Header: http.Header{}}
	if u.User != nil {
		pw, _ := u.User.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+pw)))
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT to %s: %s", addr, resp.Status)
	}
	if br.Buffered() > 0 {
		conn.Close()
		return nil, errors.New("proxy sent unexpected data after CONNECT")
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

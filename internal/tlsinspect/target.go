// Package tlsinspect connects to TLS endpoints (directly or via STARTTLS),
// inspects the negotiated session and certificate chain, and combines the
// raw-probe scanner results into a full scan report.
package tlsinspect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/matusso/sslknife/internal/netdial"
	"github.com/matusso/sslknife/internal/protocol"
)

// Target is a parsed endpoint specification.
type Target struct {
	Host     string
	Port     int
	Protocol string // from a URL scheme or --protocol; "" = autodetect
}

// String returns host:port.
func (t Target) String() string { return net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) }

// ParseTarget accepts host, host:port, [v6]:port and scheme://host[:port][/path].
func ParseTarget(s string) (Target, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Target{}, errors.New("empty target")
	}
	var t Target
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Hostname() == "" {
			return Target{}, fmt.Errorf("invalid target %q", s)
		}
		t.Host = u.Hostname()
		if _, err := protocol.Lookup(u.Scheme); err == nil {
			t.Protocol = u.Scheme
		}
		if p := u.Port(); p != "" {
			t.Port, _ = strconv.Atoi(p)
		}
	} else if h, p, err := net.SplitHostPort(s); err == nil {
		t.Host = h
		n, err := strconv.Atoi(p)
		if err != nil {
			return Target{}, fmt.Errorf("invalid port in %q", s)
		}
		t.Port = n
	} else {
		t.Host = strings.Trim(s, "[]")
	}
	if t.Port == 0 {
		t.Port = 443
		if t.Protocol != "" {
			t.Port = protocol.DefaultPort(t.Protocol)
		}
	}
	if t.Port < 1 || t.Port > 65535 {
		return Target{}, fmt.Errorf("port %d out of range", t.Port)
	}
	if strings.ContainsAny(t.Host, " /\\") {
		return Target{}, fmt.Errorf("invalid host %q", t.Host)
	}
	return t, nil
}

// LooksLikeTarget reports whether s is a network target rather than a file:
// it contains a URL scheme or a host:port.
func LooksLikeTarget(s string) bool {
	if strings.Contains(s, "://") {
		return true
	}
	h, p, err := net.SplitHostPort(s)
	if err != nil || h == "" {
		return false
	}
	_, err = strconv.Atoi(p)
	return err == nil
}

// Options control how endpoints are reached.
type Options struct {
	Dialer   netdial.Dialer
	Protocol string        // explicit --protocol
	SNI      string        // override; "" = host (omitted for IP targets)
	IP       string        // connect to this address instead of resolving
	Timeout  time.Duration // per connection
}

// Connector opens connections that are ready for a ClientHello.
type Connector struct {
	Target     Target
	Adapter    protocol.Adapter
	Detection  protocol.Detection
	SNI        string
	IPs        []string // resolved addresses (empty when using a proxy)
	addr       string   // what we dial
	opts       Options
	once       sync.Once
	transcript []string
}

// Transcript returns the plaintext negotiation of the first connection.
func (c *Connector) Transcript() []string { return c.transcript }

// Addr is the dialled address.
func (c *Connector) Addr() string { return c.addr }

// NewConnector resolves the target and determines how to reach TLS.
func NewConnector(ctx context.Context, t Target, opts Options) (*Connector, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	c := &Connector{Target: t, opts: opts, SNI: opts.SNI}
	if c.SNI == "" && net.ParseIP(t.Host) == nil {
		c.SNI = t.Host
	}
	c.addr = t.String()
	switch {
	case opts.IP != "":
		c.IPs = []string{opts.IP}
		c.addr = net.JoinHostPort(opts.IP, strconv.Itoa(t.Port))
	case opts.Dialer.Proxy != "":
		// Name resolution happens at the proxy.
	case net.ParseIP(t.Host) != nil:
		c.IPs = []string{t.Host}
	default:
		rctx, cancel := context.WithTimeout(ctx, opts.Timeout)
		addrs, err := net.DefaultResolver.LookupIPAddr(rctx, t.Host)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", t.Host, err)
		}
		for _, a := range addrs {
			c.IPs = append(c.IPs, a.IP.String())
		}
		if len(c.IPs) > 0 {
			// Pin one address so all probes hit the same server.
			c.addr = net.JoinHostPort(c.IPs[0], strconv.Itoa(t.Port))
		}
	}
	if err := c.detect(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Connector) detect(ctx context.Context) error {
	name, via := c.opts.Protocol, "flag"
	if name == "" && c.Target.Protocol != "" {
		name, via = c.Target.Protocol, "url"
	}
	if name == "" {
		if p, ok := protocol.ByPort(c.Target.Port); ok {
			name, via = p, "port"
		}
	}
	var banner []byte
	if name == "" {
		conn, err := c.rawDial(ctx)
		if err != nil {
			return err
		}
		var sniffed string
		sniffed, banner = protocol.SniffBanner(ctx, conn, 1500*time.Millisecond)
		conn.Close()
		switch sniffed {
		case "":
			name, via = "tls", "default"
		case "unknown":
			return fmt.Errorf("the server sent an unrecognised plaintext banner %q; use --protocol", protocol.Printable(banner))
		default:
			name, via = sniffed, "banner"
		}
	}
	a, err := protocol.Lookup(name)
	if err != nil {
		return err
	}
	c.Adapter = a
	method := "direct"
	if a.STARTTLS() {
		method = "starttls"
	}
	c.Detection = protocol.Detection{Protocol: a.Name(), Method: method, Via: via, Banner: protocol.Printable(banner)}
	return nil
}

func (c *Connector) rawDial(ctx context.Context) (net.Conn, error) {
	d := c.opts.Dialer
	d.Timeout = c.opts.Timeout
	return d.DialContext(ctx, c.addr)
}

// Dial opens a connection and performs the protocol upgrade.
func (c *Connector) Dial(ctx context.Context) (net.Conn, error) {
	conn, err := c.rawDial(ctx)
	if err != nil {
		return nil, err
	}
	if !c.Adapter.STARTTLS() {
		return conn, nil
	}
	_ = conn.SetDeadline(time.Now().Add(c.opts.Timeout))
	s := protocol.NewSession(conn)
	err = c.Adapter.Upgrade(ctx, s, c.Target.Host)
	c.once.Do(func() { c.transcript = s.Log })
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("%s upgrade: %w", c.Adapter.Name(), err)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

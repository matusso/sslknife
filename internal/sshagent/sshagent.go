// Package sshagent connects to a running ssh-agent and serves an in-memory
// agent over a Unix socket, so keys from the vault can be used by ssh without
// ever being written to disk.
package sshagent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh/agent"
)

// EnvSocket is the variable OpenSSH reads the agent socket from.
const EnvSocket = "SSH_AUTH_SOCK"

// ErrNoAgent means SSH_AUTH_SOCK is not set.
var ErrNoAgent = errors.New("no ssh-agent: " + EnvSocket + " is not set (start one with 'eval $(ssh-agent)' or 'sslknife ssh agent serve')")

// Client is a connection to an agent.
type Client struct {
	agent.ExtendedAgent
	conn net.Conn
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Dial connects to the agent at socket, or at $SSH_AUTH_SOCK when empty.
func Dial(socket string) (*Client, error) {
	if socket == "" {
		socket = os.Getenv(EnvSocket)
	}
	if socket == "" {
		return nil, ErrNoAgent
	}
	conn, err := net.Dial("unix", socket) //nolint:gosec // local agent socket chosen by the user
	if err != nil {
		return nil, fmt.Errorf("connect to ssh-agent at %s: %w", socket, err)
	}
	return &Client{ExtendedAgent: agent.NewClient(conn), conn: conn}, nil
}

// Listen creates the agent socket. With an empty path it makes a private
// temporary directory; the returned cleanup removes whatever Listen created.
// An existing socket nobody answers on is treated as stale and replaced.
func Listen(path string) (net.Listener, string, func(), error) {
	var dir string
	if path == "" {
		d, err := os.MkdirTemp("", "sslknife-agent-") // mode 0700
		if err != nil {
			return nil, "", nil, err
		}
		dir, path = d, filepath.Join(d, "agent.sock")
	} else if _, err := os.Lstat(path); err == nil {
		if c, err := net.Dial("unix", path); err == nil {
			c.Close()
			return nil, "", nil, fmt.Errorf("%s is in use by another agent", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, "", nil, err
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		if dir != "" {
			os.RemoveAll(dir)
		}
		return nil, "", nil, err
	}
	// The socket grants use of every loaded key: keep it to the owner.
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, "", nil, err
	}
	// Closing a Unix listener unlinks the socket; the directory is ours to remove.
	cleanup := func() {
		l.Close()
		if dir != "" {
			os.RemoveAll(dir)
		}
	}
	return l, path, cleanup, nil
}

// Serve answers agent requests from a on l until ctx is done or l is closed.
func Serve(ctx context.Context, l net.Listener, a agent.Agent) error {
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conn.Close()
			closeOnDone := context.AfterFunc(ctx, func() { conn.Close() })
			defer closeOnDone()
			_ = agent.ServeAgent(a, conn)
		}()
	}
}

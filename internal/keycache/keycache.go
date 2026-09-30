//go:build !windows

// Package keycache keeps an unlocked vault root key in a short-lived
// background process, so commands run shortly after one another do not ask
// for the password again (like sudo's timestamp). The key lives only in
// that process's memory; it is handed out over a Unix socket in a private
// per-user directory, to peers running as the same user.
package keycache

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ErrNotCached means no cache process holds the key for this vault.
var ErrNotCached = errors.New("vault is not cached")

// Supported reports whether this platform has an unlock cache.
const Supported = true

type request struct {
	Op   string `json:"op"` // get, status, lock
	DBID string `json:"db_id"`
}

type response struct {
	Root    []byte    `json:"root,omitempty"`
	Expires time.Time `json:"expires"`
	Error   string    `json:"error,omitempty"`
}

// socketDir returns the private per-user directory for cache sockets,
// creating it if needed. An existing directory must be a real directory
// owned by this user with no group or other access.
func socketDir() (string, error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, fmt.Sprintf("sslknife-%d", os.Getuid()))
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) { //nolint:gosec // trusted per-user path
		return "", err
	}
	st, err := os.Lstat(dir) //nolint:gosec // trusted per-user path
	if err != nil {
		return "", err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !st.IsDir() || !ok || int(sys.Uid) != os.Getuid() || st.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("unlock cache directory %s is not a private directory owned by you", dir)
	}
	return dir, nil
}

// SocketPath returns the socket of the cache for vault dbID.
func SocketPath(dbID string) (string, error) {
	dir, err := socketDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(dbID))
	return filepath.Join(dir, hex.EncodeToString(sum[:8])+".sock"), nil
}

func call(dbID, op string) (*response, error) {
	path, err := SocketPath(dbID)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return nil, ErrNotCached
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewEncoder(conn).Encode(request{Op: op, DBID: dbID}); err != nil {
		return nil, err
	}
	var resp response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		if op == "lock" && errors.Is(err, io.EOF) {
			return &resp, nil
		}
		return nil, fmt.Errorf("unlock cache: %w", err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("unlock cache: %s", resp.Error)
	}
	return &resp, nil
}

// Get returns the cached root key and extends the cache's lifetime.
func Get(dbID string) ([]byte, error) {
	resp, err := call(dbID, "get")
	if err != nil {
		return nil, err
	}
	return resp.Root, nil
}

// Status returns when the cache expires unless it is used again.
func Status(dbID string) (time.Time, error) {
	resp, err := call(dbID, "status")
	if err != nil {
		return time.Time{}, err
	}
	return resp.Expires, nil
}

// Lock stops the cache process for dbID.
func Lock(dbID string) error {
	_, err := call(dbID, "lock")
	return err
}

// payload is what Start hands the cache process on its stdin.
type payload struct {
	DBID string        `json:"db_id"`
	Root []byte        `json:"root"`
	Idle time.Duration `json:"idle"`
}

// Start launches exe with args as a detached cache process holding root
// for idle after its last use, replacing any running cache for dbID. The
// command must call RunDaemon.
func Start(exe string, args []string, dbID string, root []byte, idle time.Duration) error {
	_ = Lock(dbID)
	cmd := exec.Command(exe, args...) //nolint:gosec // re-executes our own binary
	cmd.Dir = "/"
	cmd.Env = daemonEnv()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	data, _ := json.Marshal(payload{DBID: dbID, Root: root, Idle: idle})
	_, err = stdin.Write(append(data, '\n'))
	clear(data)
	stdin.Close()
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}
	ready := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		ready <- strings.TrimSpace(line)
	}()
	select {
	case line := <-ready:
		if line != "ready" {
			_ = cmd.Wait()
			if line == "" {
				line = "cache process exited"
			}
			return fmt.Errorf("start unlock cache: %s", line)
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return errors.New("start unlock cache: timed out")
	}
	return cmd.Process.Release()
}

// daemonEnv drops password variables from the cache process environment.
func daemonEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "SSLKNIFE_PASSWORD") {
			continue
		}
		env = append(env, kv)
	}
	return env
}

// RunDaemon is the body of the cache process: it reads the payload from
// in, reports "ready" (or an error) on out, then serves until the idle
// timeout passes or it is locked.
func RunDaemon(in io.Reader, out io.Writer) error {
	var p payload
	line, err := bufio.NewReader(in).ReadBytes('\n')
	if err == nil {
		err = json.Unmarshal(line, &p)
	}
	clear(line)
	if err == nil && (p.DBID == "" || len(p.Root) == 0 || p.Idle <= 0) {
		err = errors.New("invalid cache payload")
	}
	if err != nil {
		fmt.Fprintln(out, err)
		return err
	}
	// Keep the key out of swap where the OS allows it.
	_ = unix.Mlock(p.Root)
	defer clear(p.Root)

	path, err := SocketPath(p.DBID)
	if err == nil {
		// A socket left behind by a crashed cache is stale: Start locked
		// any live one first.
		_ = os.Remove(path)
	}
	var l net.Listener
	if err == nil {
		l, err = net.Listen("unix", path)
	}
	if err != nil {
		fmt.Fprintln(out, err)
		return err
	}
	defer func() { _ = l.Close() }()
	if err := os.Chmod(path, 0o600); err != nil {
		fmt.Fprintln(out, err)
		return err
	}
	fmt.Fprintln(out, "ready")
	if c, ok := out.(io.Closer); ok {
		c.Close()
	}
	return Serve(l, p.DBID, p.Root, p.Idle)
}

// Serve answers cache requests on l until idle passes without a successful
// get, or a lock request arrives.
func Serve(l net.Listener, dbID string, root []byte, idle time.Duration) error {
	var mu sync.Mutex
	expires := time.Now().Add(idle)
	timer := time.AfterFunc(idle, func() { _ = l.Close() })
	defer timer.Stop()
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		uc, ok := conn.(*net.UnixConn)
		if !ok || !samePeer(uc) {
			conn.Close()
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		var req request
		if err := json.NewDecoder(conn).Decode(&req); err != nil {
			conn.Close()
			continue
		}
		var resp response
		lock := false
		mu.Lock()
		switch {
		case req.DBID != dbID:
			resp.Error = "different vault"
		case req.Op == "get":
			expires = time.Now().Add(idle)
			timer.Reset(idle)
			resp.Root = root
		case req.Op == "status":
		case req.Op == "lock":
			lock = true
		default:
			resp.Error = "unknown request"
		}
		resp.Expires = expires
		mu.Unlock()
		_ = json.NewEncoder(conn).Encode(resp)
		conn.Close()
		if lock {
			return nil
		}
	}
}

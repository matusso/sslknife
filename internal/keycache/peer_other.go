//go:build !windows && !darwin && !linux

package keycache

import "net"

// samePeer relies on the private socket directory where peer credentials
// are not available.
func samePeer(*net.UnixConn) bool { return true }

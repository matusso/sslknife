package netdial

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestHTTPConnectProxy(t *testing.T) {
	// Upstream echo server.
	up, _ := net.Listen("tcp", "127.0.0.1:0")
	defer up.Close()
	go func() {
		c, err := up.Accept()
		if err == nil {
			io.Copy(c, c)
			c.Close()
		}
	}()
	// Minimal CONNECT proxy that checks credentials.
	px, _ := net.Listen("tcp", "127.0.0.1:0")
	defer px.Close()
	go func() {
		c, err := px.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		req, err := http.ReadRequest(br)
		if err != nil || req.Method != http.MethodConnect || req.Header.Get("Proxy-Authorization") != "Basic dTpw" {
			io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
			return
		}
		dst, err := net.Dial("tcp", req.Host)
		if err != nil {
			io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			return
		}
		defer dst.Close()
		io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
		go io.Copy(dst, br)
		io.Copy(c, dst)
	}()

	d := Dialer{Timeout: 2 * time.Second, Proxy: "http://u:p@" + px.Addr().String()}
	conn, err := d.DialContext(context.Background(), up.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "ping")
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("%q %v", buf, err)
	}

	if _, err := (Dialer{Proxy: "ftp://x"}).DialContext(context.Background(), "a:1"); err == nil {
		t.Fatal("unsupported scheme accepted")
	}
}

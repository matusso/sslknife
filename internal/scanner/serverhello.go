package scanner

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// helloRetryRandom is the special ServerHello.random of a HelloRetryRequest
// (RFC 8446 §4.1.3): SHA-256("HelloRetryRequest").
var helloRetryRandom = sha256.Sum256([]byte("HelloRetryRequest"))

// ServerHello is the parsed server response to a probe.
type ServerHello struct {
	LegacyVersion uint16
	Version       uint16 // negotiated version (supported_versions if present)
	CipherSuite   uint16
	Compression   byte
	SessionIDLen  int
	Extensions    []uint16 // extension types in order received
	extData       map[uint16][]byte
	HelloRetry    bool
	KeyShareGroup uint16
	// Filled from later handshake messages for TLS ≤1.2 when requested.
	Certificates [][]byte // DER, as sent
	KeyExchange  *KeyExchange
}

// HasExtension reports whether the server sent extension t.
func (s *ServerHello) HasExtension(t uint16) bool {
	_, ok := s.extData[t]
	return ok
}

// ExtensionData returns the raw body of extension t.
func (s *ServerHello) ExtensionData(t uint16) []byte { return s.extData[t] }

// KeyExchange describes the server's ephemeral parameters (TLS ≤1.2).
type KeyExchange struct {
	Kind    string `json:"kind"` // ECDH or DH
	Group   string `json:"group,omitempty"`
	GroupID uint16 `json:"group_id,omitempty"`
	Bits    int    `json:"bits"`
}

// String formats e.g. "ECDH x25519" or "DH 2048 bits".
func (k *KeyExchange) String() string {
	if k == nil {
		return ""
	}
	if k.Kind == "DH" {
		return fmt.Sprintf("DH %d bits", k.Bits)
	}
	return "ECDH " + k.Group
}

// AlertError is a TLS alert received instead of a ServerHello.
type AlertError struct {
	Level       byte
	Description byte
}

func (e *AlertError) Error() string {
	return fmt.Sprintf("TLS alert: %s", AlertName(e.Description))
}

// AlertName names an alert description.
func AlertName(d byte) string {
	names := map[byte]string{
		0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure",
		42: "bad_certificate", 43: "unsupported_certificate", 47: "illegal_parameter", 50: "decode_error",
		51: "decrypt_error", 70: "protocol_version", 71: "insufficient_security", 80: "internal_error",
		86: "inappropriate_fallback", 90: "user_canceled", 109: "missing_extension", 110: "unsupported_extension",
		112: "unrecognized_name", 120: "no_application_protocol",
	}
	if n, ok := names[d]; ok {
		return n
	}
	return fmt.Sprintf("alert %d", d)
}

// Alert descriptions of interest.
const (
	alertInappropriateFallback byte = 86
	alertProtocolVersion       byte = 70
)

// ErrNotTLS means the peer answered with something that is not TLS.
var ErrNotTLS = errors.New("server response is not TLS")

const maxHandshakeBytes = 256 << 10

// readServerHello reads records until the ServerHello is complete, and, when
// wantMore is set and the version is ≤1.2, also the Certificate and
// ServerKeyExchange messages.
func readServerHello(r io.Reader, wantMore bool) (*ServerHello, error) {
	var hs []byte // reassembled handshake stream
	var sh *ServerHello
	for {
		typ, payload, err := readRecord(r)
		if err != nil {
			if sh != nil && errors.Is(err, io.EOF) {
				return sh, nil
			}
			return sh, err
		}
		switch typ {
		case 21: // alert
			if len(payload) < 2 {
				return sh, ErrNotTLS
			}
			if sh != nil {
				return sh, nil
			}
			return nil, &AlertError{Level: payload[0], Description: payload[1]}
		case 22: // handshake
			hs = append(hs, payload...)
			if len(hs) > maxHandshakeBytes {
				return sh, errors.New("handshake too large")
			}
		case 20: // change_cipher_spec (TLS 1.3 compatibility) — ignore
			continue
		default:
			if sh != nil {
				return sh, nil
			}
			return nil, ErrNotTLS
		}
		for len(hs) >= 4 {
			mlen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
			if len(hs) < 4+mlen {
				break
			}
			mtype, msg := hs[0], hs[4:4+mlen]
			hs = hs[4+mlen:]
			switch mtype {
			case 2: // server_hello
				if sh != nil {
					return sh, errors.New("duplicate ServerHello")
				}
				if sh, err = parseServerHello(msg); err != nil {
					return nil, err
				}
				if !wantMore || sh.Version >= VersionTLS13 || sh.HelloRetry {
					return sh, nil
				}
			case 11: // certificate
				if sh == nil {
					return nil, ErrNotTLS
				}
				sh.Certificates = parseCertificateMsg(msg)
			case 12: // server_key_exchange
				if sh == nil {
					return nil, ErrNotTLS
				}
				sh.KeyExchange = parseServerKeyExchange(sh.CipherSuite, msg)
				return sh, nil
			case 14: // server_hello_done
				return sh, nil
			default:
				if sh == nil {
					return nil, ErrNotTLS
				}
			}
		}
	}
}

func readRecord(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	if hdr[0] < 20 || hdr[0] > 23 || hdr[1] != 3 {
		// SSLv2-format or non-TLS reply.
		return 0, nil, ErrNotTLS
	}
	n := int(binary.BigEndian.Uint16(hdr[3:]))
	if n > 18432 {
		return 0, nil, ErrNotTLS
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return hdr[0], buf, nil
}

type reader struct {
	b   []byte
	err bool
}

func (r *reader) u8() byte {
	if len(r.b) < 1 {
		r.err = true
		return 0
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v
}

func (r *reader) u16() uint16 {
	if len(r.b) < 2 {
		r.err = true
		return 0
	}
	v := binary.BigEndian.Uint16(r.b)
	r.b = r.b[2:]
	return v
}

func (r *reader) bytes(n int) []byte {
	if n < 0 || len(r.b) < n {
		r.err = true
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func parseServerHello(msg []byte) (*ServerHello, error) {
	r := &reader{b: msg}
	sh := &ServerHello{extData: map[uint16][]byte{}}
	sh.LegacyVersion = r.u16()
	random := r.bytes(32)
	sh.SessionIDLen = int(r.u8())
	r.bytes(sh.SessionIDLen)
	sh.CipherSuite = r.u16()
	sh.Compression = r.u8()
	if r.err {
		return nil, errors.New("malformed ServerHello")
	}
	sh.HelloRetry = bytes.Equal(random, helloRetryRandom[:])
	sh.Version = sh.LegacyVersion
	if len(r.b) >= 2 {
		exts := &reader{b: r.bytes(int(r.u16()))}
		for len(exts.b) > 0 && !exts.err {
			t := exts.u16()
			data := exts.bytes(int(exts.u16()))
			if exts.err {
				break
			}
			sh.Extensions = append(sh.Extensions, t)
			sh.extData[t] = data
			switch t {
			case extSupportedVersions:
				if len(data) == 2 {
					sh.Version = binary.BigEndian.Uint16(data)
				}
			case extKeyShare:
				if len(data) >= 2 {
					sh.KeyShareGroup = binary.BigEndian.Uint16(data)
				}
			}
		}
		if exts.err || r.err {
			return nil, errors.New("malformed ServerHello extensions")
		}
	}
	return sh, nil
}

func parseCertificateMsg(msg []byte) [][]byte {
	r := &reader{b: msg}
	if len(msg) < 3 {
		return nil
	}
	total := int(msg[0])<<16 | int(msg[1])<<8 | int(msg[2])
	r.bytes(3)
	body := &reader{b: r.bytes(total)}
	var out [][]byte
	for len(body.b) >= 3 && !body.err {
		n := int(body.b[0])<<16 | int(body.b[1])<<8 | int(body.b[2])
		body.bytes(3)
		der := body.bytes(n)
		if body.err {
			break
		}
		out = append(out, der)
	}
	return out
}

func parseServerKeyExchange(suite uint16, msg []byte) *KeyExchange {
	s := Lookup(suite)
	r := &reader{b: msg}
	switch s.KeyExch {
	case "ECDHE":
		if r.u8() != 3 { // named_curve
			return nil
		}
		g := r.u16()
		if r.err {
			return nil
		}
		return &KeyExchange{Kind: "ECDH", Group: GroupName(g), GroupID: g, Bits: GroupBits(g)}
	case "DHE", "DH":
		p := r.bytes(int(r.u16()))
		if r.err {
			return nil
		}
		for len(p) > 0 && p[0] == 0 {
			p = p[1:]
		}
		bits := len(p) * 8
		if len(p) > 0 {
			for b := p[0]; b&0x80 == 0; b <<= 1 {
				bits--
			}
		}
		return &KeyExchange{Kind: "DH", Bits: bits}
	}
	return nil
}

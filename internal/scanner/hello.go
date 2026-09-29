package scanner

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
)

// Protocol version codes.
const (
	VersionSSL2  uint16 = 0x0002
	VersionSSL3  uint16 = 0x0300
	VersionTLS10 uint16 = 0x0301
	VersionTLS11 uint16 = 0x0302
	VersionTLS12 uint16 = 0x0303
	VersionTLS13 uint16 = 0x0304
)

// VersionName returns "TLS 1.2" style names.
func VersionName(v uint16) string {
	switch v {
	case VersionSSL2:
		return "SSLv2"
	case VersionSSL3:
		return "SSLv3"
	case VersionTLS10:
		return "TLS 1.0"
	case VersionTLS11:
		return "TLS 1.1"
	case VersionTLS12:
		return "TLS 1.2"
	case VersionTLS13:
		return "TLS 1.3"
	}
	return "unknown"
}

// Extension types used by the scanner.
const (
	extServerName          uint16 = 0
	extStatusRequest       uint16 = 5
	extSupportedGroups     uint16 = 10
	extECPointFormats      uint16 = 11
	extSignatureAlgorithms uint16 = 13
	extALPN                uint16 = 16
	extSCT                 uint16 = 18
	extPadding             uint16 = 21
	extEncryptThenMAC      uint16 = 22
	extExtendedMaster      uint16 = 23
	extSessionTicket       uint16 = 35
	extSupportedVersions   uint16 = 43
	extPSKModes            uint16 = 45
	extKeyShare            uint16 = 51
	extRenegotiationInfo   uint16 = 0xff01
)

var extensionNames = map[uint16]string{
	0: "server_name", 1: "max_fragment_length", 5: "status_request", 10: "supported_groups",
	11: "ec_point_formats", 13: "signature_algorithms", 15: "heartbeat", 16: "application_layer_protocol_negotiation",
	18: "signed_certificate_timestamp", 21: "padding", 22: "encrypt_then_mac", 23: "extended_master_secret",
	27: "compress_certificate", 28: "record_size_limit", 35: "session_ticket", 41: "pre_shared_key",
	42: "early_data", 43: "supported_versions", 44: "cookie", 45: "psk_key_exchange_modes", 51: "key_share",
	0xfe0d: "encrypted_client_hello", 0xff01: "renegotiation_info",
}

// ExtensionName names a TLS extension type.
func ExtensionName(t uint16) string {
	if n, ok := extensionNames[t]; ok {
		return n
	}
	return "unknown"
}

// Named groups.
const (
	GroupSecp256r1      uint16 = 23
	GroupSecp384r1      uint16 = 24
	GroupSecp521r1      uint16 = 25
	GroupX25519         uint16 = 29
	GroupX448           uint16 = 30
	GroupFFDHE2048      uint16 = 256
	GroupFFDHE3072      uint16 = 257
	GroupFFDHE4096      uint16 = 258
	GroupFFDHE6144      uint16 = 259
	GroupFFDHE8192      uint16 = 260
	GroupX25519MLKEM768 uint16 = 0x11EC
	GroupP256MLKEM768   uint16 = 0x11EB
	GroupP384MLKEM1024  uint16 = 0x11ED
)

var groupNames = map[uint16]string{
	1: "sect163k1", 2: "sect163r1", 3: "sect163r2", 4: "sect193r1", 5: "sect193r2", 6: "sect233k1", 7: "sect233r1",
	8: "sect239k1", 9: "sect283k1", 10: "sect283r1", 11: "sect409k1", 12: "sect409r1", 13: "sect571k1", 14: "sect571r1",
	15: "secp160k1", 16: "secp160r1", 17: "secp160r2", 18: "secp192k1", 19: "secp192r1", 20: "secp224k1",
	21: "secp224r1", 22: "secp256k1", 23: "secp256r1", 24: "secp384r1", 25: "secp521r1", 26: "brainpoolP256r1",
	27: "brainpoolP384r1", 28: "brainpoolP512r1", 29: "x25519", 30: "x448",
	256: "ffdhe2048", 257: "ffdhe3072", 258: "ffdhe4096", 259: "ffdhe6144", 260: "ffdhe8192",
	0x11EB: "SecP256r1MLKEM768", 0x11EC: "X25519MLKEM768", 0x11ED: "SecP384r1MLKEM1024",
}

// GroupName names a named group.
func GroupName(g uint16) string {
	if n, ok := groupNames[g]; ok {
		return n
	}
	return "unknown"
}

// GroupBits is the approximate security-relevant size used for grading.
func GroupBits(g uint16) int {
	switch {
	case g >= 1 && g <= 14:
		return 0 // binary curves: deprecated, size irrelevant here
	case g == 15 || g == 16 || g == 17:
		return 160
	case g == 18 || g == 19:
		return 192
	case g == 20 || g == 21:
		return 224
	case g == 22 || g == 23 || g == 26 || g == 29:
		return 256
	case g == 24 || g == 27:
		return 384
	case g == 30:
		return 448
	case g == 25 || g == 28:
		return 521
	case g == GroupFFDHE2048:
		return 2048
	case g == GroupFFDHE3072:
		return 3072
	case g == GroupFFDHE4096:
		return 4096
	case g == GroupFFDHE6144:
		return 6144
	case g == GroupFFDHE8192:
		return 8192
	case g == GroupX25519MLKEM768 || g == GroupP256MLKEM768:
		return 256
	case g == GroupP384MLKEM1024:
		return 384
	}
	return 0
}

// Tls12Groups lists curves offered to TLS ≤1.2 servers so that ECDHE suites
// can be negotiated even by servers with unusual curve configurations.
var tls12Groups = func() []uint16 {
	g := []uint16{GroupX25519, GroupSecp256r1, GroupSecp384r1, GroupSecp521r1, GroupX448, 26, 27, 28}
	for i := uint16(1); i <= 22; i++ {
		g = append(g, i)
	}
	return append(g, GroupFFDHE2048, GroupFFDHE3072, GroupFFDHE4096, GroupFFDHE6144, GroupFFDHE8192)
}()

// TLS13Groups are probed individually in TLS 1.3 group enumeration.
var TLS13Groups = []uint16{GroupX25519MLKEM768, GroupP256MLKEM768, GroupP384MLKEM1024, GroupX25519, GroupSecp256r1,
	GroupSecp384r1, GroupSecp521r1, GroupX448, GroupFFDHE2048, GroupFFDHE3072, GroupFFDHE4096, GroupFFDHE6144, GroupFFDHE8192}

// Signature schemes offered: every scheme a server might require, including
// SHA-1 based ones so that legacy servers still answer.
var sigAlgs = []uint16{
	0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0804, 0x0805, 0x0806, 0x0809, 0x080a, 0x080b,
	0x0904, 0x0905, 0x0906, 0x0401, 0x0501, 0x0601, 0x0303, 0x0301, 0x0302, 0x0402, 0x0502, 0x0602,
	0x0201, 0x0203, 0x0202,
}

// Hello describes a ClientHello to send.
type Hello struct {
	Version           uint16   // legacy_version field
	RecordVersion     uint16   // record layer version; 0 = min(Version, TLS 1.0)
	Suites            []uint16 // cipher suites in preference order
	ServerName        string   // SNI; omitted for IP addresses and when empty
	SupportedVersions []uint16 // TLS 1.3 supported_versions; nil omits the extension
	Groups            []uint16 // supported_groups; nil = default for the version
	KeyShares         []uint16 // groups to send key shares for (TLS 1.3); nil = x25519
	NoKeyShares       bool     // send an empty key_share (forces HelloRetryRequest)
	Compression       []byte   // compression methods; nil = null only
	ALPN              []string
	Fallback          bool // append TLS_FALLBACK_SCSV
	NoRenegotiation   bool // omit TLS_EMPTY_RENEGOTIATION_INFO_SCSV
}

type builder struct{ b []byte }

func (w *builder) u8(v byte)    { w.b = append(w.b, v) }
func (w *builder) u16(v uint16) { w.b = binary.BigEndian.AppendUint16(w.b, v) }
func (w *builder) raw(p []byte) { w.b = append(w.b, p...) }

// vec writes a length-prefixed vector with an n-byte length (1, 2 or 3).
func (w *builder) vec(n int, f func(*builder)) {
	var inner builder
	f(&inner)
	l := len(inner.b)
	switch n {
	case 1:
		w.u8(byte(l))
	case 2:
		w.u16(uint16(l))
	case 3:
		w.b = append(w.b, byte(l>>16), byte(l>>8), byte(l))
	}
	w.raw(inner.b)
}

func keyShareFor(g uint16) ([]byte, bool) {
	switch g {
	case GroupX25519:
		k, _ := ecdh.X25519().GenerateKey(rand.Reader)
		return k.PublicKey().Bytes(), true
	case GroupSecp256r1:
		k, _ := ecdh.P256().GenerateKey(rand.Reader)
		return k.PublicKey().Bytes(), true
	case GroupSecp384r1:
		k, _ := ecdh.P384().GenerateKey(rand.Reader)
		return k.PublicKey().Bytes(), true
	case GroupSecp521r1:
		k, _ := ecdh.P521().GenerateKey(rand.Reader)
		return k.PublicKey().Bytes(), true
	}
	return nil, false
}

// Marshal encodes the ClientHello as a single TLS record.
func (h *Hello) Marshal() ([]byte, error) {
	if len(h.Suites) == 0 {
		return nil, errors.New("no cipher suites")
	}
	tls13 := len(h.SupportedVersions) > 0
	random := make([]byte, 32)
	_, _ = rand.Read(random)

	var body builder
	body.u16(h.Version)
	body.raw(random)
	if tls13 {
		// A 32-byte legacy session ID ("middlebox compatibility mode").
		sid := make([]byte, 32)
		_, _ = rand.Read(sid)
		body.vec(1, func(w *builder) { w.raw(sid) })
	} else {
		body.u8(0)
	}
	body.vec(2, func(w *builder) {
		for _, s := range h.Suites {
			w.u16(s)
		}
		if !h.NoRenegotiation && !tls13 {
			w.u16(scsvRenegotiation)
		}
		if h.Fallback {
			w.u16(scsvFallback)
		}
	})
	comp := h.Compression
	if comp == nil {
		comp = []byte{0}
	}
	body.vec(1, func(w *builder) { w.raw(comp) })

	if h.Version == VersionSSL3 && !tls13 {
		// SSLv3 has no extensions; some SSLv3-only servers reject them.
		return record(h, body.b), nil
	}
	body.vec(2, func(w *builder) {
		if h.ServerName != "" && net.ParseIP(h.ServerName) == nil {
			w.u16(extServerName)
			w.vec(2, func(w *builder) {
				w.vec(2, func(w *builder) {
					w.u8(0) // host_name
					w.vec(2, func(w *builder) { w.raw([]byte(h.ServerName)) })
				})
			})
		}
		groups := h.Groups
		if groups == nil {
			if tls13 {
				groups = TLS13Groups
			} else {
				groups = tls12Groups
			}
		}
		w.u16(extSupportedGroups)
		w.vec(2, func(w *builder) {
			w.vec(2, func(w *builder) {
				for _, g := range groups {
					w.u16(g)
				}
			})
		})
		w.u16(extECPointFormats)
		w.vec(2, func(w *builder) { w.vec(1, func(w *builder) { w.u8(0) }) })
		w.u16(extSignatureAlgorithms)
		w.vec(2, func(w *builder) {
			w.vec(2, func(w *builder) {
				for _, s := range sigAlgs {
					w.u16(s)
				}
			})
		})
		w.u16(extStatusRequest)
		w.vec(2, func(w *builder) { w.raw([]byte{1, 0, 0, 0, 0}) }) // ocsp, no responder IDs, no extensions
		w.u16(extSCT)
		w.u16(0)
		w.u16(extExtendedMaster)
		w.u16(0)
		w.u16(extEncryptThenMAC)
		w.u16(0)
		w.u16(extSessionTicket)
		w.u16(0)
		if !tls13 && !h.NoRenegotiation {
			w.u16(extRenegotiationInfo)
			w.vec(2, func(w *builder) { w.u8(0) })
		}
		if len(h.ALPN) > 0 {
			w.u16(extALPN)
			w.vec(2, func(w *builder) {
				w.vec(2, func(w *builder) {
					for _, p := range h.ALPN {
						w.vec(1, func(w *builder) { w.raw([]byte(p)) })
					}
				})
			})
		}
		if tls13 {
			w.u16(extSupportedVersions)
			w.vec(2, func(w *builder) {
				w.vec(1, func(w *builder) {
					for _, v := range h.SupportedVersions {
						w.u16(v)
					}
				})
			})
			w.u16(extPSKModes)
			w.vec(2, func(w *builder) { w.vec(1, func(w *builder) { w.u8(1) }) }) // psk_dhe_ke
			w.u16(extKeyShare)
			w.vec(2, func(w *builder) {
				w.vec(2, func(w *builder) {
					if h.NoKeyShares {
						return
					}
					shares := h.KeyShares
					if shares == nil {
						shares = []uint16{GroupX25519}
					}
					for _, g := range shares {
						if pub, ok := keyShareFor(g); ok {
							w.u16(g)
							w.vec(2, func(w *builder) { w.raw(pub) })
						}
					}
				})
			})
		}
	})
	return record(h, body.b), nil
}

func record(h *Hello, body []byte) []byte {
	var hs builder
	hs.u8(1) // client_hello
	hs.vec(3, func(w *builder) { w.raw(body) })
	rv := h.RecordVersion
	if rv == 0 {
		rv = min(h.Version, VersionTLS10)
	}
	var rec builder
	rec.u8(22) // handshake
	rec.u16(rv)
	rec.vec(2, func(w *builder) { w.raw(hs.b) })
	return rec.b
}

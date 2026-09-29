// Package scanner enumerates TLS protocol versions, cipher suites and key
// exchange groups by sending its own ClientHello messages and reading only
// the server's reply. It does not depend on which algorithms the local TLS
// library implements, so it can detect SSLv2, export and NULL ciphers that
// no modern client would negotiate. Probes never complete a handshake and
// send no application data.
package scanner

import (
	"fmt"
	"sort"
	"strings"
)

// Suite describes one cipher suite.
type Suite struct {
	ID       uint16   `json:"id"`
	Name     string   `json:"name"`
	KeyExch  string   `json:"key_exchange"`   // ECDHE, DHE, RSA, ECDH, DH, PSK, SRP, TLS1.3, NULL
	Auth     string   `json:"authentication"` // RSA, ECDSA, DSS, anon, PSK, SRP, any, NULL
	Cipher   string   `json:"cipher"`         // AES, 3DES, RC4, CHACHA20, ...
	Bits     int      `json:"bits"`
	Mode     string   `json:"mode"` // GCM, CCM, CCM8, CBC, POLY1305, stream, none
	MAC      string   `json:"mac"`  // AEAD, SHA, SHA256, SHA384, MD5
	Export   bool     `json:"export"`
	TLS13    bool     `json:"tls13"`
	Strength string   `json:"strength"` // modern, deprecated, weak, insecure
	Reasons  []string `json:"reasons,omitempty"`
}

// ForwardSecret reports whether the key exchange is ephemeral.
func (s Suite) ForwardSecret() bool {
	return s.TLS13 || s.KeyExch == "ECDHE" || s.KeyExch == "DHE"
}

// AEAD reports whether the suite uses authenticated encryption.
func (s Suite) AEAD() bool { return s.MAC == "AEAD" }

// suiteNames is the IANA TLS Cipher Suites registry subset that is seen in
// practice (all TLS 1.3 suites, the RSA/DH/ECDH/ECDHE families with every
// historic bulk cipher, PSK and SRP).
var suiteNames = map[uint16]string{
	0x0001: "TLS_RSA_WITH_NULL_MD5",
	0x0002: "TLS_RSA_WITH_NULL_SHA",
	0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
	0x0004: "TLS_RSA_WITH_RC4_128_MD5",
	0x0005: "TLS_RSA_WITH_RC4_128_SHA",
	0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
	0x0007: "TLS_RSA_WITH_IDEA_CBC_SHA",
	0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
	0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x000B: "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
	0x000C: "TLS_DH_DSS_WITH_DES_CBC_SHA",
	0x000D: "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
	0x000E: "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x000F: "TLS_DH_RSA_WITH_DES_CBC_SHA",
	0x0010: "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0011: "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
	0x0012: "TLS_DHE_DSS_WITH_DES_CBC_SHA",
	0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
	0x0014: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x0015: "TLS_DHE_RSA_WITH_DES_CBC_SHA",
	0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0017: "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
	0x0018: "TLS_DH_anon_WITH_RC4_128_MD5",
	0x0019: "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
	0x001A: "TLS_DH_anon_WITH_DES_CBC_SHA",
	0x001B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
	0x002C: "TLS_PSK_WITH_NULL_SHA",
	0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0030: "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
	0x0031: "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
	0x0032: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
	0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x0036: "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
	0x0037: "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
	0x0038: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
	0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	0x003A: "TLS_DH_anon_WITH_AES_256_CBC_SHA",
	0x003B: "TLS_RSA_WITH_NULL_SHA256",
	0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
	0x003E: "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
	0x003F: "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
	0x0040: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
	0x0041: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
	0x0042: "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
	0x0043: "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
	0x0044: "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
	0x0045: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
	0x0046: "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
	0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	0x0068: "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
	0x0069: "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
	0x006A: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
	0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
	0x006C: "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
	0x006D: "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
	0x0084: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
	0x0085: "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
	0x0086: "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
	0x0087: "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
	0x0088: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
	0x0089: "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
	0x008A: "TLS_PSK_WITH_RC4_128_SHA",
	0x008B: "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
	0x008C: "TLS_PSK_WITH_AES_128_CBC_SHA",
	0x008D: "TLS_PSK_WITH_AES_256_CBC_SHA",
	0x0096: "TLS_RSA_WITH_SEED_CBC_SHA",
	0x0097: "TLS_DH_DSS_WITH_SEED_CBC_SHA",
	0x0098: "TLS_DH_RSA_WITH_SEED_CBC_SHA",
	0x0099: "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
	0x009A: "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
	0x009B: "TLS_DH_anon_WITH_SEED_CBC_SHA",
	0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	0x00A0: "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
	0x00A1: "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
	0x00A2: "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
	0x00A3: "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
	0x00A4: "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
	0x00A5: "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
	0x00A6: "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
	0x00A7: "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
	0x00A8: "TLS_PSK_WITH_AES_128_GCM_SHA256",
	0x00A9: "TLS_PSK_WITH_AES_256_GCM_SHA384",
	0x00BA: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
	0x00BE: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
	0x00C0: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
	0x00C4: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0x1304: "TLS_AES_128_CCM_SHA256",
	0x1305: "TLS_AES_128_CCM_8_SHA256",
	0xC001: "TLS_ECDH_ECDSA_WITH_NULL_SHA",
	0xC002: "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
	0xC003: "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
	0xC004: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
	0xC005: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
	0xC006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
	0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
	0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	0xC00B: "TLS_ECDH_RSA_WITH_NULL_SHA",
	0xC00C: "TLS_ECDH_RSA_WITH_RC4_128_SHA",
	0xC00D: "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
	0xC00E: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
	0xC00F: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
	0xC010: "TLS_ECDHE_RSA_WITH_NULL_SHA",
	0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0xC015: "TLS_ECDH_anon_WITH_NULL_SHA",
	0xC016: "TLS_ECDH_anon_WITH_RC4_128_SHA",
	0xC017: "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
	0xC018: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
	0xC019: "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
	0xC01A: "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
	0xC01B: "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
	0xC01C: "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
	0xC01D: "TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
	0xC01E: "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
	0xC01F: "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
	0xC020: "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
	0xC021: "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
	0xC022: "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
	0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	0xC025: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
	0xC026: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
	0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	0xC029: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
	0xC02A: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
	0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xC02D: "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
	0xC02E: "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
	0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xC031: "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
	0xC032: "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
	0xC035: "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
	0xC036: "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
	0xC03C: "TLS_RSA_WITH_ARIA_128_CBC_SHA256",
	0xC03D: "TLS_RSA_WITH_ARIA_256_CBC_SHA384",
	0xC044: "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256",
	0xC045: "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384",
	0xC048: "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
	0xC049: "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
	0xC04C: "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
	0xC04D: "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
	0xC050: "TLS_RSA_WITH_ARIA_128_GCM_SHA256",
	0xC051: "TLS_RSA_WITH_ARIA_256_GCM_SHA384",
	0xC052: "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
	0xC053: "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384",
	0xC05C: "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
	0xC05D: "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
	0xC060: "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
	0xC061: "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
	0xC072: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
	0xC073: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
	0xC076: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
	0xC077: "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
	0xC07A: "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256",
	0xC07B: "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384",
	0xC07C: "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
	0xC07D: "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
	0xC086: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
	0xC087: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
	0xC08A: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
	0xC08B: "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
	0xC09C: "TLS_RSA_WITH_AES_128_CCM",
	0xC09D: "TLS_RSA_WITH_AES_256_CCM",
	0xC09E: "TLS_DHE_RSA_WITH_AES_128_CCM",
	0xC09F: "TLS_DHE_RSA_WITH_AES_256_CCM",
	0xC0A0: "TLS_RSA_WITH_AES_128_CCM_8",
	0xC0A1: "TLS_RSA_WITH_AES_256_CCM_8",
	0xC0A2: "TLS_DHE_RSA_WITH_AES_128_CCM_8",
	0xC0A3: "TLS_DHE_RSA_WITH_AES_256_CCM_8",
	0xC0AC: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
	0xC0AD: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
	0xC0AE: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
	0xC0AF: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
	0xCC13: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD",
	0xCC14: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_OLD",
	0xCC15: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD",
	0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0xCCAB: "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
	0xCCAC: "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
	0xCCAD: "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
	0xCCAE: "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256",
}

// Signalling cipher suite values (not real suites).
const (
	scsvRenegotiation uint16 = 0x00FF
	scsvFallback      uint16 = 0x5600
)

var registry = func() map[uint16]Suite {
	m := make(map[uint16]Suite, len(suiteNames))
	for id, name := range suiteNames {
		m[id] = classify(id, name)
	}
	return m
}()

// Lookup returns the suite with id, or a placeholder for unknown IDs.
func Lookup(id uint16) Suite {
	if s, ok := registry[id]; ok {
		return s
	}
	return Suite{ID: id, Name: fmt.Sprintf("UNKNOWN_0x%04X", id), Strength: "unknown"}
}

// TLS13Suites returns the TLS 1.3 suites in registry order.
func TLS13Suites() []uint16 { return filterIDs(func(s Suite) bool { return s.TLS13 }) }

// LegacySuites returns all TLS 1.0–1.2 suites.
func LegacySuites() []uint16 { return filterIDs(func(s Suite) bool { return !s.TLS13 }) }

func filterIDs(f func(Suite) bool) []uint16 {
	var out []uint16
	for id, s := range registry {
		if f(s) {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// classify derives the suite properties from its IANA name and assigns a
// strength based on documented weaknesses.
func classify(id uint16, name string) Suite {
	s := Suite{ID: id, Name: name}
	n := strings.TrimPrefix(name, "TLS_")
	n = strings.TrimSuffix(n, "_OLD")
	kx, enc, found := strings.Cut(n, "_WITH_")
	if !found {
		// TLS 1.3: TLS_AES_128_GCM_SHA256
		s.TLS13, s.KeyExch, s.Auth, enc = true, "TLS1.3", "any", n
	} else {
		if strings.Contains(kx, "_EXPORT") {
			s.Export = true
			kx = strings.Replace(kx, "_EXPORT", "", 1)
		}
		parts := strings.Split(kx, "_")
		s.KeyExch = parts[0]
		s.Auth = s.KeyExch
		if len(parts) > 1 {
			s.Auth = parts[1]
		}
		switch s.KeyExch {
		case "RSA":
			if len(parts) > 1 && parts[1] == "PSK" {
				s.KeyExch, s.Auth = "RSA", "PSK"
			} else {
				s.Auth = "RSA"
			}
		case "SRP":
			s.Auth = "SRP"
			if len(parts) > 2 {
				s.Auth = parts[2]
			}
		case "PSK":
			s.Auth = "PSK"
		}
	}
	// Bulk cipher and MAC.
	switch {
	case strings.HasPrefix(enc, "NULL"):
		s.Cipher, s.Mode = "NULL", "none"
	case strings.HasPrefix(enc, "RC4_40"):
		s.Cipher, s.Bits, s.Mode = "RC4", 40, "stream"
	case strings.HasPrefix(enc, "RC4_128"):
		s.Cipher, s.Bits, s.Mode = "RC4", 128, "stream"
	case strings.HasPrefix(enc, "RC2_CBC_40"):
		s.Cipher, s.Bits, s.Mode = "RC2", 40, "CBC"
	case strings.HasPrefix(enc, "DES40"):
		s.Cipher, s.Bits, s.Mode = "DES", 40, "CBC"
	case strings.HasPrefix(enc, "DES_CBC"):
		s.Cipher, s.Bits, s.Mode = "DES", 56, "CBC"
	case strings.HasPrefix(enc, "3DES"):
		s.Cipher, s.Bits, s.Mode = "3DES", 112, "CBC"
	case strings.HasPrefix(enc, "IDEA"):
		s.Cipher, s.Bits, s.Mode = "IDEA", 128, "CBC"
	case strings.HasPrefix(enc, "SEED"):
		s.Cipher, s.Bits, s.Mode = "SEED", 128, "CBC"
	case strings.HasPrefix(enc, "CHACHA20"):
		s.Cipher, s.Bits, s.Mode = "CHACHA20", 256, "POLY1305"
	default:
		f := strings.Split(enc, "_") // AES_128_GCM_SHA256
		if len(f) >= 3 {
			s.Cipher = f[0]
			_, _ = fmt.Sscanf(f[1], "%d", &s.Bits)
			s.Mode = f[2]
			if len(f) >= 4 && f[3] == "8" {
				s.Mode = "CCM8"
			}
		}
	}
	switch {
	case s.Mode == "GCM" || s.Mode == "CCM" || s.Mode == "CCM8" || s.Mode == "POLY1305":
		s.MAC = "AEAD"
	case strings.HasSuffix(enc, "_MD5"):
		s.MAC = "MD5"
	case strings.HasSuffix(enc, "_SHA384"):
		s.MAC = "SHA384"
	case strings.HasSuffix(enc, "_SHA256"):
		s.MAC = "SHA256"
	case strings.HasSuffix(enc, "_SHA"):
		s.MAC = "SHA1"
	}

	// Strength, from the most severe applicable weakness.
	var insecure, weak, deprecated []string
	switch {
	case s.Cipher == "NULL":
		insecure = append(insecure, "no encryption (NULL cipher)")
	case s.Export:
		insecure = append(insecure, "export-grade cryptography (FREAK, Logjam)")
	case s.Cipher == "RC4":
		insecure = append(insecure, "RC4 is prohibited (RFC 7465)")
	case s.Cipher == "DES" || s.Cipher == "RC2":
		insecure = append(insecure, s.Cipher+" keys can be brute-forced")
	}
	if s.Auth == "anon" {
		insecure = append(insecure, "anonymous key exchange allows trivial man-in-the-middle")
	}
	if s.MAC == "MD5" && s.Cipher != "RC4" {
		insecure = append(insecure, "MD5 MAC")
	}
	if s.Cipher == "3DES" || s.Cipher == "IDEA" {
		weak = append(weak, "64-bit block cipher (Sweet32, CVE-2016-2183)")
	}
	if !s.ForwardSecret() && s.KeyExch != "PSK" {
		deprecated = append(deprecated, "no forward secrecy (static "+s.KeyExch+" key exchange)")
	}
	if s.Mode == "CBC" {
		deprecated = append(deprecated, "CBC mode with MAC-then-encrypt (Lucky13, padding oracles)")
	}
	if s.Mode == "CCM8" {
		deprecated = append(deprecated, "truncated 64-bit authentication tag")
	}
	if strings.HasSuffix(name, "_OLD") {
		deprecated = append(deprecated, "pre-standard ChaCha20 draft")
	}
	switch {
	case len(insecure) > 0:
		s.Strength = "insecure"
	case len(weak) > 0:
		s.Strength = "weak"
	case len(deprecated) > 0:
		s.Strength = "deprecated"
	default:
		s.Strength = "modern"
	}
	s.Reasons = append(append(insecure, weak...), deprecated...)
	return s
}

package scanner

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
)

// SSLv2 cipher kinds (3-byte codes).
var sslv2Ciphers = [][3]byte{
	{0x01, 0x00, 0x80}, // SSL_CK_RC4_128_WITH_MD5
	{0x02, 0x00, 0x80}, // SSL_CK_RC4_128_EXPORT40_WITH_MD5
	{0x03, 0x00, 0x80}, // SSL_CK_RC2_128_CBC_WITH_MD5
	{0x04, 0x00, 0x80}, // SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
	{0x05, 0x00, 0x80}, // SSL_CK_IDEA_128_CBC_WITH_MD5
	{0x06, 0x00, 0x40}, // SSL_CK_DES_64_CBC_WITH_MD5
	{0x07, 0x00, 0xC0}, // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
}

// probeSSLv2 sends an SSLv2 CLIENT-HELLO and reports whether the server
// answered with an SSLv2 SERVER-HELLO offering at least one cipher.
func (p *Prober) probeSSLv2(ctx context.Context) (bool, error) {
	challenge := make([]byte, 16)
	_, _ = rand.Read(challenge)
	var body []byte
	body = append(body, 1, 0x00, 0x02) // CLIENT-HELLO, version 2
	body = binary.BigEndian.AppendUint16(body, uint16(3*len(sslv2Ciphers)))
	body = binary.BigEndian.AppendUint16(body, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(challenge)))
	for _, c := range sslv2Ciphers {
		body = append(body, c[:]...)
	}
	body = append(body, challenge...)
	msg := append([]byte{0x80 | byte(len(body)>>8), byte(len(body))}, body...)

	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	conn, err := p.Dial(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := conn.Write(msg); err != nil {
		return false, ErrRejected
	}
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return false, ErrRejected
	}
	if hdr[0]&0x80 == 0 {
		return false, ErrRejected // TLS alert or other non-SSLv2 reply
	}
	n := int(hdr[0]&0x7f)<<8 | int(hdr[1])
	if n < 11 || n > 32768 {
		return false, ErrRejected
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return false, ErrRejected
	}
	// SERVER-HELLO: type(4) hit(1) cert_type(1) version(2) cert_len(2) specs_len(2) conn_id_len(2)
	if resp[0] != 4 || binary.BigEndian.Uint16(resp[3:5]) != 0x0002 {
		return false, ErrRejected
	}
	specs := binary.BigEndian.Uint16(resp[7:9])
	return specs >= 3, nil
}

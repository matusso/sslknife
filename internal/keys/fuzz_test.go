package keys

import "testing"

func FuzzParseKeys(f *testing.F) {
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nMAA=\n-----END PRIVATE KEY-----\n"))
	f.Add([]byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nMAA=\n-----END ENCRYPTED PRIVATE KEY-----\n"))
	f.Add([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA== x"))
	f.Add([]byte("---- BEGIN SSH2 PUBLIC KEY ----\nComment: x\nAAAA\n---- END SSH2 PUBLIC KEY ----\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		pw := func() ([]byte, error) { return []byte("x"), nil }
		_, _ = ParsePrivateKeys(data, pw)
		_, _ = ParsePublicKey(data)
		_, _ = DecryptPKCS8(data, []byte("x"))
	})
}

package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" //nolint:gosec // decrypting legacy 3DES-protected keys; never used for writing
	"crypto/pbkdf2"
	"crypto/sha1" //nolint:gosec // PBKDF2-HMAC-SHA1 is needed to read older PKCS#8 files
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"

	"golang.org/x/crypto/scrypt"

	skcrypto "github.com/matusso/sslknife/internal/crypto"
)

// Encrypted PKCS#8 (RFC 5958 EncryptedPrivateKeyInfo with PBES2, RFC 8018).
// Writing always uses PBKDF2-HMAC-SHA256 + AES-256-CBC, the same as
// `openssl pkcs8 -topk8 -v2 aes-256-cbc`. Reading also accepts other
// PBES2 PRFs, AES-128/192, 3DES and scrypt.

var (
	oidPBES2      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidScrypt     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}
	oidHMACSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	oidAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

// PBKDF2Iterations is used when writing encrypted PKCS#8 (OWASP 2023
// recommendation for PBKDF2-HMAC-SHA256).
const PBKDF2Iterations = 600_000

// ErrIncorrectPassword is returned when decryption fails.
var ErrIncorrectPassword = errors.New("incorrect password or corrupted key")

type encryptedPrivateKeyInfo struct {
	Algo pkix.AlgorithmIdentifier
	Data []byte
}

type pbes2Params struct {
	KDF    pkix.AlgorithmIdentifier
	Scheme pkix.AlgorithmIdentifier
}

type pbkdf2Params struct {
	Salt       []byte
	Iterations int
	KeyLength  int                      `asn1:"optional"`
	PRF        pkix.AlgorithmIdentifier `asn1:"optional"`
}

type scryptParams struct {
	Salt      []byte
	N         int
	R         int
	P         int
	KeyLength int `asn1:"optional"`
}

// EncryptPKCS8 wraps an unencrypted PKCS#8 DER blob.
func EncryptPKCS8(pkcs8, password []byte) ([]byte, error) {
	return encryptPKCS8(pkcs8, password, PBKDF2Iterations)
}

func encryptPKCS8(pkcs8, password []byte, iterations int) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("empty password")
	}
	salt := skcrypto.RandomBytes(16)
	iv := skcrypto.RandomBytes(aes.BlockSize)
	key, err := pbkdf2.Key(sha256.New, string(password), salt, iterations, 32)
	if err != nil {
		return nil, err
	}
	defer skcrypto.Zero(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padLen := aes.BlockSize - len(pkcs8)%aes.BlockSize
	buf := make([]byte, len(pkcs8)+padLen)
	copy(buf, pkcs8)
	for i := len(pkcs8); i < len(buf); i++ {
		buf[i] = byte(padLen)
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(buf, buf)

	kdfParams, err := asn1.Marshal(pbkdf2Params{
		Salt: salt, Iterations: iterations, KeyLength: 32,
		PRF: pkix.AlgorithmIdentifier{Algorithm: oidHMACSHA256, Parameters: asn1.NullRawValue},
	})
	if err != nil {
		return nil, err
	}
	ivDER, err := asn1.Marshal(iv)
	if err != nil {
		return nil, err
	}
	params, err := asn1.Marshal(pbes2Params{
		KDF:    pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdfParams}},
		Scheme: pkix.AlgorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: ivDER}},
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(encryptedPrivateKeyInfo{
		Algo: pkix.AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: params}},
		Data: buf,
	})
}

// DecryptPKCS8 unwraps an EncryptedPrivateKeyInfo and returns PKCS#8 DER.
func DecryptPKCS8(der, password []byte) ([]byte, error) {
	var epki encryptedPrivateKeyInfo
	if rest, err := asn1.Unmarshal(der, &epki); err != nil || len(rest) != 0 {
		return nil, errors.New("malformed encrypted PKCS#8")
	}
	if !epki.Algo.Algorithm.Equal(oidPBES2) {
		return nil, fmt.Errorf("unsupported PKCS#8 encryption %v (only PBES2 is supported; PBES1 uses broken ciphers)", epki.Algo.Algorithm)
	}
	var params pbes2Params
	if _, err := asn1.Unmarshal(epki.Algo.Parameters.FullBytes, &params); err != nil {
		return nil, errors.New("malformed PBES2 parameters")
	}

	var newCipher func([]byte) (cipher.Block, error)
	keyLen := 0
	switch {
	case params.Scheme.Algorithm.Equal(oidAES128CBC):
		newCipher, keyLen = aes.NewCipher, 16
	case params.Scheme.Algorithm.Equal(oidAES192CBC):
		newCipher, keyLen = aes.NewCipher, 24
	case params.Scheme.Algorithm.Equal(oidAES256CBC):
		newCipher, keyLen = aes.NewCipher, 32
	case params.Scheme.Algorithm.Equal(oidDESEDE3CBC):
		newCipher, keyLen = des.NewTripleDESCipher, 24
	default:
		return nil, fmt.Errorf("unsupported PBES2 cipher %v", params.Scheme.Algorithm)
	}
	var iv []byte
	if _, err := asn1.Unmarshal(params.Scheme.Parameters.FullBytes, &iv); err != nil {
		return nil, errors.New("malformed cipher IV")
	}

	var key []byte
	switch {
	case params.KDF.Algorithm.Equal(oidPBKDF2):
		var kp pbkdf2Params
		if _, err := asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kp); err != nil {
			return nil, errors.New("malformed PBKDF2 parameters")
		}
		if kp.Iterations < 1 || kp.Iterations > 10_000_000 {
			return nil, fmt.Errorf("unreasonable PBKDF2 iteration count %d", kp.Iterations)
		}
		var h func() hash.Hash
		switch {
		case len(kp.PRF.Algorithm) == 0 || kp.PRF.Algorithm.Equal(oidHMACSHA1):
			h = sha1.New
		case kp.PRF.Algorithm.Equal(oidHMACSHA256):
			h = sha256.New
		case kp.PRF.Algorithm.Equal(oidHMACSHA384):
			h = sha512.New384
		case kp.PRF.Algorithm.Equal(oidHMACSHA512):
			h = sha512.New
		default:
			return nil, fmt.Errorf("unsupported PBKDF2 PRF %v", kp.PRF.Algorithm)
		}
		var err error
		key, err = pbkdf2.Key(h, string(password), kp.Salt, kp.Iterations, keyLen)
		if err != nil {
			return nil, err
		}
	case params.KDF.Algorithm.Equal(oidScrypt):
		var sp scryptParams
		if _, err := asn1.Unmarshal(params.KDF.Parameters.FullBytes, &sp); err != nil {
			return nil, errors.New("malformed scrypt parameters")
		}
		if sp.N > 1<<22 || sp.R > 64 || sp.P > 16 {
			return nil, errors.New("unreasonable scrypt parameters")
		}
		var err error
		key, err = scrypt.Key(password, sp.Salt, sp.N, sp.R, sp.P, keyLen)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported PBES2 KDF %v", params.KDF.Algorithm)
	}
	defer skcrypto.Zero(key)

	block, err := newCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(iv) != bs || len(epki.Data) == 0 || len(epki.Data)%bs != 0 {
		return nil, errors.New("malformed encrypted data")
	}
	out := make([]byte, len(epki.Data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, epki.Data)
	pad := int(out[len(out)-1])
	if pad == 0 || pad > bs {
		return nil, ErrIncorrectPassword
	}
	want := make([]byte, pad)
	for i := range want {
		want[i] = byte(pad)
	}
	if subtle.ConstantTimeCompare(out[len(out)-pad:], want) != 1 {
		return nil, ErrIncorrectPassword
	}
	return out[:len(out)-pad], nil
}

package errors

import "errors"

var (
	ErrKeyGeneration        = errors.New("key generation failed")
	ErrInvalidKeySize       = errors.New("invalid key size")
	ErrInvalidIVSize        = errors.New("invalid IV size")
	ErrInvalidPlaintextSize = errors.New("invalid plaintext size")
	ErrEncryptionFailed     = errors.New("encryption failed")
	ErrDecryptionFailed     = errors.New("decryption failed")
	ErrInvalidCiphertext    = errors.New("invalid ciphertext")
	ErrPemDataDecode        = errors.New("failed to decode PEM dat")
	ErrPemParse             = errors.New("failed to parse PEM data")
	ErrNotRsaKey            = errors.New("not RSA key")
)

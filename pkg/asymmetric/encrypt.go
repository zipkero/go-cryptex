package asymmetric

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"go-cryptex/internal/errors"
)

type RSACipher struct {
	KeyPair *KeyPair
}

func NewRSACipher(keyPair *KeyPair) *RSACipher {
	return &RSACipher{KeyPair: keyPair}
}

func NewRSACipherWithKeySize(keySize int) (*RSACipher, error) {
	keyPair, err := GenerateKeyPair(keySize)
	if err != nil {
		return nil, err
	}
	return NewRSACipher(keyPair), nil
}

func (r *RSACipher) GetKeyPair() *KeyPair {
	return r.KeyPair
}
func (r *RSACipher) GetPublicKey() *rsa.PublicKey {
	return r.KeyPair.PublicKey
}

func (r *RSACipher) Encrypt(plaintext []byte) ([]byte, error) {
	return encryptWithPublicKey(plaintext, r.KeyPair.PublicKey)
}

func encryptWithPublicKey(plaintext []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	maxSize := publicKey.Size() - 2*sha256.Size - 2
	if len(plaintext) > maxSize {
		return nil, errors.ErrInvalidPlaintextSize
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrEncryptionFailed, err)
	}
	return ciphertext, nil
}

func (r *RSACipher) Decrypt(ciphertext []byte) ([]byte, error) {
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, r.KeyPair.PrivateKey, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrDecryptionFailed, err)
	}
	return plaintext, nil
}

func DecryptWithPrivateKey(ciphertext []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrDecryptionFailed, err)
	}
	return plaintext, nil
}

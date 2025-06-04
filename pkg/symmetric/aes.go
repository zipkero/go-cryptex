package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"go-cryptex/internal/errors"
	"go-cryptex/pkg/utils"
)

type AESCipher struct {
	key []byte
}

func NewAESCipher(key []byte) (*AESCipher, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.ErrInvalidKeySize
	}
	return &AESCipher{key: key}, nil
}

func NewAESCipherWithRandomKey() (*AESCipher, error) {
	key, err := utils.GenerateAESKey()
	if err != nil {
		return nil, errors.ErrKeyGeneration
	}
	return NewAESCipher(key)
}

func (a *AESCipher) Encrypt(plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", errors.ErrEncryptionFailed, err)
	}

	iv, err := utils.GenerateIV()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	paddedPlaintext := pkcs7Padding(plaintext, aes.BlockSize)

	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(paddedPlaintext))
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	return ciphertext, iv, nil
}

func (a *AESCipher) Decrypt(ciphertext []byte, iv []byte) ([]byte, error) {
	if len(iv) != aes.BlockSize {
		return nil, errors.ErrInvalidIVSize
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.ErrInvalidCiphertext
	}

	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrDecryptionFailed, err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	unpaddedPlaintext, err := pkcs7UnPadding(plaintext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrDecryptionFailed, err)
	}

	return unpaddedPlaintext, nil
}

func (a *AESCipher) GetKey() []byte {
	key := make([]byte, len(a.key))
	copy(key, a.key)
	return key
}

func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}
	return append(data, padText...)
}

func pkcs7UnPadding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("invalid data")
	}

	padding := int(data[len(data)-1])
	if padding > len(data) || padding == 0 {
		return nil, fmt.Errorf("invalid padding")
	}

	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return data[:len(data)-padding], nil
}

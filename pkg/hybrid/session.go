package hybrid

import (
	"crypto/rsa"
	"go-cryptex/pkg/asymmetric"
	"go-cryptex/pkg/utils"
)

type SessionManager struct {
	rsaCipher *asymmetric.RSACipher
}

func NewSessionManager(keyPair *asymmetric.KeyPair) *SessionManager {
	return &SessionManager{rsaCipher: asymmetric.NewRSACipher(keyPair)}
}

func (s *SessionManager) GenerateSessionKey() ([]byte, error) {
	return utils.GenerateAESKey()
}

func (s *SessionManager) EncryptSessionKey(sessionKey []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	cipher := &asymmetric.RSACipher{
		KeyPair: &asymmetric.KeyPair{
			PublicKey: publicKey,
		},
	}
	return cipher.Encrypt(sessionKey)
}

func (s *SessionManager) DecryptSessionKey(encryptedSessionKey []byte) ([]byte, error) {
	return s.rsaCipher.Decrypt(encryptedSessionKey)
}

func EncryptSessionKeyWithPublicKey(encryptedSessionKey []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	cipher := &asymmetric.RSACipher{
		KeyPair: &asymmetric.KeyPair{
			PublicKey: publicKey,
		},
	}
	return cipher.Decrypt(encryptedSessionKey)
}

func DecryptSessionKeyWithPrivateKey(encryptedSessionKey []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	return asymmetric.DecryptWithPrivateKey(encryptedSessionKey, privateKey)
}

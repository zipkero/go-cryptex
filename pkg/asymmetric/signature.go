package asymmetric

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

type RSASignature struct {
	keyPair *KeyPair
}

func NewRSASignature(keyPair *KeyPair) *RSASignature {
	return &RSASignature{keyPair: keyPair}
}

func (r *RSASignature) Sign(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)

	signature, err := rsa.SignPSS(rand.Reader, r.keyPair.PrivateKey, crypto.SHA256, hash[:], nil)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (r *RSASignature) Verify(data []byte, signature []byte) error {
	return VerifyWithPublicKey(data, signature, r.keyPair.PublicKey)
}

func VerifyWithPublicKey(data []byte, signature []byte, publicKey *rsa.PublicKey) error {
	hash := sha256.Sum256(data)

	err := rsa.VerifyPSS(publicKey, crypto.SHA256, hash[:], signature, nil)
	if err != nil {
		return err
	}
	return nil
}

func SignWithPrivateKey(data []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(data)
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash[:], nil)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

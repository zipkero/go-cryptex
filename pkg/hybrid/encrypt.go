package hybrid

import (
	"crypto/rsa"
	"fmt"
	"go-cryptex/internal/errors"
	"go-cryptex/pkg/asymmetric"
	"go-cryptex/pkg/symmetric"
)

type Encryptor struct {
	myKeyPair     *asymmetric.KeyPair
	peerPublicKey *rsa.PublicKey
}

func NewHybridEncryptor(myKeyPair *asymmetric.KeyPair, peerPublicKey *rsa.PublicKey) *Encryptor {
	return &Encryptor{
		myKeyPair:     myKeyPair,
		peerPublicKey: peerPublicKey,
	}
}

func (e *Encryptor) Encrypt(data []byte) (*EncryptionResult, error) {
	sessionManager := NewSessionManager(e.myKeyPair)
	sessionKey, err := sessionManager.GenerateSessionKey()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrKeyGeneration, err)
	}

	aesCipher, err := symmetric.NewAESCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrCipherGeneration, err)
	}

	encryptedData, iv, err := aesCipher.Encrypt(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrEncryptionFailed, err)
	}

	encryptedSessionKey, err := sessionManager.EncryptSessionKey(sessionKey, e.peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrEncryptionFailed, err)
	}

	messageToSign := append(encryptedSessionKey, encryptedData...)
	messageToSign = append(messageToSign, iv...)

	signer := asymmetric.NewRSASignature(e.myKeyPair)
	signature, err := signer.Sign(messageToSign)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	hybridMessage := &HybridMessage{
		EncryptedSessionKey: encryptedSessionKey,
		EncryptedData:       encryptedData,
		IV:                  iv,
		Signature:           signature,
		SignerPublicKey:     e.myKeyPair.PublicKey,
	}

	return &EncryptionResult{
		Message:    hybridMessage,
		SessionKey: encryptedSessionKey,
	}, nil
}

func (e *Encryptor) Decrypt(message *HybridMessage) ([]byte, error) {
	messageToVerify := append(message.EncryptedSessionKey, message.EncryptedData...)
	messageToVerify = append(messageToVerify, message.IV...)

	err := asymmetric.VerifyWithPublicKey(messageToVerify, message.Signature, message.SignerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	sessionManager := NewSessionManager(e.myKeyPair)
	sessionKey, err := sessionManager.DecryptSessionKey(message.EncryptedSessionKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrDecryptionFailed, err)
	}

	aesCipher, err := symmetric.NewAESCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrCipherGeneration, err)
	}

	decryptedData, err := aesCipher.Decrypt(message.EncryptedData, message.IV)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrDecryptionFailed, err)
	}

	return decryptedData, nil
}

func EncryptForPeer(data []byte, senderKeyPair *asymmetric.KeyPair, peerPublicKey *rsa.PublicKey) (*EncryptionResult, error) {
	encryptor := NewHybridEncryptor(senderKeyPair, peerPublicKey)
	result, err := encryptor.Encrypt(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrEncryptionFailed, err)
	}
	return result, nil
}

func DecryptFromPeer(message *HybridMessage, receiverKeyPair *asymmetric.KeyPair) ([]byte, error) {
	encryptor := NewHybridEncryptor(receiverKeyPair, message.SignerPublicKey)
	return encryptor.Decrypt(message)
}

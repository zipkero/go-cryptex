package hybrid

import (
	"crypto/rsa"
	"fmt"
	"go-cryptex/internal/errors"
	"go-cryptex/pkg/asymmetric"
)

type KeyExchange struct {
	myKeyPair     *asymmetric.KeyPair
	peerPublicKey *rsa.PublicKey
}

func NewKeyExchange(myKeyPair *asymmetric.KeyPair, peerPublicKey *rsa.PublicKey) *KeyExchange {
	return &KeyExchange{
		myKeyPair:     myKeyPair,
		peerPublicKey: peerPublicKey,
	}
}

func (k *KeyExchange) CreateKeyExchangeMessage() (*KeyExchangeMessage, []byte, error) {
	sessionManager := NewSessionManager(k.myKeyPair)
	sessionKey, err := sessionManager.GenerateSessionKey()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", errors.ErrKeyGeneration, err)
	}

	encryptedSessionKey, err := sessionManager.EncryptSessionKey(sessionKey, k.peerPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", errors.ErrEncryptionFailed, err)
	}

	signer := asymmetric.NewRSASignature(k.myKeyPair)
	signature, err := signer.Sign(encryptedSessionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign session key: %w", err)
	}

	message := &KeyExchangeMessage{
		EncryptedSessionKey: encryptedSessionKey,
		Signature:           signature,
		SenderPublicKey:     k.myKeyPair.PublicKey,
	}

	return message, sessionKey, nil
}

func (k *KeyExchange) ProcessKeyExchangeMessage(message *KeyExchangeMessage) ([]byte, error) {
	err := asymmetric.VerifyWithPublicKey(message.EncryptedSessionKey, message.Signature, message.SenderPublicKey)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	sessionManager := NewSessionManager(k.myKeyPair)
	sessionKey, err := sessionManager.DecryptSessionKey(message.EncryptedSessionKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrDecryptionFailed, err)
	}
	return sessionKey, nil
}

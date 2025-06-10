package hybrid

import (
	"crypto/rsa"
	"go-cryptex/pkg/asymmetric"
)

type HybridMessage struct {
	EncryptedSessionKey []byte         `json:"encrypted_session_key"`
	EncryptedData       []byte         `json:"encrypted_data"`
	IV                  []byte         `json:"iv"`
	Signature           []byte         `json:"signature"`
	SignerPublicKey     *rsa.PublicKey `json:"-"`
}

type SessionKeyInfo struct {
	Key []byte `json:"key"`
	IV  []byte `json:"iv"`
}

type HybridCipher struct {
	MyKeyPair     *asymmetric.KeyPair
	PeerPublicKey *rsa.PublicKey
}

type EncryptionResult struct {
	Message    *HybridMessage
	SessionKey []byte
}

type KeyExchangeMessage struct {
	EncryptedSessionKey []byte         `json:"encrypted_session_key"`
	Signature           []byte         `json:"signature"`
	SenderPublicKey     *rsa.PublicKey `json:"-"`
}

package main

import (
	"go-cryptex/pkg/asymmetric"
	"go-cryptex/pkg/hybrid"
	"go-cryptex/pkg/utils"
	"log"
)

func main() {
	senderKeyPair, err := asymmetric.GenerateKeyPair(2048)
	if err != nil {
		panic(err)
	}

	receiverKeyPair, err := asymmetric.GenerateKeyPair(2048)
	if err != nil {
		panic(err)
	}

	message := "sender > receiver"

	senderEncryptor := hybrid.NewHybridEncryptor(senderKeyPair, receiverKeyPair.PublicKey)
	encryptionResult, err := senderEncryptor.Encrypt([]byte(message))
	if err != nil {
		panic(err)
	}

	log.Printf("세션키 길이: %d bytes", len(encryptionResult.SessionKey))
	log.Printf("암호화된 세션키 길이: %d bytes", len(encryptionResult.Message.EncryptedSessionKey))
	log.Printf("암호화된 데이터 길이: %d bytes", len(encryptionResult.Message.EncryptedData))
	log.Printf("IV 길이: %d bytes", len(encryptionResult.Message.IV))
	log.Printf("서명 길이: %d bytes", len(encryptionResult.Message.Signature))

	// Base64 인코딩하여 전송 가능한 형태로 변환
	log.Printf("암호화된 세션키 (Base64): %s", utils.Base64Encode(encryptionResult.Message.EncryptedSessionKey))
	log.Printf("암호화된 데이터 (Base64): %s", utils.Base64Encode(encryptionResult.Message.EncryptedData))
	log.Printf("IV (Base64): %s", utils.Base64Encode(encryptionResult.Message.IV))
	log.Printf("서명 (Base64): %s", utils.Base64Encode(encryptionResult.Message.Signature))

	receiverEncryptor := hybrid.NewHybridEncryptor(receiverKeyPair, senderKeyPair.PublicKey)
	decryptedMessage, err := receiverEncryptor.Decrypt(encryptionResult.Message)
	if err != nil {
		panic(err)
	}

	log.Printf("복호화된 메시지: %s", string(decryptedMessage))

	if string(decryptedMessage) == message {
		log.Println("success")
	} else {
		log.Println("fail")
	}

	senderExchange := hybrid.NewKeyExchange(senderKeyPair, receiverKeyPair.PublicKey)
	senderMessage, senderSessionKey, err := senderExchange.CreateKeyExchangeMessage()
	if err != nil {
		panic(err)
	}

	log.Printf("sender session key: %s", utils.HexEncode(senderSessionKey))

	receiverExchange := hybrid.NewKeyExchange(receiverKeyPair, senderKeyPair.PublicKey)
	receiverSessionKey, err := receiverExchange.ProcessKeyExchangeMessage(senderMessage)
	if err != nil {
		panic(err)
	}

	log.Printf("receiver session key: %s", utils.HexEncode(receiverSessionKey))

	if utils.HexEncode(senderSessionKey) == utils.HexEncode(receiverSessionKey) {
		log.Println("success")
	} else {
		log.Println("fail")
	}
}

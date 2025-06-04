package main

import (
	"go-cryptex/pkg/asymmetric"
	"go-cryptex/pkg/utils"
	"log"
)

func main() {
	// 1. RSA 키쌍 생성
	log.Println("=== RSA 키쌍 생성 ===")
	cipher, err := asymmetric.NewRSACipherWithKeySize(2048)
	if err != nil {
		panic(err)
	}

	// 2. 공개키/개인키 PEM 형식으로 출력
	publicKeyPEM, _ := cipher.GetKeyPair().ExportPublicKeyPEM()
	privateKeyPEM, _ := cipher.GetKeyPair().ExportPrivateKeyPEM()

	log.Println("공개키:")
	log.Println(string(publicKeyPEM))
	log.Println("개인키:")
	log.Println(string(privateKeyPEM))

	// 3. 암호화/복호화 테스트
	log.Println("\n=== RSA 암호화/복호화 테스트 ===")
	plaintext := "RSA TST"
	log.Printf("원본: %s", plaintext)

	// 공개키로 암호화
	ciphertext, err := cipher.Encrypt([]byte(plaintext))
	if err != nil {
		panic(err)
	}

	encodedCiphertext := utils.Base64Encode(ciphertext)
	log.Printf("암호화+Base64: %s", encodedCiphertext)

	// 개인키로 복호화
	decrypted, err := cipher.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}

	log.Printf("복호화: %s", string(decrypted))

	// 4. 디지털 서명 테스트
	log.Println("\n=== 디지털 서명 테스트 ===")
	signer := asymmetric.NewRSASignature(cipher.GetKeyPair())

	message := "this message is signed by RSA!"
	log.Printf("서명할 메시지: %s", message)

	// 서명 생성
	signature, err := signer.Sign([]byte(message))
	if err != nil {
		panic(err)
	}

	encodedSignature := utils.Base64Encode(signature)
	log.Printf("서명+Base64: %s", encodedSignature)

	// 서명 검증
	err = signer.Verify([]byte(message), signature)
	if err != nil {
		log.Printf("sign failed: %v", err)
	} else {
		log.Println("sign success!")
	}

	// 5. 잘못된 메시지로 서명 검증
	log.Println("\n=== 변조된 메시지 서명 검증 ===")
	tamperedMessage := "this message is tampered!"
	err = signer.Verify([]byte(tamperedMessage), signature)
	if err != nil {
		log.Printf("sign failed: %v", err)
	} else {
		log.Println("sign success! but it's not the original message")
	}

}

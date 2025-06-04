package main

import (
	"go-cryptex/pkg/symmetric"
	"go-cryptex/pkg/utils"
	"log"
)

func main() {
	plaintext := "test"
	aesCipher, err := symmetric.NewAESCipherWithRandomKey()
	if err != nil {
		panic(err)
	}
	ciphertext, iv, err := aesCipher.Encrypt([]byte(plaintext))
	if err != nil {
		panic(err)
	}

	encodeCiphertext := utils.Base64Encode(ciphertext)
	encodeIv := utils.Base64Encode(iv)

	log.Println(encodeCiphertext)
	log.Println(encodeIv)

	decodeCiphertext, err := utils.Base64Decode(encodeCiphertext)
	decodeIv, err := utils.Base64Decode(encodeIv)

	decrypted, err := aesCipher.Decrypt(decodeCiphertext, decodeIv)
	if err != nil {
		panic(err)
	}
	log.Println(string(decrypted))
	if string(decrypted) == plaintext {
		log.Println("success")
	}
}

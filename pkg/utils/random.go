package utils

import "crypto/rand"

func GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func GenerateAESKey() ([]byte, error) {
	return GenerateRandomBytes(32)
}

func GenerateIV() ([]byte, error) {
	return GenerateRandomBytes(16)
}

package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

type EncryptedPayload struct {
	Nonce      []byte
	Ciphertext []byte
	AuthTag    []byte
}

func Encrypt(plaintext []byte, key [32]byte) (EncryptedPayload, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return EncryptedPayload{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedPayload{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedPayload{}, err
	}
	sealed := aead.Seal(nil, nonce, plaintext, nil)
	ciphertext := sealed[:len(sealed)-aead.Overhead()]
	authTag := sealed[len(sealed)-aead.Overhead():]

	return EncryptedPayload{
		Nonce:      nonce,
		Ciphertext: ciphertext,
		AuthTag:    authTag,
	}, nil
}

func Decrypt(payload EncryptedPayload, key [32]byte) ([]byte, error) {
	if len(payload.Nonce) != 12 {
		return nil, fmt.Errorf("invalid nonce length")
	}
	if len(payload.AuthTag) != 16 {
		return nil, fmt.Errorf("invalid auth tag length")
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, payload.Nonce, append(payload.Ciphertext, payload.AuthTag...), nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

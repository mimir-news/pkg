package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// Common encryption / decryption errors.
var (
	ErrToShortCiphertext = errors.New("ciphertext too short")
)

// Encryptor interface for encrypting a slice of bytes.
type Encryptor interface {
	Encrypt(key, plaintext []byte) ([]byte, error)
}

// Decryptor interface for decrypting a slice of bytes.
type Decryptor interface {
	Decrypt(key, ciphertext []byte) ([]byte, error)
}

// AESEncryptor implementation of Encryptor using
// the AES block cipher in GCM mode.
type AESEncryptor struct{}

// NewAESEncryptor creates a new AESEncryptor.
func NewAESEncryptor() *AESEncryptor {
	return &AESEncryptor{}
}

// Encrypt encrypts the provided plaintext with the given key.
func (e *AESEncryptor) Encrypt(key, plaintext []byte) ([]byte, error) {
	gcm, err := createGCMChipher(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// AESDecryptor implementation of Decryptor using
// the AES block cipher in GCM mode.
type AESDecryptor struct{}

// NewAESDecryptor creates a new AESDecryptor.
func NewAESDecryptor() *AESDecryptor {
	return &AESDecryptor{}
}

// Decrypt decrypts the provided ciphertexts with the given key.
func (e *AESDecryptor) Decrypt(key, ciphertext []byte) ([]byte, error) {
	gcm, err := createGCMChipher(key)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrToShortCiphertext
	}

	return gcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
}

func createGCMChipher(key []byte) (cipher.AEAD, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(c)
}

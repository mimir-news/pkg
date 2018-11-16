package auth_test

import (
	"testing"

	"github.com/mimir-news/pkg/httputil/auth"
	"github.com/stretchr/testify/assert"
)

func TestAESEncryptorAndDecryptor(t *testing.T) {
	assert := assert.New(t)

	data := "my secret data"
	key := auth.HashKey("my-key")

	var encryptor auth.Encryptor = auth.NewAESEncryptor()
	var decryptor auth.Decryptor = auth.NewAESDecryptor()

	ciphertext, err := encryptor.Encrypt(key, []byte(data))
	assert.Nil(err)
	assert.NotNil(ciphertext)
	assert.NotEqual(data, string(ciphertext))

	plaintext, err := decryptor.Decrypt(key, ciphertext)
	assert.Nil(err)
	assert.NotNil(plaintext)
	assert.Equal(data, string(plaintext))
}

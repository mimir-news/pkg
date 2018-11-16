package auth_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/mimir-news/pkg/httputil/auth"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestBryptHasher(t *testing.T) {
	assert := assert.New(t)

	expectedHashStr := "$2a$10$JHQueqewjWFUIjpnmYehMurX5ZxRVA1L6dIQR5fVJEtXXFyCe2SGW" // Bcrypt hash of "a-b-c"

	var hasher auth.Hasher = &auth.BcryptHasher{
		Cost: bcrypt.MinCost,
	}
	hash, err := hasher.Hash("a-b-c")
	assert.Nil(err)

	err = hasher.Verify("a-b-c", hash)
	assert.Nil(nil)

	err = hasher.Verify("a-b-c", expectedHashStr)
	assert.Nil(err)
}

func TestSha3Hasher(t *testing.T) {
	assert := assert.New(t)

	expectedHashStr := "345f7c214e36251e44ca46dbaf71018fa68eb7131554c393f795f62ec27aed25" // SHA-3 256 sum of "a-b-c"

	var hasher auth.Hasher = &auth.Sha3Hasher{
		Uppercase: false,
	}
	hash, err := hasher.Hash("a-b-c")
	assert.Nil(err)
	assert.Equal(expectedHashStr, hash)
	assert.Nil(hasher.Verify("a-b-c", expectedHashStr))

	hasher = &auth.Sha3Hasher{
		Uppercase: true,
	}
	upperCaseHash, err := hasher.Hash("a-b-c")
	assert.Nil(err)
	assert.Equal(strings.ToUpper(expectedHashStr), upperCaseHash)
	assert.Nil(hasher.Verify("a-b-c", strings.ToUpper(expectedHashStr)))
}

func TestHashKey(t *testing.T) {
	assert := assert.New(t)

	expectedHashStr := "345f7c214e36251e44ca46dbaf71018fa68eb7131554c393f795f62ec27aed25" // SHA-3 256 sum of "a-b-c"

	hash := auth.HashKey("a", "b", "c")
	assert.Len(hash, 32)
	assert.Equal(expectedHashStr, fmt.Sprintf("%x", hash))

	singleHash := auth.HashKey("a-b-c")
	assert.Len(singleHash, 32)
	assert.Equal(expectedHashStr, fmt.Sprintf("%x", singleHash))
}

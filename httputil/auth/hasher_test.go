package auth_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/mimir-news/pkg/httputil/auth"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestSaltedBryptHasher(t *testing.T) {
	assert := assert.New(t)

	testCases := []struct {
		key        string
		data       string
		sameAsLast bool
	}{
		{
			key:        "my-key-1",
			data:       "my-data",
			sameAsLast: false,
		},
		{
			key:        "my-key-1",
			data:       "my-data",
			sameAsLast: true,
		},
		{
			key:        "my-key-1",
			data:       "my-other-data",
			sameAsLast: false,
		},
	}

	bcryptHasher := &auth.BcryptHasher{
		Cost: bcrypt.DefaultCost,
	}

	var previousData string
	for i, tc := range testCases {
		testName := fmt.Sprintf("TestSaltedBryptHasher %d", i+1)
		var hasher auth.Hasher = auth.NewHasher(tc.key)

		hash, err := hasher.Hash(tc.data)
		assert.Nil(err, testName)

		errBryptMissmatch := bcryptHasher.Verify(tc.data, hash)
		assert.Equal(auth.ErrHashDoesNotMatch, errBryptMissmatch, testName)

		verifyErr := hasher.Verify(previousData, hash)
		if tc.sameAsLast {
			assert.Nil(verifyErr, testName)
		} else {
			assert.NotNil(verifyErr, testName)
		}

		previousData = tc.data
	}

	h1 := auth.NewHasher("key 1")
	h2 := auth.NewHasher("key 2")
	password := "super secret password"

	hash1, err := h1.Hash(password)
	assert.Nil(err)
	hash2, err := h2.Hash(password)
	assert.Nil(err)

	assert.NotEqual(hash1, hash2)

	err = h1.Verify(password, hash1)
	assert.Nil(err)
	err = h1.Verify(password, hash2)
	assert.NotNil(err)

	err = h2.Verify(password, hash2)
	assert.Nil(err)
	err = h2.Verify(password, hash1)
	assert.NotNil(err)
}

func TestBryptHasher(t *testing.T) {
	assert := assert.New(t)

	expectedHashStr := "$2a$10$JHQueqewjWFUIjpnmYehMurX5ZxRVA1L6dIQR5fVJEtXXFyCe2SGW" // Bcrypt hash of "a-b-c"

	var hasher auth.Hasher = &auth.BcryptHasher{
		Cost: bcrypt.MinCost,
	}
	hash, err := hasher.Hash("a-b-c")
	assert.Nil(err)

	err = hasher.Verify("a-b-c", hash)
	assert.Nil(err)

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

func TestGenerateSalt(t *testing.T) {
	assert := assert.New(t)

	previousSalt := ""

	for i := 0; i < 100; i++ {
		testCase := fmt.Sprintf("TestGenerateSalt: %d", i+1)
		salt, err := auth.GenerateSalt()
		assert.Nil(err)
		assert.NotEqual(previousSalt, salt, testCase)
		previousSalt = salt
	}
}

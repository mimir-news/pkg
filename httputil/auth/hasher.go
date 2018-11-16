package auth

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/sha3"
)

// Common errors related to hashing.
var (
	ErrHashDoesNotMatch = errors.New("The data does not match the given hash")
)

// HashKey hashes a key based on a variable number of components.
func HashKey(components ...string) []byte {
	keydata := []byte(strings.Join(components, "-"))
	hash := sha3.Sum256(keydata)
	return hash[:]
}

// Hasher interface for hashing string values and
// verifying if a string would hash to a specific hash.
type Hasher interface {
	Hash(data string) (string, error)
	Verify(data, hash string) error
}

// NewHasher returns a new SaltedBcryptHasher with a given key.
func NewHasher(key string) Hasher {
	hashedKey := HashKey(key)
	// scrambledKey := scrambleByKey(hashedKey, []byte(key))

	return &SaltedBcryptHasher{
		salt: hashedKey, //HashKey(scrambledKey),
		bcryptHasher: &BcryptHasher{
			Cost: bcrypt.DefaultCost,
		},
	}
}

// SaltedBcryptHasher implementation of Hasher that computes hashes
// using bcrypt with a global secret salt that is determnistlicy
// scrambled based on the data that should be hashed.
type SaltedBcryptHasher struct {
	salt         []byte
	bcryptHasher *BcryptHasher
}

// Hash salts the supplied data and hashes it.
func (h *SaltedBcryptHasher) Hash(data string) (string, error) {
	saltedData := h.saltData(data)
	return h.bcryptHasher.Hash(saltedData)
}

// Verify verifies that the salted data matches the supplied hash.
func (h *SaltedBcryptHasher) Verify(data, hash string) error {
	saltedData := h.saltData(data)
	return h.bcryptHasher.Verify(saltedData, hash)
}

func (h *SaltedBcryptHasher) saltData(data string) string {
	return scrambleByKey(h.salt, []byte(data))
}

// BcryptHasher implementation of Hasher that computes hashes using bcrypt.
type BcryptHasher struct {
	Cost int
}

// Hash computes a brypt hash of a given string, the error returned will always be nil.
func (h *BcryptHasher) Hash(data string) (string, error) {
	dataBytes := []byte(data)

	hash, err := bcrypt.GenerateFromPassword(dataBytes, h.Cost)
	if err != nil {
		return "", err
	}
	return string(hash), err
}

// Verify compares a string agaist a given hash and throws an error if they do not match.
func (h *BcryptHasher) Verify(data, hash string) error {
	dataBytes := []byte(data)
	hashBytes := []byte(hash)

	err := bcrypt.CompareHashAndPassword(hashBytes, dataBytes)
	if err != nil {
		return ErrHashDoesNotMatch
	}
	return nil
}

// Sha3Hasher implementation of Hasher that computes hashes using sha256.
type Sha3Hasher struct {
	Uppercase bool
}

// Hash computes the sha3 256 sum of a given string, the error returned will always be nil.
func (h *Sha3Hasher) Hash(data string) (string, error) {
	bytesHash := sha3.Sum256([]byte(data))
	if h.Uppercase {
		return fmt.Sprintf("%X", bytesHash), nil
	}
	return fmt.Sprintf("%x", bytesHash), nil
}

// Verify compares a string agaist a given hash and throws an error if they do not match.
func (h *Sha3Hasher) Verify(data, hash string) error {
	dataHash, _ := h.Hash(data)
	if dataHash != hash {
		return ErrHashDoesNotMatch
	}
	return nil
}

func scrambleByKey(key, data []byte) string {
	long, short := orderByLength(key, data)
	shortLen := len(short)
	if shortLen == 0 {
		return ""
	}

	scrambled := make([]byte, 0, len(long))
	for i, longByte := range long {
		shortIndex := i % shortLen
		shortByte := short[shortIndex]

		scrambledByte := addBytesWithMultiplier(i, longByte, shortByte)
		scrambled = append(scrambled, scrambledByte)
	}
	return string(scrambled)
}

func addBytesWithMultiplier(c int, x, y byte) byte {
	byteNumber := ((c+1)*int(x) + int(y)) % 255
	return byte(byteNumber)
}

func orderByLength(first, second []byte) ([]byte, []byte) {
	if len(first) >= len(second) {
		return first, second
	}
	return second, first
}

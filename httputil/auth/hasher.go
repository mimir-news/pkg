package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/sha3"
)

// DefualtBcryptCost default cost factor for bcrypt hashing.
const DefualtBcryptCost = 12

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

// GenerateSalt creates random salt and returns it as a base64 encoded stirng.
func GenerateSalt() (string, error) {
	nonce := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(nonce), nil
}

// Hasher interface for hashing string values and
// verifying if a string would hash to a specific hash.
type Hasher interface {
	Hash(data string) (string, error)
	Verify(data, hash string) error
}

// NewHasher returns a new PepperBcryptHasher with a given key.
func NewHasher(key string) Hasher {
	sha3Hasher := &Sha3Hasher{Uppercase: false}
	hashedKey, _ := sha3Hasher.Hash(key)

	return &PepperBcryptHasher{
		pepper: hashedKey,
		bcryptHasher: &BcryptHasher{
			Cost: DefualtBcryptCost,
		},
		sha3Hasher: sha3Hasher,
	}
}

// PepperBcryptHasher implementation of Hasher that computes hashes
// using bcrypt with a global secret pepper.
type PepperBcryptHasher struct {
	pepper       string
	bcryptHasher *BcryptHasher
	sha3Hasher   *Sha3Hasher
}

// Hash salts the supplied data and hashes it.
func (h *PepperBcryptHasher) Hash(data string) (string, error) {
	pepperedData := h.pepperData(data)
	return h.bcryptHasher.Hash(pepperedData)
}

// Verify verifies that the salted data matches the supplied hash.
func (h *PepperBcryptHasher) Verify(data, hash string) error {
	pepperedData := h.pepperData(data)
	return h.bcryptHasher.Verify(pepperedData, hash)
}

func (h *PepperBcryptHasher) pepperData(data string) string {
	pepperedData := fmt.Sprintf("%s-%s", h.pepper, data)
	pepperedHash, _ := h.sha3Hasher.Hash(pepperedData)
	return pepperedHash
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

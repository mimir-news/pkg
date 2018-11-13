package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/mimir-news/pkg/id"
)

// Common errors in token creation and verification.
var (
	ErrMissingSubject  = errors.New("Missing subject")
	ErrMissingClientID = errors.New("Missing clientID")
	ErrInvalidToken    = errors.New("Token is invalid")
	ErrExpiredToken    = errors.New("Token has expired")
)

var (
	emptyToken          = Token{}
	emptyTokenBody      = TokenBody{}
	emptyEncryptedToken = EcryptedToken{}
)

// Supported version of the auth token protocol.
const (
	V1 Version = "v1"
)

// Token contains subject and metadata required
// to securly authenticate a subject.
type Token struct {
	ID      string    `json:"id"`
	Version Version   `json:"version"`
	Body    TokenBody `json:"body"`
}

// Version denotes supported version of the protocol.
type Version string

// EcryptedToken a token with its body encrypted.
type EcryptedToken struct {
	ID      string  `json:"id"`
	Version Version `json:"version"`
	Body    string  `json:"body"`
}

// token turns an EcryptedToken into a Token by adding a decrypted body.
func (e EcryptedToken) token(body TokenBody) Token {
	return Token{
		ID:      e.ID,
		Version: e.Version,
		Body:    body,
	}
}

// TokenBody contains subject and other authenication metadata.
type TokenBody struct {
	Subject          string `json:"subject"`
	ExpiresAt        int64  `json:"expiresAt"`
	TokenID          string `json:"tokenId"`
	ClientID         string `json:"clientId"`
	VerificationHash string `json:"verificationHash"`
}

// Signer interface for issuing and signing auth tokens.
type Signer interface {
	Issue(subject, clientID string) (Token, error)
	Sign(token Token) (string, error)
}

// NewSigner creates a new signer.
func NewSigner(secret, verificationKey string, tokenAge time.Duration) Signer {
	return &aesSigner{
		secretHash:       hash(secret),
		verificationHash: hash(verificationKey),
		tokenAge:         tokenAge,
	}
}

// Verifier interface for verifying auth tokens.
type Verifier interface {
	Verify(clientID, rawToken string) (Token, error)
}

// NewVerifier creates a new verifier.
func NewVerifier(secret, verificationKey string, tokenAge time.Duration) Verifier {
	return &aesVerifier{
		secretHash:       hash(secret),
		verificationHash: hash(verificationKey),
		tokenAge:         tokenAge,
	}
}

type aesVerifier struct {
	secretHash       string
	verificationHash string
	tokenAge         time.Duration
}

func (v *aesVerifier) Verify(clientID, rawToken string) (Token, error) {
	encryptedToken, err := decodeEncryptedToken(rawToken)
	if err != nil {
		return emptyToken, err
	}

	key := createAESKey(v.secretHash, encryptedToken.ID, encryptedToken.Version)
	tokenBody, err := aesDecrypt(encryptedToken.Body, key)
	if err != nil {
		return emptyToken, ErrInvalidToken
	}

	token := encryptedToken.token(tokenBody)
	err = v.checkTokenValidity(token, clientID)
	if err != nil {
		return emptyToken, err
	}

	token.Body.VerificationHash = ""
	return token, nil
}

func (v *aesVerifier) checkTokenValidity(token Token, clientID string) error {
	if token.Body.ClientID != clientID {
		return ErrInvalidToken
	}

	if token.Body.VerificationHash != v.verificationHash {
		return ErrInvalidToken
	}

	expiryTime := time.Unix(0, token.Body.ExpiresAt).UTC()
	if now().After(expiryTime) {
		return ErrExpiredToken
	}

	return nil
}

type aesSigner struct {
	secretHash       string
	verificationHash string
	tokenAge         time.Duration
}

func (s *aesSigner) Issue(subject, clientID string) (Token, error) {
	if subject == "" {
		return emptyToken, ErrMissingSubject
	}

	if clientID == "" {
		return emptyToken, ErrMissingClientID
	}

	return s.newToken(subject, clientID), nil
}

func (s *aesSigner) newToken(subject, clientID string) Token {
	tokenID := id.New()
	return Token{
		ID:      tokenID,
		Version: V1,
		Body: TokenBody{
			Subject:          subject,
			ExpiresAt:        now().Add(s.tokenAge).UnixNano(),
			TokenID:          tokenID,
			ClientID:         clientID,
			VerificationHash: s.verificationHash,
		},
	}
}

func (s *aesSigner) Sign(token Token) (string, error) {
	if token.Body.VerificationHash != s.verificationHash {
		fmt.Println(s.verificationHash)
		return "", ErrInvalidToken
	}

	ecryptedToken, err := s.encrypt(token)
	if err != nil {
		return "", err
	}

	tokenBytes, err := json.Marshal(ecryptedToken)
	if err != nil {
		log.Println(err)
		return "", ErrInvalidToken
	}

	return base64.StdEncoding.EncodeToString(tokenBytes), nil
}

func (s *aesSigner) encrypt(token Token) (EcryptedToken, error) {
	key := createAESKey(s.secretHash, token.ID, token.Version)

	encryptedBody, err := aesEncrypt(token.Body, key)
	if err != nil {
		return emptyEncryptedToken, err
	}

	encryptedToken := EcryptedToken{
		ID:      token.ID,
		Version: token.Version,
		Body:    encryptedBody,
	}
	return encryptedToken, nil
}

func hash(value string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(value)))
}

func createAESKey(secret, salt string, version Version) []byte {
	saltedKey := fmt.Sprintf("%s-%s-%s", secret, salt, version)
	return []byte(hash(saltedKey))[:32]
}

func aesEncrypt(body TokenBody, key []byte) (string, error) {
	plaintext, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	gcm, err := createGCMChipher(key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func aesDecrypt(encryptedBody string, key []byte) (TokenBody, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedBody)
	if err != nil {
		return emptyTokenBody, err
	}

	gcm, err := createGCMChipher(key)
	if err != nil {
		return emptyTokenBody, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return emptyTokenBody, errors.New("ciphertext too short")
	}

	plaintext, err := gcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
	if err != nil {
		return emptyTokenBody, err
	}

	var tokenBody TokenBody
	err = json.Unmarshal(plaintext, &tokenBody)
	return tokenBody, err
}

func createGCMChipher(key []byte) (cipher.AEAD, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(c)
}

func decodeEncryptedToken(rawToken string) (EcryptedToken, error) {
	tokenBytes, err := base64.StdEncoding.DecodeString(rawToken)
	if err != nil {
		log.Println(err)
		return emptyEncryptedToken, ErrInvalidToken
	}

	var ecryptedToken EcryptedToken
	err = json.Unmarshal(tokenBytes, &ecryptedToken)
	return ecryptedToken, err
}

func now() time.Time {
	return time.Now().UTC()
}

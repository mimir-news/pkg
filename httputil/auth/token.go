package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
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

// Verifier interface for verifying auth tokens.
type Verifier interface {
	Verify(clientID, rawToken string) (Token, error)
}

// NewVerifier creates a new verifier.
func NewVerifier(secret, verificationKey string) Verifier {
	hasher := Sha256Hasher{Uppercase: false}
	hashedSecret, _ := hasher.Hash(secret)
	hashedKey, _ := hasher.Hash(verificationKey)

	return &aesVerifier{
		decryptor:        NewAESDecryptor(),
		secretHash:       hashedSecret,
		verificationHash: hashedKey,
	}
}

type aesVerifier struct {
	decryptor        *AESDecryptor
	secretHash       string
	verificationHash string
}

func (v *aesVerifier) Verify(clientID, rawToken string) (Token, error) {
	encryptedToken, err := decodeEncryptedToken(rawToken)
	if err != nil {
		return emptyToken, err
	}

	key := createAESKey(v.secretHash, encryptedToken.ID, encryptedToken.Version)
	tokenBody, err := v.aesDecrypt(encryptedToken.Body, key)
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

func (v *aesVerifier) aesDecrypt(encryptedBody string, key []byte) (TokenBody, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedBody)
	if err != nil {
		return emptyTokenBody, err
	}

	plaintext, err := v.decryptor.Decrypt(key, ciphertext)
	if err != nil {
		return emptyTokenBody, err
	}

	var tokenBody TokenBody
	err = json.Unmarshal(plaintext, &tokenBody)
	return tokenBody, err
}

// Signer interface for issuing and signing auth tokens.
type Signer interface {
	New(subject, clientID string) (string, error)
}

// NewSigner creates a new signer.
func NewSigner(secret, verificationKey string, tokenAge time.Duration) Signer {
	hasher := Sha256Hasher{Uppercase: false}
	hashedSecret, _ := hasher.Hash(secret)
	hashedKey, _ := hasher.Hash(verificationKey)

	return &aesSigner{
		encryptor:        NewAESEncryptor(),
		secretHash:       hashedSecret,
		verificationHash: hashedKey,
		tokenAge:         tokenAge,
	}
}

type aesSigner struct {
	encryptor        *AESEncryptor
	secretHash       string
	verificationHash string
	tokenAge         time.Duration
}

func (s *aesSigner) New(subject, clientID string) (string, error) {
	if subject == "" {
		return "", ErrMissingSubject
	}

	if clientID == "" {
		return "", ErrMissingClientID
	}

	token := s.newToken(subject, clientID)
	return s.sign(token)
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

func (s *aesSigner) sign(token Token) (string, error) {
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

	encryptedBody, err := s.aesEncrypt(token.Body, key)
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

func (s *aesSigner) aesEncrypt(body TokenBody, key []byte) (string, error) {
	plaintext, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	ciphertext, err := s.encryptor.Encrypt(key, plaintext)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func createAESKey(secret, salt string, version Version) []byte {
	return HashKey(secret, salt, string(version))
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

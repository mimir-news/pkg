package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// Common errors in token creation and verification.
var (
	ErrMissingTokenID   = errors.New("Missing token ID")
	ErrMissingSubject   = errors.New("Missing subject")
	ErrInvalidToken     = errors.New("Token is invalid")
	ErrExpiredToken     = errors.New("Token has expired")
	ErrNotYetValidToken = errors.New("Token is not yet valid")
)

var (
	emptyToken       = Token{}
	emptyCredentials = JWTCredentials{}
)

// User roles.
const (
	UserRole      = "USER"
	AdminRole     = "ADMIN"
	AnonymousRole = "ANONYMOUS"
)

// User authentication infromation.
type User struct {
	ID   string `json:"id"`
	Role string `json:"role"`
}

// Token contains ID and role of a user.
type Token struct {
	ID   string `json:"id"`
	User User   `json:"user"`
}

// JWTCredentials credentials to issue and verify JWT tokens.
type JWTCredentials struct {
	Issuer string `json:"issuer"`
	Secret string `json:"secret"`
}

// ReadJWTCredentials reads JWTCredentials from an io.Reader.
func ReadJWTCredentials(r io.Reader) (JWTCredentials, error) {
	var credentials JWTCredentials
	err := json.NewDecoder(r).Decode(&credentials)
	return credentials, err
}

// Verifier interface for verifying string token.
type Verifier interface {
	Verify(rawToken string) (Token, error)
}

// jwtVerifier implementation of the verifier interface for dealing with JWT tokens.
type jwtVerifier struct {
	secret         []byte
	expectedIssuer string
	leeway         time.Duration
}

// NewVerifier creates a new Verifier using the default implementation.
func NewVerifier(creds JWTCredentials, leeway time.Duration) Verifier {
	return &jwtVerifier{
		secret:         []byte(creds.Secret),
		expectedIssuer: creds.Issuer,
		leeway:         leeway,
	}
}

// Verify verifies a encoded JWT token.
func (v *jwtVerifier) Verify(rawToken string) (Token, error) {
	token, err := jwt.ParseSigned(rawToken) // test sending invalid tokens
	if err != nil {
		return emptyToken, ErrInvalidToken
	}

	var claims jwt.Claims
	err = token.Claims(v.secret, &claims)
	if err != nil {
		fmt.Println(err)
		return emptyToken, ErrInvalidToken
	}

	var customClaims customJwtClaims
	err = token.Claims(v.secret, &customClaims)
	if err != nil {
		return emptyToken, ErrInvalidToken
	}

	err = v.validateClaims(claims)
	if err != nil {
		return emptyToken, err
	}

	return getTokenFromClaims(claims, customClaims), nil
}

func (v *jwtVerifier) validateClaims(claims jwt.Claims) error {
	err := claims.ValidateWithLeeway(jwt.Expected{Issuer: v.expectedIssuer}, v.leeway)
	if err != nil {
		return ErrInvalidToken
	}

	err = v.checkTokenExpiry(claims)
	if err != nil {
		return err
	}

	if claims.Subject == "" {
		return ErrMissingSubject
	}

	if claims.ID == "" {
		return ErrMissingTokenID
	}

	return nil
}

func (v *jwtVerifier) checkTokenExpiry(claims jwt.Claims) error {
	earliestDate := claims.NotBefore.Time().UTC()
	latestDate := claims.Expiry.Time().Add(v.leeway).UTC()
	now := time.Now().UTC()

	if now.Before(earliestDate) {
		return ErrNotYetValidToken
	}

	if now.After(latestDate) {
		return ErrExpiredToken
	}

	return nil
}

func getTokenFromClaims(claims jwt.Claims, customClaims customJwtClaims) Token {
	return Token{
		ID: claims.ID,
		User: User{
			ID:   claims.Subject,
			Role: customClaims.Role,
		},
	}
}

type customJwtClaims struct {
	Role string `json:"role"`
}

// Signer interface for issuing and signing auth tokens.
type Signer interface {
	Sign(tokenID string, user User) (string, error)
}

// NewSigner creates a new signer using the default implementation.
func NewSigner(creds JWTCredentials, tokenAge time.Duration) Signer {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte(creds.Secret)}, nil)
	if err != nil {
		log.Fatal("Failed to create jose.Signer. ", err)
	}

	return &jwtSigner{
		issuer:   creds.Issuer,
		signer:   signer,
		tokenAge: tokenAge,
	}
}

// jwtSigner signer implemntation for issueing JWT tokens.
type jwtSigner struct {
	issuer   string
	signer   jose.Signer
	tokenAge time.Duration
}

// Sign creates a new signed JWT token.
func (s *jwtSigner) Sign(tokenID string, user User) (string, error) {
	err := s.verifyTokenContent(tokenID, user)
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	claims := jwt.Claims{
		Subject:   user.ID,
		ID:        tokenID,
		Issuer:    s.issuer,
		NotBefore: jwt.NewNumericDate(now.Add(-1 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(s.tokenAge)),
	}
	customClaims := customJwtClaims{Role: user.Role}
	return jwt.Signed(s.signer).Claims(claims).Claims(customClaims).CompactSerialize()
}

func (s *jwtSigner) verifyTokenContent(tokenID string, user User) error {
	if tokenID == "" {
		return ErrMissingTokenID
	}
	if user.ID == "" {
		return ErrMissingSubject
	}

	return nil
}

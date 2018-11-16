package auth_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/mimir-news/pkg/httputil/auth"
)

func TestSignAndVerify(t *testing.T) {
	subject := "test-subject"
	clientID := "test-client"
	secret := "test-secret"
	verificationKey := "test-key"
	tokenAge := 10 * time.Minute

	signer := auth.NewSigner(secret, verificationKey, tokenAge)

	encrypted, err := signer.New(subject, clientID)
	if err != nil {
		t.Fatal("Failed to sign token:", err)
	}

	verifier := auth.NewVerifier(secret, verificationKey)

	decryptedToken, err := verifier.Verify("test-client", encrypted)
	if err != nil {
		t.Fatal("Failed to verify token:", err)
	}

	assertV1Token(t, subject, clientID, decryptedToken)
}

func assertV1Token(t *testing.T, subject, client string, token auth.Token) {
	assert.Equal(t, auth.V1, token.Version)
	assert.Equal(t, subject, token.Body.Subject)
	assert.Equal(t, client, token.Body.ClientID)
}

func TestSignAndVerify_wrongClientID(t *testing.T) {
	subject := "test-subject"
	clientID := "test-client"
	secret := "test-secret"
	verificationKey := "test-key"
	tokenAge := 10 * time.Minute

	signer := auth.NewSigner(secret, verificationKey, tokenAge)

	encrypted, err := signer.New(subject, clientID)
	assert.Nil(t, err)

	verifier := auth.NewVerifier(secret, verificationKey)

	_, err = verifier.Verify("wrong-client", encrypted)
	assert.Equal(t, auth.ErrInvalidToken, err)
}

func TestSignAndVerify_expiredToken(t *testing.T) {
	subject := "test-subject"
	clientID := "test-client"
	secret := "test-secret"
	verificationKey := "test-key"
	tokenAge := -5 * time.Minute

	signer := auth.NewSigner(secret, verificationKey, tokenAge)
	encrypted, err := signer.New(subject, clientID)
	assert.Nil(t, err)

	verifier := auth.NewVerifier(secret, verificationKey)

	_, err = verifier.Verify("test-client", encrypted)
	if err != auth.ErrExpiredToken {
		t.Fatal("Token should be teated as expired", err)
	}
}

func TestSignAndVerify_wrongVerifier(t *testing.T) {
	subject := "test-subject"
	clientID := "test-client"
	secret := "test-secret"
	verificationKey := "test-key"
	tokenAge := 10 * time.Minute

	signer := auth.NewSigner(secret, verificationKey, tokenAge)
	encrypted, err := signer.New(subject, clientID)
	assert.Nil(t, err)

	verifier := auth.NewVerifier("other-secret", verificationKey)
	_, err = verifier.Verify(clientID, encrypted)
	assert.NotNil(t, err)

	verifier = auth.NewVerifier(secret, "other-key")
	_, err = verifier.Verify(clientID, encrypted)
	assert.NotNil(t, err)

	verifier = auth.NewVerifier("other-secret", "other-key")
	_, err = verifier.Verify(clientID, encrypted)
	assert.NotNil(t, err)
}

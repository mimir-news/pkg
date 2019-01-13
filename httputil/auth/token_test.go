package auth_test

import (
	"testing"
	"time"

	"github.com/mimir-news/pkg/httputil/auth"
	"github.com/mimir-news/pkg/id"
	"github.com/stretchr/testify/assert"
)

func TestSignAndVerifyJWT(t *testing.T) {
	secret := id.New()
	issuer := id.New()
	tokenAge := 10 * time.Minute
	signer := auth.NewSigner(issuer, secret, tokenAge)

	tokenID := id.New()
	user := auth.User{
		ID:   id.New(),
		Role: auth.UserRole,
	}
	tokenString, err := signer.Sign(tokenID, user)
	assert.NoError(t, err)
	assert.NotEqual(t, "", tokenString)

	verifier := auth.NewVerifier(issuer, secret, 0)
	token, err := verifier.Verify(tokenString)
	assert.NoError(t, err)
	assert.Equal(t, tokenID, token.ID)
	assert.Equal(t, user.ID, token.User.ID)
	assert.Equal(t, user.Role, token.User.Role)

	_, err = verifier.Verify("this.clearlyIsNot.aValidToken")
	assert.Equal(t, auth.ErrInvalidToken, err)

	verifier = auth.NewVerifier(issuer, "wrong-secret", 0)
	_, err = verifier.Verify(tokenString)
	assert.Equal(t, auth.ErrInvalidToken, err)

	verifier = auth.NewVerifier("wrong-issuer", secret, 0)
	_, err = verifier.Verify(tokenString)
	assert.Equal(t, auth.ErrInvalidToken, err)

	verifier = auth.NewVerifier("wrong-issuer", "wrong-secret", 0)
	_, err = verifier.Verify(tokenString)
	assert.Equal(t, auth.ErrInvalidToken, err)
}

func TestSignAndVerify_expiredJWT(t *testing.T) {
	secret := id.New()
	issuer := id.New()
	tokenAge := 2 * time.Second
	signer := auth.NewSigner(issuer, secret, tokenAge)

	tokenID := id.New()
	user := auth.User{
		ID:   id.New(),
		Role: auth.UserRole,
	}
	tokenString, err := signer.Sign(tokenID, user)
	assert.NoError(t, err)
	assert.NotEqual(t, "", tokenString)

	verifier := auth.NewVerifier(issuer, secret, 0)
	token, err := verifier.Verify(tokenString)
	assert.NoError(t, err)
	assert.Equal(t, tokenID, token.ID)
	assert.Equal(t, user.ID, token.User.ID)
	assert.Equal(t, user.Role, token.User.Role)

	time.Sleep(3 * time.Second)
	_, err = verifier.Verify(tokenString)
	assert.Error(t, err)
}

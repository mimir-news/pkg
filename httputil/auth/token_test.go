package auth_test

import (
	"bytes"
	"fmt"
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
	signer := auth.NewSigner(auth.JWTCredentials{Issuer: issuer, Secret: secret}, tokenAge)

	tokenID := id.New()
	user := auth.User{
		ID:   id.New(),
		Role: auth.UserRole,
	}
	tokenString, err := signer.Sign(tokenID, user)
	assert.NoError(t, err)
	assert.NotEqual(t, "", tokenString)

	verifier := auth.NewVerifier(auth.JWTCredentials{Issuer: issuer, Secret: secret}, 0)
	token, err := verifier.Verify(tokenString)
	assert.NoError(t, err)
	assert.Equal(t, tokenID, token.ID)
	assert.Equal(t, user.ID, token.User.ID)
	assert.Equal(t, user.Role, token.User.Role)

	_, err = verifier.Verify("this.clearlyIsNot.aValidToken")
	assert.Equal(t, auth.ErrInvalidToken, err)

	verifier = auth.NewVerifier(auth.JWTCredentials{Issuer: issuer, Secret: "wrong-secret"}, 0)
	_, err = verifier.Verify(tokenString)
	assert.Equal(t, auth.ErrInvalidToken, err)

	verifier = auth.NewVerifier(auth.JWTCredentials{Issuer: "wrong-issuer", Secret: secret}, 0)
	_, err = verifier.Verify(tokenString)
	assert.Equal(t, auth.ErrInvalidToken, err)

	verifier = auth.NewVerifier(auth.JWTCredentials{Issuer: "wrong-issuer", Secret: "wrong-secret"}, 0)
	_, err = verifier.Verify(tokenString)
	assert.Equal(t, auth.ErrInvalidToken, err)

	_, err = signer.Sign(tokenID, auth.User{Role: auth.UserRole})
	assert.Equal(t, auth.ErrMissingSubject, err)

	_, err = signer.Sign("", user)
	assert.Equal(t, auth.ErrMissingTokenID, err)
}

func TestSignAndVerify_expiredJWT(t *testing.T) {
	secret := id.New()
	issuer := id.New()
	tokenAge := 2 * time.Second
	signer := auth.NewSigner(auth.JWTCredentials{Issuer: issuer, Secret: secret}, tokenAge)

	tokenID := id.New()
	user := auth.User{
		ID:   id.New(),
		Role: auth.UserRole,
	}
	tokenString, err := signer.Sign(tokenID, user)
	assert.NoError(t, err)
	assert.NotEqual(t, "", tokenString)

	verifier := auth.NewVerifier(auth.JWTCredentials{Issuer: issuer, Secret: secret}, 0)
	token, err := verifier.Verify(tokenString)
	assert.NoError(t, err)
	assert.Equal(t, tokenID, token.ID)
	assert.Equal(t, user.ID, token.User.ID)
	assert.Equal(t, user.Role, token.User.Role)

	time.Sleep(3 * time.Second)
	_, err = verifier.Verify(tokenString)
	assert.Error(t, err)
}

func TestReadJWTCredentials(t *testing.T) {
	issuer := "test-issuer"
	secret, err := auth.GenerateSalt()
	assert.NoError(t, err)
	credentialString := fmt.Sprintf("{\"issuer\":\"%s\",\"secret\":\"%s\"}", issuer, secret)
	buffer := bytes.NewReader([]byte(credentialString))

	creds, err := auth.ReadJWTCredentials(buffer)
	assert.NoError(t, err)
	assert.Equal(t, issuer, creds.Issuer)
	assert.Equal(t, secret, creds.Secret)
}

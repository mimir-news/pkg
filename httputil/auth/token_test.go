package auth_test

import (
	"testing"
	"time"

	"github.com/mimir-news/pkg/httputil/auth"
)

func TestSignAndVerify(t *testing.T) {
	secret := "test-secret"
	verificationKey := "test-key"
	maxAge := 10 * time.Minute

	// Sha256 hash of "test-key"
	verificationHash := "62af8704764faf8ea82fc61ce9c4c3908b6cb97d463a634e9e587d7c885db0ef"
	token := auth.Token{
		ID:      "a2b7c635-981e-4a3d-a4c9-e4d871a767cb",
		Version: auth.V1,
		Body: auth.TokenBody{
			Subject:          "test-subject",
			ExpiresAt:        4695667686255857000, // 100 years from 2018-11-13.
			TokenID:          "a2b7c635-981e-4a3d-a4c9-e4d871a767cb",
			ClientID:         "test-client",
			VerificationHash: verificationHash,
		},
	}

	signer := auth.NewSigner(secret, verificationKey, maxAge)

	encrypted, err := signer.Sign(token)
	if err != nil {
		t.Fatal("Failed to sign token:", err)
	}

	verifier := auth.NewVerifier(secret, verificationKey, maxAge)

	decryptedToken, err := verifier.Verify("test-client", encrypted)
	if err != nil {
		t.Fatal("Failed to verify token:", err)
	}

	if decryptedToken.ID != token.ID {
		t.Fatalf("Wrong token ID. Expected=%s Got=%s", token.ID, decryptedToken.ID)
	}
}

func TestSignAndVerify_wrongClientID(t *testing.T) {
	secret := "test-secret"
	verificationKey := "test-key"
	maxAge := 10 * time.Minute

	// Sha256 hash of "test-key"
	verificationHash := "62af8704764faf8ea82fc61ce9c4c3908b6cb97d463a634e9e587d7c885db0ef"
	token := auth.Token{
		ID:      "a2b7c635-981e-4a3d-a4c9-e4d871a767cb",
		Version: auth.V1,
		Body: auth.TokenBody{
			Subject:          "test-subject",
			ExpiresAt:        4695667686255857000, // 100 years from 2018-11-13.
			TokenID:          "a2b7c635-981e-4a3d-a4c9-e4d871a767cb",
			ClientID:         "test-client",
			VerificationHash: verificationHash,
		},
	}

	signer := auth.NewSigner(secret, verificationKey, maxAge)

	encrypted, err := signer.Sign(token)
	if err != nil {
		t.Fatal("Failed to sign token:", err)
	}

	verifier := auth.NewVerifier(secret, verificationKey, maxAge)

	_, err = verifier.Verify("wrong-client", encrypted)
	if err != auth.ErrInvalidToken {
		t.Fatal("Should be invalid token, got nil")
	}
}

func TestSignAndVerify_expiredToken(t *testing.T) {
	secret := "test-secret"
	verificationKey := "test-key"
	maxAge := 5 * time.Millisecond

	signer := auth.NewSigner(secret, verificationKey, maxAge)
	token, err := signer.Issue("test-subject", "test-client")
	if err != nil {
		t.Fatal("Failed create token:", err)
	}

	encrypted, err := signer.Sign(token)
	if err != nil {
		t.Fatal("Failed to sign token:", err)
	}

	verifier := auth.NewVerifier(secret, verificationKey, maxAge)

	time.Sleep(20 * time.Millisecond)
	_, err = verifier.Verify("test-client", encrypted)
	if err != auth.ErrExpiredToken {
		t.Fatal("Token should be teated as expired", err)
	}
}

func TestSignAndVerify_wrongVerifier(t *testing.T) {
	secret := "test-secret"
	verificationKey := "test-key"
	maxAge := 10 * time.Minute

	signer := auth.NewSigner(secret, verificationKey, maxAge)
	token, err := signer.Issue("test-subject", "test-client")
	if err != nil {
		t.Fatal("Failed create token:", err)
	}

	encrypted, err := signer.Sign(token)
	if err != nil {
		t.Fatal("Failed to sign token:", err)
	}

	verifier := auth.NewVerifier("other-secret", verificationKey, maxAge)
	_, err = verifier.Verify("test-client", encrypted)
	if err != auth.ErrInvalidToken {
		t.Error("Should be invalid token, got nil")
	}

	verifier = auth.NewVerifier(secret, "other-key", maxAge)
	_, err = verifier.Verify("test-client", encrypted)
	if err != auth.ErrInvalidToken {
		t.Error("Should be invalid token, got nil")
	}

	verifier = auth.NewVerifier("other-secret", "other-key", maxAge)
	_, err = verifier.Verify("test-client", encrypted)
	if err != auth.ErrInvalidToken {
		t.Error("Should be invalid token, got nil")
	}
}

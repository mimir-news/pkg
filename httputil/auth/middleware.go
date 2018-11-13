package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/mimir-news/pkg/httputil"
)

// Header keys
const (
	AuthHeaderKey   = "Authorization"
	AuthTokenPrefix = "Bearer "
	ClientIDKey     = "X-Client-ID"
	UserIDKey       = "X-User-ID"
)

// RequireToken adds token verification ahead of serving requests.
func RequireToken(secret, verificationKey string) gin.HandlerFunc {
	verifier := NewVerifier(secret, verificationKey)
	return func(c *gin.Context) {
		encodedToken, err := getAuthToken(c)
		if err != nil {
			httputil.SendError(err, c)
			return
		}

		clientID := c.GetHeader(ClientIDKey)
		if clientID == "" {
			httputil.SendError(httputil.ErrUnauthorized(), c)
			return
		}

		token, verificationErr := verifier.Verify(clientID, encodedToken)
		if verificationErr != nil {
			err = httputil.NewError(verificationErr.Error(), http.StatusUnauthorized)
			httputil.SendError(err, c)
			return
		}

		SetContextUserID(c, token.Body.Subject)
		c.Next()
	}
}

func getAuthToken(c *gin.Context) (string, *httputil.Error) {
	authHeader := c.GetHeader(AuthHeaderKey)
	if authHeader == "" {
		return "", httputil.ErrUnauthorized()
	}

	if !strings.HasPrefix(authHeader, AuthTokenPrefix) {
		return "", httputil.ErrUnauthorized()
	}

	return strings.Replace(authHeader, AuthTokenPrefix, "", 1), nil
}

// SetContextUserID sets the userID of the client that initated the request.
func SetContextUserID(c *gin.Context, userID string) {
	if userID != "" {
		c.Set(UserIDKey, userID)
	}
}

// GetUserID gets the user id set by the auth middleware.
func GetUserID(c *gin.Context) (string, error) {
	userID := c.GetString(UserIDKey)
	if userID == "" {
		return "", httputil.NewError("UserID missing", http.StatusInternalServerError)
	}
	return userID, nil
}

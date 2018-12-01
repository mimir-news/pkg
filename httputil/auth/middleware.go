package auth

import (
	"fmt"
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

// Options options for configuring authentication middleware.
type Options struct {
	Secret          string
	VerificationKey string
	ExemptedRoutes  []string
}

// NewOptions sets up new auth options with optional exmpted routes.
func NewOptions(secret, verificationKey string, exemptedRoutes ...string) *Options {
	return &Options{
		Secret:          secret,
		VerificationKey: verificationKey,
		ExemptedRoutes:  exemptedRoutes,
	}
}

func (opts *Options) exemptedRoutesSet() map[string]bool {
	routesSet := make(map[string]bool)
	for _, route := range opts.ExemptedRoutes {
		routesSet[route] = true
	}
	return routesSet
}

// RequireToken adds token verification ahead of serving requests.
func RequireToken(opts *Options) gin.HandlerFunc {
	verifier := NewVerifier(opts.Secret, opts.VerificationKey)
	exemptedRoutes := opts.exemptedRoutesSet()

	return func(c *gin.Context) {
		if _, ok := exemptedRoutes[c.Request.URL.Path]; ok {
			c.Next()
			return
		}

		encodedToken, err := getAuthToken(c)
		if err != nil {
			httputil.SendError(err, c)
			return
		}

		clientID := c.GetHeader(ClientIDKey)
		fmt.Println(clientID)
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

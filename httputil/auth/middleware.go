package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mimir-news/pkg/httputil"
)

// Header keys
const (
	AuthHeaderKey   = "Authorization"
	AuthTokenPrefix = "Bearer "
	ClientIDKey     = "X-Client-ID"
	userIDKey       = "X-User-ID"
	userRoleKey     = "X-User-Role"
	sessionIDKey    = "X-Session-ID"
)

// Options options for configuring authentication middleware.
type Options struct {
	Credentials    JWTCredentials
	ExemptedRoutes []string
}

// NewOptions sets up new auth options with optional exmpted routes.
func NewOptions(creds JWTCredentials, exemptedRoutes ...string) *Options {
	return &Options{
		Credentials:    creds,
		ExemptedRoutes: exemptedRoutes,
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
	verifier := NewVerifier(opts.Credentials, time.Minute)
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
		if clientID == "" {
			httputil.SendError(httputil.ErrUnauthorized(), c)
			return
		}

		token, verificationErr := verifier.Verify(encodedToken)
		if verificationErr != nil {
			err = httputil.NewError(verificationErr.Error(), http.StatusUnauthorized)
			httputil.SendError(err, c)
			return
		}

		saveTokenContent(c, token)
		c.Next()
	}
}

func saveTokenContent(c *gin.Context, token Token) {
	c.Set(userIDKey, token.User.ID)
	c.Set(userRoleKey, token.User.Role)
	c.Set(sessionIDKey, token.ID)
}

// GetUserID gets the user id set by the auth middleware.
func GetUserID(c *gin.Context) (string, error) {
	userID := c.GetString(userIDKey)
	if userID == "" {
		return "", httputil.NewError("User ID missing", http.StatusInternalServerError)
	}
	return userID, nil
}

// GetUserRole gets the user role set by auth middleware.
func GetUserRole(c *gin.Context) (string, error) {
	role := c.GetString(userIDKey)
	if role == "" {
		return "", httputil.NewError("UserRole missing", http.StatusInternalServerError)
	}
	return role, nil
}

// GetSessionID gets the session id set by auth middleware.
func GetSessionID(c *gin.Context) (string, error) {
	sessionID := c.GetString(sessionIDKey)
	if sessionID == "" {
		return "", httputil.NewError("Session ID missing", http.StatusInternalServerError)
	}
	return sessionID, nil
}

// AllowRoles middleware to set a number of allowed roles to call an endpoint.
func AllowRoles(roles ...string) gin.HandlerFunc {
	rolesSet := createRolesSet(roles)

	return func(c *gin.Context) {
		role, _ := GetUserRole(c)
		if _, ok := rolesSet[role]; !ok {
			httputil.SendError(httputil.ErrUnauthorized(), c)
			return
		}

		c.Next()
	}
}

// DisallowRoles middleware to set a number of roles that are not allowed to call an endpoint.
func DisallowRoles(roles ...string) gin.HandlerFunc {
	rolesSet := createRolesSet(roles)

	return func(c *gin.Context) {
		role, err := GetUserRole(c)
		if err != nil {
			httpErr, _ := err.(*httputil.Error)
			httputil.SendError(httpErr, c)
			return
		}

		if _, ok := rolesSet[role]; ok {
			httputil.SendError(httputil.ErrUnauthorized(), c)
			return
		}

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

func createRolesSet(roles []string) map[string]bool {
	set := make(map[string]bool)
	for _, role := range roles {
		set[role] = true
	}
	return set
}

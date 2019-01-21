package auth_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mimir-news/pkg/httputil"
	"github.com/mimir-news/pkg/httputil/auth"
	"github.com/mimir-news/pkg/id"
	"github.com/stretchr/testify/assert"
)

func TestRequireToken(t *testing.T) {
	assert := assert.New(t)

	subject := "test-subject"
	secret := "test-secret"
	issuer := "test-token-issuer"

	tokenAge := 1 * time.Minute

	okToken, err := auth.NewSigner(auth.JWTCredentials{Issuer: issuer, Secret: secret}, tokenAge).Sign(id.New(), auth.User{ID: subject, Role: auth.UserRole})
	assert.Nil(err)

	wrongSecretToken, err := auth.NewSigner(auth.JWTCredentials{Issuer: issuer, Secret: "wrong"}, tokenAge).Sign(id.New(), auth.User{ID: subject, Role: auth.UserRole})
	assert.Nil(err)

	wrongIssuerToken, err := auth.NewSigner(auth.JWTCredentials{Issuer: "wrong", Secret: secret}, tokenAge).Sign(id.New(), auth.User{ID: subject, Role: auth.UserRole})
	assert.Nil(err)

	expiredToken, err := auth.NewSigner(auth.JWTCredentials{Issuer: issuer, Secret: secret}, -2*time.Minute).Sign(id.New(), auth.User{ID: subject, Role: auth.UserRole})
	assert.Nil(err)

	tt := []struct {
		token          string
		route          string
		expectedStatus int
	}{
		{token: okToken, route: "/test", expectedStatus: http.StatusOK},
		{token: wrongSecretToken, route: "/test", expectedStatus: http.StatusUnauthorized},
		{token: wrongIssuerToken, route: "/test", expectedStatus: http.StatusUnauthorized},
		{token: expiredToken, route: "/test", expectedStatus: http.StatusUnauthorized},
		{route: "/test", expectedStatus: http.StatusUnauthorized},
		{route: "/test", expectedStatus: http.StatusUnauthorized},
		{route: "/exempted", expectedStatus: http.StatusOK},
	}

	r := gin.New()
	opts := auth.NewOptions(auth.JWTCredentials{Issuer: issuer, Secret: secret}, "/exempted")
	r.Use(auth.RequireToken(opts))
	r.GET("/test", testHandler)
	r.GET("/exempted", exemptedHandler)

	for i, tc := range tt {
		testCase := fmt.Sprintf("RequireToken test: %d", i+1)
		req := createTestRequest(t, tc.token, tc.route)
		recorder := performTestRequest(r, req)

		assert.Equal(tc.expectedStatus, recorder.Code, testCase)
	}
}

func TestAllowRoles(t *testing.T) {
	assert := assert.New(t)

	secret := "test-secret"
	issuer := "test-token-issuer"
	tokenAge := 1 * time.Minute
	jwtCreds := auth.JWTCredentials{Issuer: issuer, Secret: secret}
	signer := auth.NewSigner(jwtCreds, tokenAge)

	r := httputil.NewRouter("allow-roles-test", "1.0", func() error {
		return nil
	})
	r.Use(auth.RequireToken(auth.NewOptions(jwtCreds, "/health")))
	roleFilter := auth.AllowRoles(auth.AdminRole)
	r.GET("/test", roleFilter, httputil.SendOK)

	req := createTestRequest(t, "", "/health")
	res := performTestRequest(r, req)
	assert.Equal(http.StatusOK, res.Code)

	token, err := signer.Sign(id.New(), auth.User{
		ID:   id.New(),
		Role: auth.AdminRole,
	})
	assert.NoError(err)

	req = createTestRequest(t, token, "/test")
	res = performTestRequest(r, req)
	assert.Equal(http.StatusOK, res.Code)

	userToken, err := signer.Sign(id.New(), auth.User{
		ID:   id.New(),
		Role: auth.UserRole,
	})
	assert.NoError(err)

	req = createTestRequest(t, userToken, "/test")
	res = performTestRequest(r, req)
	assert.Equal(http.StatusForbidden, res.Code)

	anonymousToken, err := signer.Sign(id.New(), auth.User{
		ID:   id.New(),
		Role: auth.AnonymousRole,
	})
	assert.NoError(err)

	req = createTestRequest(t, anonymousToken, "/test")
	res = performTestRequest(r, req)
	assert.Equal(http.StatusForbidden, res.Code)
}

func TestDisallowRoles(t *testing.T) {
	assert := assert.New(t)

	secret := "test-secret"
	issuer := "test-token-issuer"
	tokenAge := 1 * time.Minute
	jwtCreds := auth.JWTCredentials{Issuer: issuer, Secret: secret}
	signer := auth.NewSigner(jwtCreds, tokenAge)

	r := httputil.NewRouter("allow-roles-test", "1.0", func() error {
		return nil
	})
	r.Use(auth.RequireToken(auth.NewOptions(jwtCreds, "/health")))
	roleFilter := auth.DisallowRoles(auth.AnonymousRole)
	r.GET("/test", roleFilter, httputil.SendOK)

	req := createTestRequest(t, "", "/health")
	res := performTestRequest(r, req)
	assert.Equal(http.StatusOK, res.Code)

	token, err := signer.Sign(id.New(), auth.User{
		ID:   id.New(),
		Role: auth.AdminRole,
	})
	assert.NoError(err)

	req = createTestRequest(t, token, "/test")
	res = performTestRequest(r, req)
	assert.Equal(http.StatusOK, res.Code)

	userToken, err := signer.Sign(id.New(), auth.User{
		ID:   id.New(),
		Role: auth.UserRole,
	})
	assert.NoError(err)

	req = createTestRequest(t, userToken, "/test")
	res = performTestRequest(r, req)
	assert.Equal(http.StatusOK, res.Code)

	anonymousToken, err := signer.Sign(id.New(), auth.User{
		ID:   id.New(),
		Role: auth.AnonymousRole,
	})
	assert.NoError(err)

	req = createTestRequest(t, anonymousToken, "/test")
	res = performTestRequest(r, req)
	assert.Equal(http.StatusForbidden, res.Code)

	noRoleToken, err := signer.Sign(id.New(), auth.User{
		ID:   id.New(),
		Role: "",
	})
	assert.NoError(err)

	req = createTestRequest(t, noRoleToken, "/test")
	res = performTestRequest(r, req)
	assert.Equal(http.StatusInternalServerError, res.Code)
}

func testHandler(c *gin.Context) {
	userID, err := auth.GetUserID(c)
	if err != nil {
		httpErr := err.(*httputil.Error)
		httputil.SendError(httpErr, c)
		return
	}
	c.String(http.StatusOK, "hello %s", userID)
}

func exemptedHandler(c *gin.Context) {
	c.String(http.StatusOK, "this route was exempted from auth checks.")
}

func performTestRequest(r http.Handler, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func createTestRequest(t *testing.T, token, route string) *http.Request {
	req, err := http.NewRequest(http.MethodGet, route, nil)
	assert.NoError(t, err)
	if token != "" {
		bearerToken := auth.AuthTokenPrefix + token
		req.Header.Set(auth.AuthHeaderKey, bearerToken)
	}

	return req
}

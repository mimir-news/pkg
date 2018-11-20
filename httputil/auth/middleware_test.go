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

	"github.com/stretchr/testify/assert"
)

func TestRequireToken(t *testing.T) {
	assert := assert.New(t)

	clientID := "test-client"
	subject := "test-subject"
	secret := "test-secret"
	key := "test-verification-key"
	tokenAge := 1 * time.Minute

	okToken, err := auth.NewSigner(secret, key, tokenAge).New(subject, clientID)
	assert.Nil(err)

	wrongSecretToken, err := auth.NewSigner("wrong", key, tokenAge).New(subject, clientID)
	assert.Nil(err)

	wrongKeyToken, err := auth.NewSigner(secret, "wrong", tokenAge).New(subject, clientID)
	assert.Nil(err)

	expiredToken, err := auth.NewSigner(secret, key, -2*time.Minute).New(subject, clientID)
	assert.Nil(err)

	tt := []struct {
		clientID       string
		token          string
		route          string
		expectedStatus int
	}{
		{clientID: clientID, token: okToken, route: "/test", expectedStatus: http.StatusOK},
		{clientID: "wrong-client", token: okToken, route: "/test", expectedStatus: http.StatusUnauthorized},
		{clientID: clientID, token: wrongSecretToken, route: "/test", expectedStatus: http.StatusUnauthorized},
		{clientID: clientID, token: wrongKeyToken, route: "/test", expectedStatus: http.StatusUnauthorized},
		{clientID: clientID, token: expiredToken, route: "/test", expectedStatus: http.StatusUnauthorized},
		{token: okToken, route: "/test", expectedStatus: http.StatusUnauthorized},
		{clientID: clientID, route: "/test", expectedStatus: http.StatusUnauthorized},
		{route: "/test", expectedStatus: http.StatusUnauthorized},
		{route: "/exempted", expectedStatus: http.StatusOK},
	}

	r := gin.New()
	opts := auth.NewOptions(secret, key, "/exempted")
	r.Use(auth.RequireToken(opts))
	r.GET("/test", testHandler)
	r.GET("/exempted", exemptedHandler)

	for i, tc := range tt {
		testCase := fmt.Sprintf("RequireToken test: %d", i+1)
		req := createTestRequest(t, tc.clientID, tc.token, tc.route)
		recorder := performTestRequest(r, req)

		assert.Equal(tc.expectedStatus, recorder.Code, testCase)
	}
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

func createTestRequest(t *testing.T, clientID, token, route string) *http.Request {
	req, err := http.NewRequest(http.MethodGet, route, nil)
	assert.Nil(t, err)

	if clientID != "" {
		req.Header.Set(auth.ClientIDKey, clientID)
	}
	if token != "" {
		bearerToken := auth.AuthTokenPrefix + token
		req.Header.Set(auth.AuthHeaderKey, bearerToken)
	}

	return req
}

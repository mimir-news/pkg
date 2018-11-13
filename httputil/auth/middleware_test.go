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
		expectedStatus int
	}{
		{clientID: clientID, token: okToken, expectedStatus: http.StatusOK},
		{clientID: "wrong-client", token: okToken, expectedStatus: http.StatusUnauthorized},
		{clientID: clientID, token: wrongSecretToken, expectedStatus: http.StatusUnauthorized},
		{clientID: clientID, token: wrongKeyToken, expectedStatus: http.StatusUnauthorized},
		{clientID: clientID, token: expiredToken, expectedStatus: http.StatusUnauthorized},
		{token: okToken, expectedStatus: http.StatusUnauthorized},
		{clientID: clientID, expectedStatus: http.StatusUnauthorized},
		{expectedStatus: http.StatusUnauthorized},
	}

	r := gin.New()
	r.Use(auth.RequireToken(secret, key))
	r.GET("/test", testHandler)

	for i, tc := range tt {
		testCase := fmt.Sprintf("RequireToken test: %d", i+1)
		req := createTestRequest(t, tc.clientID, tc.token)
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

func performTestRequest(r http.Handler, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func createTestRequest(t *testing.T, clientID, token string) *http.Request {
	req, err := http.NewRequest(http.MethodGet, "/test", nil)
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

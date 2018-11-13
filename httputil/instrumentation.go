package httputil

import (
	"github.com/gin-gonic/gin"
)

// Header keys
const (
	RequestIDHeader = "X-Request-ID"
)

func getRequestID(c *gin.Context) string {
	return c.GetString(RequestIDHeader)
}

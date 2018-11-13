package httputil

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/mimir-news/pkg/id"
)

// Header keys
const (
	RequestIDHeader = "X-Request-ID"
)

// RequestID annotates request with unique request id.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader(RequestIDHeader)
		if requestID == "" {
			requestID = id.New()
		}

		setRequestID(requestID, c)
		log.Println("DEBUG - Incoming request with id:", requestID)

		c.Next()
	}
}

// GetRequestID gets the request id from the gin context.
func GetRequestID(c *gin.Context) string {
	return c.GetString(RequestIDHeader)
}

// setRequestID sets a given request id in the gin context and the response headers.
func setRequestID(requestID string, c *gin.Context) {
	c.Set(RequestIDHeader, requestID)
	c.Header(RequestIDHeader, requestID)
}

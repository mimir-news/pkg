package httputil

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

// NewRouter creates a default router.
func NewRouter(name, version string) *gin.Engine {
	r := gin.Default()
	r.Use(
		ServerInfo(name, version),
		RequestID(),
		HandleErrors())

	return r
}

// ServerInfo annotates request with server name and version.
func ServerInfo(name, version string) gin.HandlerFunc {
	serverInfo := fmt.Sprintf("%s %s", name, version)
	return func(c *gin.Context) {
		c.Header("Server", serverInfo)
		c.Next()
	}
}

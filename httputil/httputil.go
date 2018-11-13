package httputil

import (
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

package httputil

import (
	"fmt"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Logger request logging middleware.
func Logger() gin.HandlerFunc {
	logger := getNamedLogger("Logger")

	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery
		c.Next()

		end := time.Now()
		latency := end.Sub(start)

		logger.Info(fmt.Sprintf("%s %s", c.Request.Method, path),
			zap.Int("status", c.Writer.Status()),
			zap.String("query", query),
			zap.String("requestId", GetRequestID(c)),
			zap.String("user-agent", c.Request.UserAgent()),
			zap.String("time", end.Format(time.RFC3339)),
			zap.Duration("latency", latency))
	}
}

func getLogger() *zap.Logger {
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalln("Failed to get zap.Logger", err)
	}

	return logger
}

func getNamedLogger(name string) *zap.Logger {
	logger := getLogger()
	return logger.With(zap.String("middleware", name))
}

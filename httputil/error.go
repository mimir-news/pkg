package httputil

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/mimir-news/pkg/id"
)

// Error implements the error interface with a message, unique ID and http status code.
type Error struct {
	ID         string
	Message    string
	StatusCode int
}

// NewError creates a new Error.
func NewError(message string, status int) *Error {
	return &Error{
		ID:         id.New(),
		Message:    message,
		StatusCode: status,
	}
}

func (e *Error) Error() string {
	return fmt.Sprintf("id=%s statusCode=%d message=%s", e.ID, e.StatusCode, e.Message)
}

type errorResponse struct {
	ErrorID    string `json:"errorId"`
	RequestID  string `json:"requestId"`
	Message    string `json:"message"`
	Path       string `json:"path"`
	StatusCode int    `json:"statusCode"`
}

func newErrorResponse(err *Error, c *gin.Context) errorResponse {
	return errorResponse{
		ErrorID:    err.ID,
		RequestID:  getRequestID(c),
		Message:    err.Message,
		Path:       c.Request.URL.Path,
		StatusCode: err.StatusCode,
	}
}

// SendError formats, logs and sends a response back to the client
func SendError(err *Error, c *gin.Context) {
	errResp := newErrorResponse(err, c)

	jsonErr, _ := json.Marshal(errResp)
	log.Println("ERROR:", string(jsonErr))

	c.AbortWithStatusJSON(errResp.StatusCode, errResp)
}

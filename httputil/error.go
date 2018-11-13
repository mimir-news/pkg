package httputil

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/mimir-news/pkg/id"
)

type Error struct {
	ID         string
	Message    string
	StatusCode int
}

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

func SendError(err *Error, c *gin.Context) {

}

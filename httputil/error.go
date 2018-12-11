package httputil

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/mimir-news/pkg/id"
)

// Error implements the error interface with a message, unique ID and http status code.
type Error struct {
	ID         string
	Message    string
	StatusCode int
}

// ErrUnauthorized creates an new unauthorized error.
func ErrUnauthorized() *Error {
	return newStandardError(http.StatusUnauthorized)
}

// ErrForbidden creates a new forbidden error.
func ErrForbidden() *Error {
	return newStandardError(http.StatusForbidden)
}

// ErrBadRequest creates a new forbidden error.
func ErrBadRequest() *Error {
	return newStandardError(http.StatusBadRequest)
}

// ErrNotFound creates a new not found errror.
func ErrNotFound() *Error {
	return newStandardError(http.StatusNotFound)
}

// NewInternalServerError creates a new internal server error.
func NewInternalServerError(message string) *Error {
	return NewError(message, http.StatusInternalServerError)
}

// NewError creates a new Error.
func NewError(message string, status int) *Error {
	return &Error{
		ID:         id.New(),
		Message:    message,
		StatusCode: status,
	}
}

// newStandardError creates an Error with a status and its default error message.
func newStandardError(status int) *Error {
	return NewError(http.StatusText(status), status)
}

// Error returns a string representation of the Error.
func (e *Error) Error() string {
	return fmt.Sprintf("id=%s statusCode=%d message=%s", e.ID, e.StatusCode, e.Message)
}

// HandleErrors wrapper function to deal with encountered errors
// during request handling.
func HandleErrors() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		err := getFirstError(c)
		if err == nil {
			return
		}

		var httpError *Error
		switch err.(type) {
		case *Error:
			httpError = err.(*Error)
			break
		default:
			httpError = NewInternalServerError(err.Error())
			break
		}

		SendError(httpError, c)
	}
}

// ErrorResponse description of the error encountered during request handling.
type ErrorResponse struct {
	ErrorID    string `json:"errorId"`
	RequestID  string `json:"requestId"`
	Message    string `json:"message"`
	Path       string `json:"path"`
	StatusCode int    `json:"statusCode"`
}

func newErrorResponse(err *Error, c *gin.Context) ErrorResponse {
	return ErrorResponse{
		ErrorID:    err.ID,
		RequestID:  GetRequestID(c),
		Message:    err.Message,
		Path:       c.Request.URL.Path,
		StatusCode: err.StatusCode,
	}
}

// SendError formats, logs and sends a response back to the client
func SendError(err *Error, c *gin.Context) {
	errResp := newErrorResponse(err, c)
	c.AbortWithStatusJSON(errResp.StatusCode, errResp)
}

// getFirstError returns the first error in the gin.Context, nil if not present.
func getFirstError(c *gin.Context) error {
	allErrors := c.Errors
	if len(allErrors) == 0 {
		return nil
	}
	return allErrors[0].Err
}

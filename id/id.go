// Package id is used for generating unique UUIDs.
package id

import (
	"github.com/satori/go.uuid"
)

// New creates a new UUID as a string.
func New() string {
	return uuid.NewV4().String()
}

package mq

import (
	"testing"
)

func TestConfigURI(t *testing.T) {
	cfg := NewConfig("localhost", "5672", "me", "pwd", 10)
	expectedURI := "amqp://me:pwd@localhost:5672/"

	if expectedURI != cfg.URI() {
		t.Errorf("Config.URI failed: Expected=%s Got=%s", expectedURI, cfg.URI())
	}
}

package mq

import (
	"testing"
)

func TestConfigURI(t *testing.T) {
	conf := NewConfig("localhost", "5672", "me", "pwd")
	expectedURI := "amqp://me:pwd@localhost:5672/"

	if expectedURI != conf.URI() {
		t.Errorf("Config.URI failed: Expected=%s Got=%s", expectedURI, conf.URI())
	}
}

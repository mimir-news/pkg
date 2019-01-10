package mq

import "fmt"

// Config holds configuraiton info needed for establishing an mq connection.
type Config struct {
	host          string
	port          string
	user          string
	password      string
	prefetchCount int
}

// NewConfig creates a new config.
func NewConfig(host, port, user, password string, prefetchCount int) Config {
	return Config{
		host:          host,
		port:          port,
		user:          user,
		password:      password,
		prefetchCount: prefetchCount,
	}
}

// URI creates a conndection URI
func (c Config) URI() string {
	return fmt.Sprintf("amqp://%s:%s@%s:%s/", c.user, c.password, c.host, c.port)
}

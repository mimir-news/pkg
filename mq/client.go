package mq

import (
	"encoding/json"
	"log"

	"github.com/streadway/amqp"
)

var (
	emptyAMQPPublishing = amqp.Publishing{}
)

// Message interface for deliveries from an underlying queue.
type Message interface {
	Ack() error
	Reject() error
	Decode(v interface{}) error
}

// AMQPMessage AMQP implemenation for the Message interface.
type AMQPMessage struct {
	msg amqp.Delivery
}

// NewAMQPMessage wraps an amqp.Delivery into an AMQPMessage.
func NewAMQPMessage(msg amqp.Delivery) AMQPMessage {
	return AMQPMessage{
		msg: msg,
	}
}

// Ack acknowlages the delivery of a message.
func (m AMQPMessage) Ack() error {
	return m.msg.Ack(false)
}

// Reject informes the underlying mq that the delivered message
// was invalid and should be discarded.
func (m AMQPMessage) Reject() error {
	return m.msg.Reject(false)
}

// Decode deserializes the delivery of a message into a supplied container.
func (m AMQPMessage) Decode(v interface{}) error {
	return json.Unmarshal(m.msg.Body, v)
}

// Client generic message queue client.
type Client interface {
	Close() error
	Send(msg interface{}, exchange, queue string) error
	Subscribe(queue, client string) (chan Message, error)
	Connected() bool
}

// AMQPClient client implemenation for the AMQP protocol.
type AMQPClient struct {
	url          string
	conn         *amqp.Connection
	channel      *amqp.Channel
	healthTarget string
}

// NewClient creates a new MQ client.
func NewClient(cfg Config, healthTarget string) (Client, error) {
	conn, err := amqp.Dial(cfg.URI())
	if err != nil {
		return nil, err
	}
	ch, err := conn.Channel()
	if err != nil {
		return nil, err
	}

	err = ch.Qos(cfg.prefetchCount, 0, false)
	if err != nil {
		return nil, err
	}

	client := &AMQPClient{
		url:          cfg.URI(),
		conn:         conn,
		channel:      ch,
		healthTarget: healthTarget,
	}

	return client, nil
}

// Subscribe creates Message channel that clients can use to consume messages from.
func (c *AMQPClient) Subscribe(queue, client string) (chan Message, error) {
	deliveryChan, err := c.channel.Consume(queue, client, false, false, false, false, nil)
	if err != nil {
		return nil, err
	}

	messageChannel := make(chan Message)
	go func() {
		for delivery := range deliveryChan {
			messageChannel <- NewAMQPMessage(delivery)
		}
		close(messageChannel)
	}()

	return messageChannel, nil
}

// Send serializes and sends a message to the specified queue.
func (c *AMQPClient) Send(msg interface{}, exchange, queue string) error {
	amqpMessage, err := newAMQPublishing(msg)
	if err != nil {
		return err
	}

	return c.channel.Publish(exchange, queue, false, false, amqpMessage)
}

// newAMQPublishing wraps message into an amqp.Publishing.
func newAMQPublishing(msg interface{}) (amqp.Publishing, error) {
	msgBody, err := json.Marshal(msg)
	if err != nil {
		return emptyAMQPPublishing, err
	}

	amqpMessage := amqp.Publishing{
		ContentType: "application/json",
		Body:        msgBody,
	}
	return amqpMessage, nil
}

// Close closes the underlying connection to the mq server.
func (c *AMQPClient) Close() error {
	err := c.channel.Close()
	if err != nil {
		log.Printf("Failed to close channel: %s", err.Error())
	}
	return c.conn.Close()
}

// Connected return the connection state of the client.
func (c *AMQPClient) Connected() bool {
	_, err := c.channel.QueueDeclarePassive(c.healthTarget, true, false, false, false, nil)
	if err != nil {
		log.Println("ERROR -", err)
		return false
	}

	return true
}

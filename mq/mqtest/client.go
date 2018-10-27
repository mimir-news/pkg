package mock

import (
	"encoding/json"
	"errors"
	"log"

	"github.com/news-ranker/pkg/mq"
)

type MockMessage struct {
	body       []byte
	failAck    bool
	failReject bool
}

func NewMessage(msgBody interface{}, failAck, failReject bool) mq.Message {
	body, err := json.Marshal(msgBody)
	if err != nil {
		log.Fatal(err)
	}

	return MockMessage{
		body:       body,
		failAck:    failAck,
		failReject: failReject,
	}
}

func (m MockMessage) Ack() error {
	if m.failAck {
		return errors.New("Mock Ack failed")
	}
	return nil
}

func (m MockMessage) Reject() error {
	if m.failReject {
		return errors.New("Mock reject failed")
	}
	return nil
}

func (m MockMessage) Decode(v interface{}) error {
	return json.Unmarshal(m.body, v)
}

type MockClient struct {
	messages      []MockMessage
	failClose     bool
	failSend      bool
	failSubscribe bool
}

func NewMockClient(messages []MockMessage, failClose, failSend, failSubscribe bool) mq.Client {
	return &MockClient{
		messages:      messages,
		failClose:     failClose,
		failSend:      failSend,
		failSubscribe: failSubscribe,
	}
}

func NewSuccessMockClient(messages []MockMessage) mq.Client {
	return &MockClient{
		messages:      messages,
		failClose:     false,
		failSend:      false,
		failSubscribe: false,
	}
}

func (c *MockClient) Close() error {
	if c.failClose {
		return errors.New("Mock close failed")
	}
	return nil
}

func (c *MockClient) Send(msg interface{}, exchange, queue string) error {
	if c.failSend {
		return errors.New("Mock send failed")
	}
	_, err := json.Marshal(msg)
	return err
}

func (c *MockClient) Subscribe(queue, client string) (chan mq.Message, error) {
	if c.failSubscribe {
		return nil, errors.New("Mock subscribe failed")
	}
	messageChannel := make(chan mq.Message)
	go func() {
		for _, msg := range c.messages {
			messageChannel <- msg
		}
	}()
	return messageChannel, nil
}

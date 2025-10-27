package main

import (
	"fmt"
	"log"
	"time"

	"github.com/nats-io/nats.go"
)

// This test demonstrates direct NATS connection with nkey authentication
// matching what the Santa NATS client would do

func main() {
	// Example credentials (would come from preflight in real usage)
	nkey := "UADJHFAVSNFSSBVRCTGTTXWXHYRNTTDKEEKZFADF5CJ6KGZOKT2A7WZM"
	jwt := "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJFU1VQS0NSNDQ1T1RZU0JRVkdXM1dITkVKNDI1TjNNWkdLM0I2NE1JUlhHU0QzS0E3WFBRIiwiaWF0IjoxNjA5NDU5MjAwLCJpc3MiOiJBQlkzT05DR0VGVUQzWDZMNUs2MldWQUhOSk9YS0ZWUjRETEhNQlRIQVZMT0FCUUlKUEpZV05TSSIsIm5hbWUiOiJ0ZXN0IiwidHlwZSI6InVzZXIiLCJuYXRzIjp7InB1YiI6e30sInN1YiI6e30sInN1YnMiOi0xLCJkYXRhIjotMSwicGF5bG9hZCI6LTF9fQ.example"
	
	// Server configuration
	server := "nats://localhost:4222" // For local testing without TLS
	// server := "tls://localhost.push.northpole.security:443" // Production would use TLS
	
	machineID := "test-machine-12345"
	tags := []string{"workshop", "santa-clients"}
	
	// Create NATS options with credentials
	opts := []nats.Option{
		nats.UserCredentials(
			// In real implementation, these would be passed to natsOptions_SetUserCredentials
			// For testing, we can use inline credentials
			nats.UserJWT(func() (string, error) { return jwt, nil },
				func(nonce []byte) ([]byte, error) {
					// In real implementation, this would sign the nonce with the nkey
					// For testing, we return a dummy signature
					return []byte("test-signature"), nil
				}),
		),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(10 * time.Second),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			log.Printf("Disconnected: %v", err)
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			log.Printf("Reconnected to %s", nc.ConnectedUrl())
		}),
		nats.ClosedHandler(func(nc *nats.Conn) {
			log.Printf("Connection closed")
		}),
	}
	
	log.Printf("Connecting to NATS server: %s", server)
	nc, err := nats.Connect(server, opts...)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer nc.Close()
	
	log.Println("Connected successfully!")
	
	// Subscribe to device topic
	deviceTopic := fmt.Sprintf("santa.%s", machineID)
	_, err = nc.Subscribe(deviceTopic, func(msg *nats.Msg) {
		log.Printf("Received on %s: %s", msg.Subject, string(msg.Data))
	})
	if err != nil {
		log.Fatalf("Failed to subscribe to device topic: %v", err)
	}
	log.Printf("Subscribed to device topic: %s", deviceTopic)
	
	// Subscribe to tags
	for _, tag := range tags {
		_, err = nc.Subscribe(tag, func(msg *nats.Msg) {
			log.Printf("Received on tag %s: %s", msg.Subject, string(msg.Data))
		})
		if err != nil {
			log.Printf("Failed to subscribe to tag %s: %v", tag, err)
		} else {
			log.Printf("Subscribed to tag: %s", tag)
		}
	}
	
	log.Println("Test client ready. Press Ctrl+C to exit.")
	
	// Keep running
	select {}
}
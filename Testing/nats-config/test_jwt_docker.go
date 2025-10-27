package main

import (
	"fmt"
	"log"
	"time"

	"github.com/nats-io/nats.go"
)

func main() {
	// JWT and seed from test-machine-12345.creds
	jwt := "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiI0N1dWSzdBUkpUV1c1NFhJSENIVDU1SlM3M1dWU1VUTUxUV1U0SUdPUlVJVUFHUVRLQkdRIiwiaWF0IjoxNzYxMzk3NjA4LCJpc3MiOiJBRE40R1VISEtNR01MMkQyQURFTFBVWUVGRjNRWU5JNERWTjZGNDNKUFA2R0k3VjRTVVlTSlRCNCIsIm5hbWUiOiJ0ZXN0LW1hY2hpbmUtMTIzNDUiLCJzdWIiOiJVQ043WTQ1VzVLTkE3V01ZTVdSQVVRSkRDSEVOQ1o3N1BSWVNCMkhYSENNUFRBNlBXRVZMVVRNTyIsIm5hdHMiOnsicHViIjp7ImFsbG93IjpbIl9JTkJPWC5cdTAwM2UiXX0sInN1YiI6eyJhbGxvdyI6WyJfSU5CT1guXHUwMDNlIiwic2FudGEtY2xpZW50cyIsInNhbnRhLioiLCJzYW50YS5ob3N0LioiLCJzYW50YS50YWcuKiIsIndvcmtzaG9wIl19LCJyZXNwIjp7Im1heCI6MSwidHRsIjowfSwic3VicyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwidHlwZSI6InVzZXIiLCJ2ZXJzaW9uIjoyfX0.L2C1512oLT6KDkgRLN8Ggl5Pa9ZQ1_a_NCqL8YZyzp9ot4PwHLHkLsGNuIgodRYi7LWybYKKIPJN1eRTxs0CDw"
	seed := "SUACBNSCZDJFQNXSNUMNMPHN7UY5AWS42E6VMQXVTKCU2KJYBR75MVDPJQ"

	// Connect to Docker NATS on port 443
	nc, err := nats.Connect("nats://localhost:443",
		nats.UserJWTAndSeed(jwt, seed),
		nats.ErrorHandler(func(nc *nats.Conn, sub *nats.Subscription, err error) {
			log.Printf("NATS Error: %v", err)
		}),
	)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer nc.Close()

	fmt.Println("Connected to Docker NATS!")

	// Test subscriptions with hexadecimal machine ID
	hexMachineID := "ABCDEF123456789"
	
	// Try subscribing to various topics
	topics := []string{
		fmt.Sprintf("santa.host.%s", hexMachineID),
		"santa.tag.global",
		"santa.tag.santa-clients",
		"santa.tag.workshop",
	}

	for _, topic := range topics {
		sub, err := nc.Subscribe(topic, func(m *nats.Msg) {
			fmt.Printf("Received message on %s: %s\n", m.Subject, string(m.Data))
		})
		if err != nil {
			fmt.Printf("❌ Failed to subscribe to %s: %v\n", topic, err)
		} else {
			fmt.Printf("✅ Subscribed to %s\n", topic)
			sub.Unsubscribe()
		}
	}

	// Also test with the original machine ID from the JWT
	fmt.Println("\nTesting with original machine ID from JWT:")
	origTopic := "santa.host.test-machine-12345"
	_, err = nc.Subscribe(origTopic, func(m *nats.Msg) {})
	if err != nil {
		fmt.Printf("❌ Failed to subscribe to %s: %v\n", origTopic, err)
	} else {
		fmt.Printf("✅ Subscribed to %s\n", origTopic)
	}

	// Keep connection alive briefly
	time.Sleep(1 * time.Second)
}
package main

import (
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
)

func main() {
	// Test both client and publisher JWTs
	tests := []struct {
		name string
		jwt  string
		seed string
	}{
		{
			name: "test-machine-12345 (client)",
			jwt:  "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiI0N1dWSzdBUkpUV1c1NFhJSENIVDU1SlM3M1dWU1VUTUxUV1U0SUdPUlVJVUFHUVRLQkdRIiwiaWF0IjoxNzYxMzk3NjA4LCJpc3MiOiJBRE40R1VISEtNR01MMkQyQURFTFBVWUVGRjNRWU5JNERWTjZGNDNKUFA2R0k3VjRTVVlTSlRCNCIsIm5hbWUiOiJ0ZXN0LW1hY2hpbmUtMTIzNDUiLCJzdWIiOiJVQ043WTQ1VzVLTkE3V01ZTVdSQVVRSkRDSEVOQ1o3N1BSWVNCMkhYSENNUFRBNlBXRVZMVVRNTyIsIm5hdHMiOnsicHViIjp7ImFsbG93IjpbIl9JTkJPWC5cdTAwM2UiXX0sInN1YiI6eyJhbGxvdyI6WyJfSU5CT1guXHUwMDNlIiwic2FudGEtY2xpZW50cyIsInNhbnRhLioiLCJzYW50YS5ob3N0LioiLCJzYW50YS50YWcuKiIsIndvcmtzaG9wIl19LCJyZXNwIjp7Im1heCI6MSwidHRsIjowfSwic3VicyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwidHlwZSI6InVzZXIiLCJ2ZXJzaW9uIjoyfX0.L2C1512oLT6KDkgRLN8Ggl5Pa9ZQ1_a_NCqL8YZyzp9ot4PwHLHkLsGNuIgodRYi7LWybYKKIPJN1eRTxs0CDw",
			seed: "SUACBNSCZDJFQNXSNUMNMPHN7UY5AWS42E6VMQXVTKCU2KJYBR75MVDPJQ",
		},
		{
			name: "test-publisher",
			jwt:  "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJYNlREWklOTE1VUVRHWjdXT0k1Tzc0MkQ2VExWQk1OV0oyNDIyUEtCUTRJMklMRk1ITlFBIiwiaWF0IjoxNzYxMzk2NjU0LCJpc3MiOiJBRE40R1VISEtNR01MMkQyQURFTFBVWUVGRjNRWU5JNERWTjZGNDNKUFA2R0k3VjRTVVlTSlRCNCIsIm5hbWUiOiJ0ZXN0LXB1Ymxpc2hlciIsInN1YiI6IlVCM1ZDTFRRSVMyWklPUjRNRzdZSFFQNkU2Q1NQUVA0NkxQNjNVUUFHNldITU40WUJJS0VPTkIyIiwibmF0cyI6eyJwdWIiOnsiYWxsb3ciOlsic2FudGEuKiIsInNhbnRhLmhvc3QuKiIsInNhbnRhLnRhZy4qIl19LCJzdWIiOnsiYWxsb3ciOlsic2FudGEuKiJdfSwic3VicyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwidHlwZSI6InVzZXIiLCJ2ZXJzaW9uIjoyfX0.-WT84YZASQ4e8cqmTncyVwaDMfjkM66HQFnFxYU36_WOoUV9FZHexCDYHArWLjdJu_ybaiIv4tmn2hIhkRq2Bw",
			seed: "SUAHTEEWVEQ72TBSE5ZRCCALOU57HKPOLWDLZGBHZB6RMAPOD5OI4KNAYM",
		},
	}

	for _, test := range tests {
		fmt.Printf("\n=== Testing %s ===\n", test.name)
		
		nc, err := nats.Connect("nats://localhost:443",
			nats.UserJWTAndSeed(test.jwt, test.seed),
			nats.ErrorHandler(func(nc *nats.Conn, sub *nats.Subscription, err error) {
				fmt.Printf("⚠️  NATS Error: %v\n", err)
			}),
		)
		if err != nil {
			fmt.Printf("❌ Failed to connect: %v\n", err)
			continue
		}
		
		fmt.Printf("✅ Connected as %s\n", test.name)
		
		// Test various operations that might trigger violations
		
		// 1. Try subscribing to subjects that should fail
		fmt.Println("\nTesting subscriptions that should fail:")
		failSubs := []string{
			"forbidden.topic",
			"$SYS.>",
			"admin.>",
		}
		for _, topic := range failSubs {
			_, err := nc.Subscribe(topic, func(m *nats.Msg) {})
			if err != nil {
				fmt.Printf("❌ Expected: Failed to subscribe to %s: %v\n", topic, err)
			} else {
				fmt.Printf("⚠️  Unexpected: Successfully subscribed to %s\n", topic)
			}
		}
		
		// 2. Try publishing to subjects
		fmt.Println("\nTesting publish operations:")
		pubTests := []string{
			"santa.host.ABCDEF123456789",
			"santa.tag.global",
			"forbidden.topic",
			"$SYS.REQ.SERVER.PING",
		}
		for _, topic := range pubTests {
			err := nc.Publish(topic, []byte("test"))
			if err != nil {
				fmt.Printf("❌ Failed to publish to %s: %v\n", topic, err)
			} else {
				fmt.Printf("✅ Published to %s\n", topic)
			}
		}
		
		// 3. Test wildcard subscriptions
		fmt.Println("\nTesting wildcard subscriptions:")
		wildcards := []string{
			"santa.>",
			"santa.host.>",
			"santa.tag.>",
		}
		for _, topic := range wildcards {
			_, err := nc.Subscribe(topic, func(m *nats.Msg) {})
			if err != nil {
				fmt.Printf("❌ Failed to subscribe to %s: %v\n", topic, err)
			} else {
				fmt.Printf("✅ Subscribed to %s\n", topic)
			}
		}
		
		nc.Close()
		time.Sleep(1 * time.Second)
	}
	
	fmt.Println("\nTest complete - check Docker logs for violations")
}
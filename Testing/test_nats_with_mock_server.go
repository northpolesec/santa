package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

// PreflightResponse represents the response sent to Santa's preflight request
type PreflightResponse struct {
	ClientMode                                  string   `json:"client_mode"`
	FullSyncIntervalSeconds                     int      `json:"full_sync_interval_seconds"`
	EnableBundles                               bool     `json:"enable_bundles"`
	EnableTransitiveRules                       bool     `json:"enable_transitive_rules"`
	PushServer                                  string   `json:"push_server"`
	PushToken                                   string   `json:"push_token"`
	PushJWT                                     string   `json:"push_jwt"`
	PushTags                                    []string `json:"push_tags"`
	PushNotificationFullSyncIntervalSeconds     int      `json:"push_notification_full_sync_interval_seconds"`
	PushNotificationGlobalRuleSyncDeadlineSeconds int    `json:"push_notification_global_rule_sync_deadline_seconds"`
}

func preflightHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		http.Error(w, "Error reading request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Extract machine ID from path
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	machineID := "unknown"
	if len(pathParts) >= 2 {
		machineID = pathParts[1]
	}

	log.Printf("Preflight request for machine: %s", machineID)
	log.Printf("Request body: %s", string(body))

	// Create response with NATS configuration
	response := PreflightResponse{
		ClientMode:            "MONITOR",
		FullSyncIntervalSeconds: 3600,
		EnableBundles:         true,
		EnableTransitiveRules: true,
		
		// NATS push notification configuration
		PushServer: "localhost", // Will be appended with .push.northpole.security
		PushToken:  "UADJHFAVSNFSSBVRCTGTTXWXHYRNTTDKEEKZFADF5CJ6KGZOKT2A7WZM", // Example nkey
		PushJWT:    "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJFU1VQS0NSNDQ1T1RZU0JRVkdXM1dITkVKNDI1TjNNWkdLM0I2NE1JUlhHU0QzS0E3WFBRIiwiaWF0IjoxNjA5NDU5MjAwLCJpc3MiOiJBQlkzT05DR0VGVUQzWDZMNUs2MldWQUhOSk9YS0ZWUjRETEhNQlRIQVZMT0FCUUlKUEpZV05TSSIsIm5hbWUiOiJ0ZXN0IiwidHlwZSI6InVzZXIiLCJuYXRzIjp7InB1YiI6e30sInN1YiI6e30sInN1YnMiOi0xLCJkYXRhIjotMSwicGF5bG9hZCI6LTF9fQ.example",
		PushTags:   []string{"workshop", "santa-clients", fmt.Sprintf("machine-%s", machineID)},
		
		// Push notification intervals
		PushNotificationFullSyncIntervalSeconds:       86400, // 24 hours
		PushNotificationGlobalRuleSyncDeadlineSeconds: 600,   // 10 minutes
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
		return
	}
}

func loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		next(w, r)
	}
}

func main() {
	port := flag.Int("port", 8080, "Port to run the mock sync server on")
	flag.Parse()

	http.HandleFunc("/preflight/", loggingMiddleware(preflightHandler))
	
	// Handle other endpoints
	http.HandleFunc("/", loggingMiddleware(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Unhandled endpoint: %s", r.URL.Path)
		http.Error(w, "Not found", http.StatusNotFound)
	}))

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Starting mock sync server on port %d", *port)
	log.Printf("Configure Santa with sync URL: http://localhost:%d", *port)
	log.Println("Press Ctrl+C to stop")

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
package main

import (
	"encoding/json"
	"log"
	"strings"

	"github.com/nats-io/nats.go"
)

type AuthRequest struct {
	Token   string            `json:"token"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
}

type AuthResponse struct {
	Valid    bool              `json:"valid"`
	UserId   string            `json:"userId,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Error    string            `json:"error,omitempty"`
}

func main() {
	// Connect to NATS
	nc, err := nats.Connect("nats://localhost:4222")
	if err != nil {
		log.Fatal(err)
	}
	defer nc.Close()

	// Subscribe to auth requests
	_, err = nc.Subscribe("auth.verify", func(msg *nats.Msg) {
		var req AuthRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			respondError(msg, "Invalid request format")
			return
		}

		// Perform authentication logic
		resp := authenticate(req)

		// Send response
		respData, _ := json.Marshal(resp)
		msg.Respond(respData)
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Auth microservice listening on auth.verify...")
	select {} // Keep running
}

func authenticate(req AuthRequest) AuthResponse {
	// Example: Bearer token validation
	token := strings.TrimPrefix(req.Token, "Bearer ")

	// TODO: Implement your actual authentication logic
	// - Validate JWT
	// - Check database
	// - Verify API key
	// - etc.

	// Example mock validation
	if token == "valid-token-123" {
		return AuthResponse{
			Valid:  true,
			UserId: "user-123",
			Metadata: map[string]string{
				"Role":  "admin",
				"Email": "user@example.com",
			},
		}
	}

	return AuthResponse{
		Valid: false,
		Error: "Invalid or expired token",
	}
}

func respondError(msg *nats.Msg, errMsg string) {
	resp := AuthResponse{
		Valid: false,
		Error: errMsg,
	}
	respData, _ := json.Marshal(resp)
	msg.Respond(respData)
}

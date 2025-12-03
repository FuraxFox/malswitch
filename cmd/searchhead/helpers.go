package main

import (
	"log"
	"net/http"

	"github.com/FuraxFox/malswitch/internal/message"
)

func RespondRequest(w http.ResponseWriter, r *http.Request, recipientContact message.MessageContact, content string) {

	// Encrypt response using server's signing key and client's public keys
	responseMsg, err := message.GenerateMessage([]byte(content), ServerSigningKey, []message.MessageContact{recipientContact})
	if err != nil {
		log.Printf("RESPONSE MESSAGE CREATION FAILED: %v", err)
		http.Error(w, "Failed to encrypt response", http.StatusInternalServerError)
		return
	}

	// Send encrypted response back
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(responseMsg)
	log.Println("Sent encrypted response back to client.")
}

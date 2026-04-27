package main

import (
	"github.com/FuraxFox/malswitch/internal/aiq"
	"github.com/FuraxFox/malswitch/internal/aiq_message"

	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

// DecryptHandler handles incoming JSON messages, decrypts, and sends an encrypted response.
func DecryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	// Decrypt the message (includes recipient verificaiton and cryptographic signature verification)
	clearText, sender, err := aiq_message.ReceiveMessage(body, ServerDecryptionKey, Correspondents)
	if err != nil {
		log.Printf("Decryption failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "Decryption Failed",
			"error":  err.Error(),
		})
		return
	}

	// Success
	log.Println("Decryption succeded ---")
	log.Printf("Decrypted Message: %s\n", clearText)

	responseText := handleAIQRequest(clearText)

	// The recipient for the response is the original sender (client)

	RespondRequest(w, r, sender, responseText)
}

func handleAIQRequest(decryptedPayload []byte) string {
	var responseText string
	request, err := aiq.DeserializeRequest(decryptedPayload)
	if err != nil {
		responseText = fmt.Sprintf("INVALID REQUEST: %v", err)
	} else {
		responseText = "REQUEST ACCEPTED"
		// TODO submit search
		log.Printf("Request: [%s]", request.String())
	}
	return responseText
}

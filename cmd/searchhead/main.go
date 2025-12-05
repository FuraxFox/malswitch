package main

import (
	"os"

	"github.com/FuraxFox/malswitch/internal/aiq"
	"github.com/FuraxFox/malswitch/internal/aiq_message"

	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"crypto/ed25519"
)

var (
	// Server's X25519 private key for incoming message decryption
	ServerDecryptionKey []byte
	// Server's Ed25519 private key for signing outgoing responses
	ServerSigningKey ed25519.PrivateKey
	// The list of contacts the server trusts (used for signature verification and authorization)
	Correspondents = []aiq_message.MessageContact{}
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
	decryptedString := clearText
	log.Println("Decryption succeded ---")
	log.Printf("Decrypted Message: %s\n", decryptedString)

	var responseText string
	request, err := aiq.DeserializeSearch(decryptedString)
	if err != nil {
		responseText = fmt.Sprintf("INVALID REQUEST: %v", err)
	} else {
		responseText = "REQUEST ACCEPTED"
		// TODO submit search
		log.Printf("Request: [%s]", request.String())
	}

	// The recipient for the response is the original sender (client)

	RespondRequest(w, r, sender, responseText)
}

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("Usage: %s <server_priv_file> <client_pub_file_1> [client_pub_file_2 ...]\n", os.Args[0])
		fmt.Println("Example: go run message_server.go R1.priv S1.pub S2.pub")
		os.Exit(1)
	}

	serverPrivFile := os.Args[1]
	clientPubKeyFiles := os.Args[2:]

	// Load Server's Private Keys
	privKeys, err := aiq_message.LoadPrivateKeys(serverPrivFile)
	if err != nil {
		log.Fatalf("Error loading server private key: %v", err)
	}
	ServerDecryptionKey = privKeys.DecryptionKey
	ServerSigningKey = privKeys.SigningKey
	log.Printf("Server initialized with keys from: %s", serverPrivFile)

	// Load Client Public Keys for Signature Verification and Authorization
	for _, clientPubKeyFile := range clientPubKeyFiles {
		clientContact, err := aiq_message.LoadContactFromFile(clientPubKeyFile)
		if err != nil {
			log.Fatalf("Error loading client public key from %s: %v", clientPubKeyFile, err)
		}

		// Populate Correspondents list
		Correspondents = append(Correspondents, clientContact)
		log.Printf("   -> Trusting client public key from: %s", clientPubKeyFile)
	}
	log.Printf("Trusting %d client(s) for communication.", len(Correspondents))

	http.HandleFunc("/decrypt", DecryptHandler)

	log.Println("\nStarting minimal decryption server on :8080...")
	log.Println("POST JSON payload to http://localhost:8080/decrypt")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

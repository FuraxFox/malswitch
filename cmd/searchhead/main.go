package main

import (
	"bytes"
	"os"

	"github.com/FuraxFox/malswitch/internal/message"
	"github.com/FuraxFox/malswitch/internal/search"

	"encoding/base64"
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
	Correspondents = []message.MessageContact{}
)

func CheckSenderAuthorization(msg *message.EncryptedMessage, correspondents []message.MessageContact) bool {

	for _, contact := range correspondents {
		if bytes.Equal(msg.Sender.SignatureKey, contact.SignatureKey) {
			return true
		}
	}
	return false
}

func RespondRequest(w http.ResponseWriter, r *http.Request, recipientContact message.MessageContact, content string) {

	// Encrypt response using server's signing key and client's public keys
	responseMsg, err := message.EncryptMessage([]byte(content), ServerSigningKey, []message.MessageContact{recipientContact})
	if err != nil {
		log.Printf("RESPONSE ENCRYPTION FAILED: %v", err)
		http.Error(w, "Failed to encrypt response", http.StatusInternalServerError)
		return
	}

	// Send encrypted response back
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(responseMsg)
	log.Println("Sent encrypted response back to client.")
}

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

	var msg message.EncryptedMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		http.Error(w, "Invalid JSON format: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Log incoming message details
	log.Println("--- Received Encrypted Message ---")
	senderSigKeyB64 := base64.StdEncoding.EncodeToString(msg.Sender.SignatureKey)
	log.Printf("Sender Sig Key (B64): %s", senderSigKeyB64)
	log.Printf("Data B64 Length: %d", len(msg.Data))

	// Authorization Check: Ensure sender's key is in the trusted list
	if !CheckSenderAuthorization(&msg, Correspondents) {
		log.Printf("AUTHORIZATION FAILED: Sender signature key %s is not in the trusted list.", senderSigKeyB64)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "Authorization Failed",
			"error":  "Sender signature key is not recognized or trusted.",
		})
	}

	// Decrypt the message (includes cryptographic signature verification)
	clearText, err := message.DecryptMessage(msg, ServerDecryptionKey, Correspondents)
	if err != nil {
		log.Printf("DECRYPTION/VERIFICATION FAILED: %v", err)
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
	log.Println("--- DECRYPTION SUCCESS ---")
	log.Printf("Decrypted Message: %s\n", decryptedString)

	var responseText string
	request, err := search.DeserializeSearch(decryptedString)
	if err != nil {
		responseText = fmt.Sprintf("INVALID REQUEST: %v", err)
	} else {
		responseText = "REQUEST RECEIVED"
	}

	// Process request
	fmt.Printf("Request: [%s]", request.String())

	// The recipient for the response is the original sender (client)

	RespondRequest(w, r, msg.Sender, responseText)
}

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("Usage: %s <server_priv_file> <client_pub_file_1> [client_pub_file_2 ...]\n", os.Args[0])
		fmt.Println("Example: go run message_server.go R1.priv S2.pub S3.pub")
		os.Exit(1)
	}

	serverPrivFile := os.Args[1]
	clientPubKeyFiles := os.Args[2:]

	// 1. Load Server's Private Keys (R1)
	privKeys, err := message.LoadPrivateKeys(serverPrivFile)
	if err != nil {
		log.Fatalf("Error loading server private key: %v", err)
	}
	ServerDecryptionKey = privKeys.DecryptionKey
	ServerSigningKey = privKeys.SigningKey
	log.Printf("Server initialized with keys from: %s", serverPrivFile)

	// 2. Load Client Public Keys for Signature Verification and Authorization
	for _, clientPubKeyFile := range clientPubKeyFiles {
		clientContact, err := message.LoadContactFromFile(clientPubKeyFile)
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

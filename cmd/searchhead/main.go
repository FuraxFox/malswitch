package main

import (
	"os"

	"github.com/FuraxFox/malswitch/internal/message"

	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	// Import the new internal package
)

// Define the structure for reading the key files
// PublicKeySet is now defined and loaded in internal/message
type PrivateKeySet struct {
	DecryptionKey string `json:"X25519_Priv"`
	SigningKey    string `json:"Ed25519_Priv"` // Ed25519 Private Key (64 bytes)
}

var (
	// Recipient's X25519 private key (32 bytes)
	RecipientDecryptionKey []byte
	// The hardcoded list of contacts the recipient trusts (here, just the sender S2)
	Correspondents = []message.MessageContact{}
)

// DecryptHandler handles incoming JSON messages and attempts decryption.
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

	log.Println("--- Received Encrypted Message ---")
	log.Printf("Sender Sig Key (B64): %s", base64.StdEncoding.EncodeToString(msg.Sender.SignatureKey)[:10]+"...")
	log.Printf("Data B64 Length: %d", len(msg.Data))

	// Decrypt the message using the function from the 'message' package
	clearText, err := message.DecryptMessage(msg, RecipientDecryptionKey, Correspondents)

	if err != nil {
		log.Printf("DECRYPTION FAILED: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "Decryption Failed",
			"error":  err.Error(),
		})
		return
	}

	// Success
	decryptedString := string(clearText)
	log.Println("--- DECRYPTION SUCCESS ---")
	log.Printf("Decrypted Message: %s", decryptedString)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "OK",
		"message":  decryptedString,
		"verified": "true",
	})
}

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: %s <recipient_priv_file> <sender_pub_file>\n", os.Args[0])
		fmt.Println("Example: go run message_server.go R1.priv S2.pub")
		os.Exit(1)
	}

	recipientPrivFile := os.Args[1]
	senderPubKeyFile := os.Args[2]

	// 1. Load Server's Private Key (R1)
	var privKeys message.PrivateKeySet
	if err := message.LoadPrivateKeys(recipientPrivFile, &privKeys); err != nil {
		log.Fatalf("Error loading recipient private key: %v", err)
	}
	var err error
	RecipientDecryptionKey, err = base64.StdEncoding.DecodeString(privKeys.DecryptionKey)
	if err != nil {
		log.Fatalf("Error decoding recipient X25519 private key: %v", err)
	}

	// 2. Load Client's Public Key (S2) using the new utility function
	senderContact, err := message.LoadContactFromFile(senderPubKeyFile)
	if err != nil {
		log.Fatalf("Error loading sender public key: %v", err)
	}

	// Populate Correspondents (needed for DecryptMessage signature, verifies sender's identity)
	Correspondents = append(Correspondents, senderContact)

	log.Printf("Server R1 initialized with decryption key from: %s", recipientPrivFile)
	log.Printf("Server R1 configured to trust sender S2 public key from: %s", senderPubKeyFile)

	http.HandleFunc("/decrypt", DecryptHandler)

	log.Println("Starting minimal decryption server on :8080...")
	log.Println("POST JSON payload to http://localhost:8080/decrypt")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

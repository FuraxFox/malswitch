package main

import (
	"crypto/ed25519"
	"fmt"
	"log"
	"time"

	"github.com/FuraxFox/malswitch/internal/message"

	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"

	"io"

	"net/http"
	"os"
)

// Define the structure for reading the key files (must match msg-keygen.go output)
type PublicKeySet struct {
	EncryptionKey string `json:"X25519_Pub"`
	SignatureKey  string `json:"Ed25519_Pub"`
}

type PrivateKeySet struct {
	DecryptionKey string `json:"X25519_Priv"`  // X25519 Private Key (32 bytes)
	SigningKey    string `json:"Ed25519_Priv"` // Ed25519 Private Key (64 bytes)
}

var (
	// Client's Ed25519 private key (64 bytes)
	ClientSigningKey ed25519.PrivateKey
	// The server's public key as a message.MessageContact
	ServerRecipient message.MessageContact
	// HTTP client
	httpClient = &http.Client{Timeout: 10 * time.Second}
)

// loadKeySetFromFile reads a JSON file, decodes the Base64 keys, and populates the target struct.
func loadKeySetFromFile(filename string, target interface{}) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", filename, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("failed to parse JSON from %s: %w", filename, err)
	}
	return nil
}

// initKeysFromFile loads keys from the provided file paths.
func initKeysFromFile(clientPrivFile, serverPubKeyFile string) error {
	var err error

	// 1. Load Client's Private Key (S2)
	var privKeys PrivateKeySet
	if err := loadKeySetFromFile(clientPrivFile, &privKeys); err != nil {
		return fmt.Errorf("error loading client private key: %w", err)
	}

	ClientSigningKey, err = base64.StdEncoding.DecodeString(privKeys.SigningKey)
	if err != nil {
		return fmt.Errorf("error decoding client Ed25519 private key: %w", err)
	}
	// The decoded key must be a valid 64-byte Ed25519 private key
	if len(ClientSigningKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid client Ed25519 private key size: expected %d, got %d", ed25519.PrivateKeySize, len(ClientSigningKey))
	}

	// 2. Load Server's Public Keys (R1)
	var pubKeys PublicKeySet
	if err := loadKeySetFromFile(serverPubKeyFile, &pubKeys); err != nil {
		return fmt.Errorf("error loading server public key: %w", err)
	}

	r1XPub, err := base64.StdEncoding.DecodeString(pubKeys.EncryptionKey)
	if err != nil {
		return fmt.Errorf("error decoding server X25519 public key: %w", err)
	}
	r1EdPub, err := base64.StdEncoding.DecodeString(pubKeys.SignatureKey)
	if err != nil {
		return fmt.Errorf("error decoding server Ed25519 public key: %w", err)
	}

	ServerRecipient = message.MessageContact{
		EncryptionKey: r1XPub,
		SignatureKey:  r1EdPub,
	}

	log.Printf("Client S2 initialized with signing key from: %s", clientPrivFile)
	log.Printf("Client S2 configured to encrypt to server R1 public key from: %s", serverPubKeyFile)
	return nil
}

// sendEncryptedMessage encrypts the clear text and posts the resulting JSON to the server.
func sendEncryptedMessage(serverURL string, clearText string) error {
	if clearText == "" {
		return nil // Skip empty lines
	}

	log.Printf("Encrypting message: \"%s\"", clearText)

	// 1. Encrypt the message
	encryptedMsg, err := message.EncryptMessage([]byte(clearText), ClientSigningKey, []message.MessageContact{ServerRecipient})
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// 2. Marshal to JSON
	jsonPayload, err := json.Marshal(encryptedMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// 3. Send via HTTP POST
	log.Printf("Sending %d byte payload to %s...", len(jsonPayload), serverURL)

	resp, err := httpClient.Post(serverURL, "application/json", bytes.NewReader(jsonPayload))
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// 4. Read and display server response
	responseBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned error status %d: %s", resp.StatusCode, string(responseBody))
	}

	log.Printf("Server Response (%d OK): %s", resp.StatusCode, string(responseBody))
	return nil
}

// readAndSendMessages reads messages from stdin and sends them to the server.
func readAndSendMessages(serverURL string) {
	fmt.Println("--- Secure Message Client ---")
	fmt.Printf("Server Target: %s\n", serverURL)
	fmt.Println("Enter messages line by line (Ctrl+D or Ctrl+Z to exit):")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()

		err := sendEncryptedMessage(serverURL, line)
		if err != nil {
			log.Printf("[Error] Could not send message: %v", err)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[Scanner Error]: %v", err)
	}

	fmt.Println("\nClient finished.")
}

func main() {
	log.SetFlags(log.Ltime)

	if len(os.Args) < 3 || len(os.Args) > 4 {
		fmt.Printf("Usage: %s <client_priv_file> <server_pub_file> [server_url]\n", os.Args[0])
		fmt.Println("Example: go run msg-client.go S2.priv R1.pub http://localhost:8080/decrypt")
		os.Exit(1)
	}

	clientPrivFile := os.Args[1]
	serverPubKeyFile := os.Args[2]
	serverURL := "http://localhost:8080/decrypt"
	if len(os.Args) == 4 {
		serverURL = os.Args[3]
	}

	if err := initKeysFromFile(clientPrivFile, serverPubKeyFile); err != nil {
		log.Fatalf("Fatal initialization error: %v", err)
	}

	readAndSendMessages(serverURL)
}

package main

import (
	"crypto/ed25519"
	"fmt"
	"log"
	"time"

	"github.com/FuraxFox/malswitch/internal/message"

	"bufio"
	"bytes"
	"encoding/json"

	"io"

	"net/http"
	"os"
)

var (
	// Client's Ed25519 private key for signing outgoing messages
	ClientSigningKey ed25519.PrivateKey
	// Client's X25519 private key for decrypting incoming responses
	ClientDecryptionKey []byte
	// The server's public key (for encryption and response signature verification)
	ServerContact message.MessageContact
	// HTTP client
	httpClient = &http.Client{Timeout: 10 * time.Second}
)

// initKeysFromFile loads keys from the provided file paths.
func initKeysFromFile(clientPrivFile, serverPubKeyFile string) error {
	var err error

	// 1. Load Client's Full Private Key Set (S2)
	privKeys, err := message.LoadPrivateKeys(clientPrivFile)
	if err != nil {
		return fmt.Errorf("error loading client private key: %w", err)
	}
	ClientSigningKey = privKeys.SigningKey
	ClientDecryptionKey = privKeys.DecryptionKey

	// 2. Load Server's Public Keys (R1)
	ServerContact, err = message.LoadContactFromFile(serverPubKeyFile)
	if err != nil {
		return fmt.Errorf("error loading server public key: %w", err)
	}

	log.Printf("Client S2 initialized with full key pair from: %s", clientPrivFile)
	log.Printf("Client S2 configured to communicate with server R1 public key from: %s", serverPubKeyFile)
	return nil
}

// sendEncryptedMessage encrypts the clear text, posts it, and decrypts the response.
func sendEncryptedMessage(serverURL string, clearText string) error {
	if clearText == "" {
		return nil // Skip empty lines
	}

	log.Printf("Encrypting message: \"%s\"", clearText)

	// 1. Encrypt the outgoing message
	encryptedMsg, err := message.EncryptMessage([]byte(clearText), ClientSigningKey, []message.MessageContact{ServerContact})
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// 2. Marshal to JSON and send
	jsonPayload, err := json.Marshal(encryptedMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	log.Printf("Sending %d byte payload to %s...", len(jsonPayload), serverURL)
	resp, err := httpClient.Post(serverURL, "application/json", bytes.NewReader(jsonPayload))
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// 3. Read response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read server response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Handle error responses (which may or may not be encrypted)
		return fmt.Errorf("server returned error status %d: %s", resp.StatusCode, string(responseBody))
	}

	// 4. Unmarshal the EncryptedMessage response
	var encryptedResponse message.EncryptedMessage
	if err := json.Unmarshal(responseBody, &encryptedResponse); err != nil {
		return fmt.Errorf("failed to parse encrypted response JSON: %w", err)
	}

	// 5. Decrypt the response
	// The server is the sender of this response.
	// The client uses its decryption key and the server's public key (ServerContact) for verification/unwrapping.
	decryptedResponse, err := message.DecryptMessage(encryptedResponse, ClientDecryptionKey, []message.MessageContact{ServerContact})

	if err != nil {
		return fmt.Errorf("failed to decrypt server response: %w", err)
	}

	// Success
	log.Printf("Server Acknowledgment: %s", string(decryptedResponse))
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

/*
 * Support functions: networking and files
 */
package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/FuraxFox/malswitch/internal/message"
)

// initKeysFromFile loads keys from the provided file paths, simulating the original logic.
func (m *model) initKeysFromFile(clientPrivFile, serverPubKeyFile string) error {
	var err error

	// Load Client's Full Private Key Set (sender)
	privKeys, err := message.LoadPrivateKeys(clientPrivFile)
	if err != nil {
		return fmt.Errorf("error loading client private key from %s: %w", clientPrivFile, err)
	}
	m.ClientKeys = privKeys

	// Load Server's Public Keys (recipient)
	m.ServerContact, err = message.LoadContactFromFile(serverPubKeyFile)
	if err != nil {
		return fmt.Errorf("error loading server public key from %s: %w", serverPubKeyFile, err)
	}

	log.Printf("Client initialized with full key pair from: %s", clientPrivFile)
	log.Printf("Client configured to communicate with server public key from: %s", serverPubKeyFile)
	return nil
}

// sendEncryptedMessage encrypts the clear text (the signed JSON payload), posts it, and decrypts the response.
// The result is handled asynchronously by the TUI.
func sendEncryptedMessage(serverURL string, clientKeys *message.PrivateKeySet, serverContact *message.MessageContact, clearText string) (string, error) {

	// Acceptable contacts, containing only the server informations
	correspondents := []message.MessageContact{*serverContact}
	jsonPayload, err := message.GenerateMessage([]byte(clearText), clientKeys.SigningKey, correspondents)
	if err != nil {
		return "", fmt.Errorf("message generation failed: %w", err)
	}

	// Sending...
	resp, err := httpClient.Post(serverURL, "application/json", bytes.NewReader(jsonPayload))
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read server response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("server returned error status %d: %s", resp.StatusCode, string(responseBody))
	}

	// Decode, verify and decrypt response (since only the server is accepted we do not check the sender)
	ack, _, err := message.ReceiveMessage(responseBody, clientKeys.DecryptionKey, correspondents)
	if err != nil {
		return "", fmt.Errorf("error on acknowleded: %v", err)
	}

	// Success is implied by the lack of error from DecryptMessage and the OK status.
	log.Printf("Acknowlede received: %v", ack)
	return string(ack), nil
}

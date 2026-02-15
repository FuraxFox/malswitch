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

	"github.com/FuraxFox/malswitch/internal/aiq_message"
	tea "github.com/charmbracelet/bubbletea"
)

// initKeysFromFile loads keys from the provided file paths, simulating the original logic.
func (m *model) initKeysFromFile(clientPrivFile, serverPubKeyFile string) error {
	var err error

	// Load Client's Full Private Key Set (sender)
	privKeys, err := aiq_message.LoadPrivateKeys(clientPrivFile)
	if err != nil {
		return fmt.Errorf("error loading client private key from %s: %w", clientPrivFile, err)
	}
	m.ClientKeys = privKeys

	// Load Server's Public Keys (recipient)
	m.ServerContact, err = aiq_message.LoadContactFromFile(serverPubKeyFile)
	if err != nil {
		return fmt.Errorf("error loading server public key from %s: %w", serverPubKeyFile, err)
	}

	log.Printf("Client initialized with full key pair from: %s", clientPrivFile)
	log.Printf("Client configured to communicate with server public key from: %s", serverPubKeyFile)
	return nil
}

// sendEncryptedMessage encrypts the clear text (the signed JSON payload), posts it, and decrypts the response.
// The result is handled asynchronously by the TUI.
func sendEncryptedMessage(serverURL string, clientKeys *aiq_message.PrivateKeySet, serverContact *aiq_message.MessageContact, clearText string) (string, error) {
	return sendEncryptedMessageTo(serverURL, clientKeys, []aiq_message.MessageContact{*serverContact}, clearText)
}

// sendEncryptedMessageTo encrypts the clear text, posts it to the URL, and decrypts the response using any of the correspondents.
func sendEncryptedMessageTo(targetURL string, clientKeys *aiq_message.PrivateKeySet, correspondents []aiq_message.MessageContact, clearText string) (string, error) {

	jsonPayload, err := aiq_message.GenerateMessage([]byte(clearText), clientKeys.SigningKey, correspondents)
	if err != nil {
		return "", fmt.Errorf("message generation failed: %w", err)
	}

	// Sending...
	resp, err := httpClient.Post(targetURL, "application/json", bytes.NewReader(jsonPayload))
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
	ack, _, err := aiq_message.ReceiveMessage(responseBody, clientKeys.DecryptionKey, correspondents)
	if err != nil {
		return "", fmt.Errorf("error on acknowleded: %v", err)
	}

	// Success is implied by the lack of error from DecryptMessage and the OK status.
	log.Printf("Acknowlede received: %v", ack)
	return string(ack), nil
}

// sendCommunityUpdateCmd generates and sends a community update to a specific contact.
func (m *model) sendCommunityUpdateCmd(contact aiq_message.MessageContact) tea.Cmd {
	return func() tea.Msg {
		// Generate the update message
		updatePayload, err := m.community.GenerateUpdate(m.ClientKeys.SigningKey, []aiq_message.MessageContact{contact})
		if err != nil {
			return sendResultMsg{err: fmt.Errorf("failed to generate community update: %w", err)}
		}

		// Sending... (since GenerateUpdate already returns the full AIQ message, we use http.Post directly)
		resp, err := httpClient.Post(contact.Endpoint, "application/json", bytes.NewReader(updatePayload))
		if err != nil {
			return sendResultMsg{err: fmt.Errorf("failed to send community update to %s: %w", contact.Endpoint, err)}
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return sendResultMsg{err: fmt.Errorf("server returned error %d: %s", resp.StatusCode, string(body))}
		}

		// Decode ACK
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return sendResultMsg{err: fmt.Errorf("failed to read ACK: %w", err)}
		}

		// The ACK is also an AIQ message
		ack, _, err := aiq_message.ReceiveMessage(body, m.ClientKeys.DecryptionKey, []aiq_message.MessageContact{contact})
		if err != nil {
			return sendResultMsg{err: fmt.Errorf("failed to decrypt ACK: %w", err)}
		}

		return sendResultMsg{result: "Community update accepted by " + contact.Endpoint + ": " + string(ack)}
	}
}

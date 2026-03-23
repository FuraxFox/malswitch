/*
 * Support functions: networking and files
 */
package main

import (
	"fmt"

	"log"

	"github.com/FuraxFox/malswitch/internal/aiq_message"
	tea "github.com/charmbracelet/bubbletea"
)

///////////////////////////////////////////// Sending the request to the server

// Msg to handle the result of the asynchronous network operation
type sendResultMsg struct {
	err    error
	result string // Decrypted response from server
}

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

	log.Printf("CommMgr initialized with full key pair from: %s", clientPrivFile)
	log.Printf("CommMgr configured to communicate with server public key from: %s", serverPubKeyFile)
	return nil
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

		ack, err := m.Client.SendMessage(&m.ServerContact, string(updatePayload))
		if err != nil {
			return sendResultMsg{err: fmt.Errorf("failed to send community update to %s: %w", contact.Endpoint, err)}
		}

		return sendResultMsg{result: "Community update accepted by " + contact.Endpoint + ": " + string(ack)}
	}
}

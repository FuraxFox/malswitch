// aiq_message public API

package aiq_message

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
)

// EncryptedMessage holds the final message structure, with binary fields encoded in Base64 for transport.
type EncryptedMessage struct {
	Version     int
	Data        string   // Base64 encoded ciphertext + nonce
	Signature   string   // Base64 encoded ed25519 signature of the normalized message
	WrappedKeys []string // List of Base64 encoded wrapped symmetric keys (one per recipient)
	Sender      MessageContact
}

// Receive a JSON encoded message, decode it, verify signature and return the payload, the sender and the eventual error
func ReceiveMessage(rawJSON []byte, decryptionKey []byte, correspondents []MessageContact) ([]byte, MessageContact, error) {

	// Unmarshal the message
	var msg EncryptedMessage
	if err := json.Unmarshal(rawJSON, &msg); err != nil {
		return nil, MessageContact{}, fmt.Errorf("failed to parse encrypted response JSON: %w", err)
	}

	// Decrypt and verify the message
	result, err := decryptMessage(msg, decryptionKey, correspondents)
	if err != nil {
		return nil, MessageContact{}, fmt.Errorf("failed to decrypt or verify server response: %w", err)
	}

	return result, msg.Sender, nil
}

// Generate a JSON encoded encrypted and signed message
func GenerateMessage(clearText []byte, signingKey []byte, correspondents []MessageContact) ([]byte, error) {
	// Encrypt the outgoing message
	encryptedMsg, err := encryptMessage(clearText, ed25519.PrivateKey(signingKey), correspondents)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	// Marshal to JSON and send
	jsonPayload, err := json.Marshal(encryptedMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return jsonPayload, nil
}

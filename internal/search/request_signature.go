package search

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/FuraxFox/malswitch/internal/message"
)

// searchContent is a temporary struct used to create a canonical, normalized
// representation of the Search data *excluding* the Signature field.
type searchContent struct {
	Community        string               `json:"community"`
	EncryptedContent []byte               `json:"content"`
	SenderKeys       message.PublicKeySet `json:"keys"`
}

// normalizedContent generates the canonical JSON byte representation of the search request,
// which is used as input for signing and verification.
// It is critical that this output is deterministic.
func (s *Search) normalizedContent() ([]byte, error) {
	// Create the content structure, explicitly excluding the Signature field
	content := searchContent{
		Community:        s.Community,
		EncryptedContent: s.EncryptedContent,
		SenderKeys:       s.SenderKeys,
	}

	// Marshal to JSON. Use json.Marshal (not MarshalIndent) for canonical output.
	data, err := json.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal search content for normalization: %w", err)
	}
	return data, nil
}

// Sign generates an Ed25519 signature of the normalized search content
// using the provided private key, and updates the Search's Signature field.
// This function should be called before the Search is transmitted.
func (s *Search) Sign(privKeys message.PrivateKeySet) error {
	// 1. Get the normalized content bytes
	content, err := s.normalizedContent()
	if err != nil {
		return fmt.Errorf("search signing failed: %w", err)
	}

	// 2. Perform the Ed25519 signing
	signature := ed25519.Sign(privKeys.SigningKey, content)

	// 3. Update the struct
	s.Signature = signature
	return nil
}

// Verify checks the search request's signature against the sender's public key
// and the normalized content.
func (s *Search) Verify() error {
	// 1. Check if the signature exists
	if len(s.Signature) == 0 {
		return errors.New("verification failed: search request lacks a signature")
	}

	// 2. Get the sender's public key (SignatureKey) and decode it from Base64
	senderPubKeyB64 := s.SenderKeys.SignatureKey
	senderPubKey, err := base64.StdEncoding.DecodeString(senderPubKeyB64)
	if err != nil {
		return fmt.Errorf("verification failed: failed to decode sender's signature key from Base64: %w", err)
	}

	if len(senderPubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("verification failed: sender's public key has invalid size (%d)", len(senderPubKey))
	}

	// 3. Get the normalized content bytes
	content, err := s.normalizedContent()
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	// 4. Perform the Ed25519 verification
	if !ed25519.Verify(senderPubKey, content, s.Signature) {
		return errors.New("verification failed: signature is invalid or request content has been tampered with")
	}

	return nil
}

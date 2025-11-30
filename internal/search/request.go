package search

import (
	"encoding/json"
	"fmt"

	"github.com/FuraxFox/malswitch/internal/message"
)

type Search struct {
	Community        string
	EncryptedContent []byte               `json:"content"`
	Signature        []byte               `json:"signature"`
	SenderKeys       message.PublicKeySet `json:"keys"`
}

// Serialize signs the Search request using the provided private key and marshals the result to JSON.
func (s *Search) Serialize(privKeys message.PrivateKeySet) ([]byte, error) {
	// 1. Sign the request
	if err := s.Sign(privKeys); err != nil {
		return nil, fmt.Errorf("failed to sign request before serialization: %w", err)
	}

	// 2. Marshal the signed struct to JSON
	data, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Search struct to JSON: %w", err)
	}

	return data, nil
}

// Deserialize reads a JSON byte slice, unmarshals the content into a Search struct,
// and verifies the embedded signature.
func DeserializeSearch(data []byte) (Search, error) {
	var s Search

	// 1. Unmarshal the JSON byte slice into the Search struct
	if err := json.Unmarshal(data, &s); err != nil {
		return Search{}, fmt.Errorf("failed to unmarshal JSON into Search struct: %w", err)
	}

	// 2. Verify the signature
	if err := s.Verify(); err != nil {
		return Search{}, fmt.Errorf("data integrity check failed during deserialization: %w", err)
	}

	return s, nil
}

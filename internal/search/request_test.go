package search

import (
	"testing"

	"github.com/FuraxFox/malswitch/internal/message"
)

// TestSearchSigningVerification tests the successful Sign and Verify lifecycle of a Search request.
func TestSearchSigningVerification(t *testing.T) {
	// Setup keys for the sender
	senderPubKey, senderPrivKey := generateKeys(t)

	// 1. Create a Search request
	searchRequest := Search{
		Community:        "alpha-community",
		EncryptedContent: []byte("encrypted data payload"),
		SenderKeys:       senderPubKey,
	}

	// 2. Sign the request
	if err := searchRequest.Sign(senderPrivKey); err != nil {
		t.Fatalf("Failed to sign Search request: %v", err)
	}
	if len(searchRequest.Signature) == 0 {
		t.Fatal("Signature field is empty after signing")
	}

	// 3. Verify the signature
	if err := searchRequest.Verify(); err != nil {
		t.Errorf("Verification failed for correctly signed request: %v", err)
	}
}

// TestSearchVerificationFailures tests various scenarios where verification should fail.
func TestSearchVerificationFailures(t *testing.T) {
	// Setup keys
	validPubKey, validPrivKey := generateKeys(t)
	tamperingPubKey, tamperingPrivKey := generateKeys(t)

	// Base valid request
	baseRequest := Search{
		Community:        "beta-community",
		EncryptedContent: []byte("secure search content"),
		SenderKeys:       validPubKey,
	}
	// Sign the base request
	if err := baseRequest.Sign(validPrivKey); err != nil {
		t.Fatalf("Failed to sign base request: %v", err)
	}

	tests := []struct {
		name      string
		mutate    func(*Search)
		expectErr bool
	}{
		{
			name: "No signature",
			mutate: func(s *Search) {
				s.Signature = nil
			},
			expectErr: true,
		},
		{
			name: "Content tampering (changing community ID)",
			mutate: func(s *Search) {
				s.Community = "tampered-community"
			},
			expectErr: true,
		},
		{
			name: "Content tampering (changing encrypted content)",
			mutate: func(s *Search) {
				s.EncryptedContent = []byte("altered content")
			},
			expectErr: true,
		},
		{
			name: "Invalid signature (signed by another key)",
			mutate: func(s *Search) {
				// Sign with the tampering key, but keep the sender keys as the valid key
				s.Sign(message.PrivateKeySet{SigningKey: tamperingPrivKey.SigningKey})
			},
			expectErr: true,
		},
		{
			name: "Corrupt signature key (causes Base64 decode error)",
			mutate: func(s *Search) {
				s.SenderKeys.SignatureKey = "!!!"
			},
			expectErr: true,
		},
		{
			name: "Mismatched signature key (signature is valid, but key in payload is wrong)",
			mutate: func(s *Search) {
				// The signature belongs to validPrivKey, but we tell the receiver the key is tamperingPubKey
				s.SenderKeys.SignatureKey = tamperingPubKey.SignatureKey
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fresh copy of the signed base request for each test case
			requestCopy := baseRequest

			// Mutate the copy
			tt.mutate(&requestCopy)

			err := requestCopy.Verify()

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected an error for %s, but got nil", tt.name)
				}
			} else {
				if err != nil {
					t.Errorf("Did not expect an error for %s, but got: %v", tt.name, err)
				}
			}
		})
	}
}

// TestSearchSerializationDeserialization verifies that a search request can be correctly
// signed, serialized, and then deserialized and verified.
func TestSearchSerializationDeserialization(t *testing.T) {
	// Setup keys for the sender
	senderPubKey, senderPrivKey := generateKeys(t)

	// 1. Create a Search request
	originalRequest := Search{
		Community:        "serialization-community",
		EncryptedContent: []byte("data to serialize"),
		SenderKeys:       senderPubKey,
	}

	// 2. Serialize and sign the request
	serializedData, err := originalRequest.Serialize(senderPrivKey)
	if err != nil {
		t.Fatalf("Failed to serialize request: %v", err)
	}

	// 3. Deserialize and verify the request
	deserializedRequest, err := DeserializeSearch(serializedData)
	if err != nil {
		t.Fatalf("Failed to deserialize and verify request: %v", err)
	}

	// 4. Check content integrity
	if deserializedRequest.Community != originalRequest.Community {
		t.Errorf("Community mismatch: got %s, want %s", deserializedRequest.Community, originalRequest.Community)
	}

	// Test failure on tampering the serialized data
	t.Run("Tampering during transmission", func(t *testing.T) {
		// Flip a bit in the serialized JSON data
		tamperedData := make([]byte, len(serializedData))
		copy(tamperedData, serializedData)

		// Find and change a character in the content string
		// This will cause the normalized content hash to change.
		// NOTE: Finding 'data' in JSON and changing it is robust.
		for i, b := range tamperedData {
			if b == 'd' {
				tamperedData[i] = 'X' // Change 'data' to 'Xata' in the content field
				break
			}
		}

		_, err := DeserializeSearch(tamperedData)
		if err == nil {
			t.Error("Expected verification failure after tampering, got nil")
		}
	})
}

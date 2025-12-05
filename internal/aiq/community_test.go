package aiq

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/FuraxFox/malswitch/internal/aiq_message"
)

// Helper function to generate a new Ed25519 key pair and format it
// into the PublicKeySet and PrivateKeySet structs for testing.
func generateKeys(t *testing.T) (aiq_message.PublicKeySet, aiq_message.PrivateKeySet) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 keys: %v", err)
	}

	// Create PrivateKeySet
	privSet := aiq_message.PrivateKeySet{
		DecryptionKey: make([]byte, 32), // Placeholder X25519 Decryption Key
		SigningKey:    priv,
	}

	// Base64 encode the public key for the PublicKeySet string field
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	// Create PublicKeySet
	pubSet := aiq_message.PublicKeySet{
		EncryptionKey: pubB64, // Using the same key for both fields for simplicity in testing
		SignatureKey:  pubB64,
	}

	return pubSet, privSet
}

// TestCommunityPersistence tests the full lifecycle: Sign, Save, Load, and Verify.
func TestCommunityPersistence(t *testing.T) {
	// Setup keys for the owner
	ownerPubKey, ownerPrivKey := generateKeys(t)

	// Create a temporary file path
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "test_community.json")

	// 1. Create the Community struct
	community := Community{
		UID:         "test-123",
		Threshold:   "Low",
		RequestKind: true,
		Members: []CommunityMember{
			{Endpoint: "https://member1.com", Keys: ownerPubKey},
		},
		Owner: CommunityMember{
			Endpoint: "https://owner.com",
			Keys:     ownerPubKey,
		},
	}

	// 2. Sign the community
	if err := community.Sign(ownerPrivKey); err != nil {
		t.Fatalf("Failed to sign community: %v", err)
	}
	if len(community.Signature) == 0 {
		t.Fatal("Signature field is empty after signing")
	}

	// 3. Save the community to file
	if err := community.Save(filename); err != nil {
		t.Fatalf("Failed to save community: %v", err)
	}

	// 4. Load the community from file
	loadedCommunity, err := LoadCommunity(filename)
	if err != nil {
		t.Fatalf("Failed to load community: %v", err)
	}

	// 5. Verify the loaded community's signature
	if err := loadedCommunity.Verify(); err != nil {
		t.Errorf("Verification failed after loading: %v", err)
	}

	// Basic check to ensure content loaded correctly
	if loadedCommunity.UID != community.UID {
		t.Errorf("Loaded UID mismatch: got %s, want %s", loadedCommunity.UID, community.UID)
	}
}

// TestVerifyFailure tests scenarios where verification should intentionally fail.
func TestVerifyFailure(t *testing.T) {
	ownerPubKey, ownerPrivKey := generateKeys(t)
	attackerPubKey, attackerPrivKey := generateKeys(t)

	// Create base community
	community := Community{
		UID:         "test-456",
		Threshold:   "High",
		RequestKind: false,
		Members:     []CommunityMember{},
		Owner: CommunityMember{
			Endpoint: "https://owner.com",
			Keys:     ownerPubKey,
		},
	}
	community.Sign(ownerPrivKey)

	tests := []struct {
		name      string
		mutate    func(*Community)
		expectErr bool
	}{
		{
			name: "No signature",
			mutate: func(c *Community) {
				c.Signature = nil
			},
			expectErr: true,
		},
		{
			name: "Content tampering (changing UID)",
			mutate: func(c *Community) {
				c.UID = "tampered-456"
			},
			expectErr: true,
		},
		{
			name: "Invalid signature (using another key's signature)",
			mutate: func(c *Community) {
				// Sign with attacker's key, but keep the owner data the same
				attackerCommunity := *c // Deep copy for signing
				attackerCommunity.Sign(attackerPrivKey)
				c.Signature = attackerCommunity.Signature
			},
			expectErr: true,
		},
		{
			name: "Owner key tampering (signature doesn't match new owner's public key)",
			mutate: func(c *Community) {
				// Change the owner's public key without resigning
				c.Owner.Keys = attackerPubKey
			},
			expectErr: true,
		},
		{
			name: "Signature decoding failure (corrupt Base64 public key)",
			mutate: func(c *Community) {
				// Corrupt the Base64 key string to fail decoding
				c.Owner.Keys.SignatureKey = "not a valid base64 key"
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fresh signed community for each test case
			c := community // shallow copy is enough here since we only mutate fields
			tt.mutate(&c)

			err := c.Verify()

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

// TestLoadFailure tests scenarios where file loading should fail.
func TestLoadFailure(t *testing.T) {
	// 1. Test non-existent file
	_, err := LoadCommunity("non_existent_file.json")
	if err == nil {
		t.Error("Expected error when loading non-existent file, got nil")
	}

	// 2. Test invalid JSON format
	tmpDir := t.TempDir()
	invalidJsonFile := filepath.Join(tmpDir, "invalid.json")
	if err := os.WriteFile(invalidJsonFile, []byte("{invalid json"), 0644); err != nil {
		t.Fatalf("Failed to write invalid JSON file: %v", err)
	}
	_, err = LoadCommunity(invalidJsonFile)
	if err == nil {
		t.Error("Expected error when loading invalid JSON, got nil")
	}

	// 3. Test invalid signature after loading (uses TestCommunityPersistence setup)
	ownerPubKey, ownerPrivKey := generateKeys(t)
	filename := filepath.Join(tmpDir, "bad_sig.json")

	// Create and sign a community
	community := Community{
		UID: "bad-sig-test", Threshold: "High", RequestKind: false,
		Owner: CommunityMember{Endpoint: "https://owner.com", Keys: ownerPubKey},
	}
	community.Sign(ownerPrivKey)

	// Tamper with the saved file *content* before loading
	originalData, err := json.MarshalIndent(community, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal original data: %v", err)
	}

	// Inject some random byte change into the content (e.g., change 'High' to 'Hige')
	tamperedData := bytes.Replace(originalData, []byte("High"), []byte("Hige"), 1)

	if err := os.WriteFile(filename, tamperedData, 0644); err != nil {
		t.Fatalf("Failed to write tampered file: %v", err)
	}

	_, err = LoadCommunity(filename)
	if err == nil {
		t.Error("Expected signature verification error after content tampering during Load, got nil")
	}
}

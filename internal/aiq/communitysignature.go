package aiq

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/FuraxFox/malswitch/internal/aiq_message"
)

// communityContent is a temporary struct used to create a canonical, normalized
// representation of the community data *excluding* the signature field.
// This is what gets marshaled and signed/verified.
type communityContent struct {
	UID         string                       `json:"uuid"`
	Members     []aiq_message.MessageContact `json:"members"`
	Threshold   string                       `json:"maxlevel"`
	RequestKind bool                         `json:"fullcontent"`
	Owner       aiq_message.MessageContact   `json:"owner"`
}

// normalizedContent generates the canonical JSON byte representation of the community,
// which is used as input for signing and verification.
func (c *Community) normalizedContent() ([]byte, error) {
	// Create the content structure, excluding the Signature field
	content := communityContent{
		UID:         c.UID,
		Members:     c.Members,
		Threshold:   c.Threshold,
		RequestKind: c.RequestKind,
		Owner:       c.Owner,
	}

	// Marshal to JSON. Using standard Marshal is critical for deterministic output.
	// If fields are added or rearranged, the signing must use the exact same logic.
	data, err := json.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal content for normalization: %w", err)
	}
	return data, nil
}

// Sign generates an Ed25519 signature of the normalized community content
// using the provided private key, and updates the Community's Signature field.
// The private key must belong to the Community's Owner.
func (c *Community) Sign(privKeys aiq_message.PrivateKeySet) error {
	// 1. Get the normalized content bytes
	content, err := c.normalizedContent()
	if err != nil {
		return err
	}

	// 2. Perform the Ed25519 signing
	signature := ed25519.Sign(privKeys.SigningKey, content)

	// 3. Update the struct
	c.Signature = signature
	return nil
}

// / Verify checks the community's signature against the owner's public key
// and the current normalized content.
func (c *Community) Verify() error {
	// 1. Check if the signature exists
	if len(c.Signature) == 0 {
		return errors.New("verification failed: community lacks a signature")
	}

	// 2. Get the owner's public key (SignatureKey) and decode it from Base64
	ownerPubKeyB64 := c.Owner.SignatureKey
	ownerPubKey, err := base64.StdEncoding.DecodeString(ownerPubKeyB64) // <-- NEW: Decode Base64 string
	if err != nil {
		return fmt.Errorf("verification failed: failed to decode owner's signature key from Base64: %w", err)
	}

	if len(ownerPubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("verification failed: owner's public key has invalid size (%d)", len(ownerPubKey))
	}

	// 3. Get the normalized content bytes
	content, err := c.normalizedContent()
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	// 4. Perform the Ed25519 verification
	// ownerPubKey is now []byte, which satisfies the ed25519.PublicKey type.
	if !ed25519.Verify(ownerPubKey, content, c.Signature) {
		return errors.New("verification failed: signature is invalid or content has been tampered with")
	}

	return nil
}

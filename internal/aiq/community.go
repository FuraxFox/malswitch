package aiq

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/FuraxFox/malswitch/internal/aiq_message"
)

type Community struct {
	UID         string                       `json:"uuid"`
	Members     []aiq_message.MessageContact `json:"members"`
	Threshold   string                       `json:"maxlevel"`
	RequestKind bool                         `json:"fullcontent"`
	Signature   []byte                       `json:"signature"`
	Owner       aiq_message.MessageContact   `json:"owner"`
}

func (c *Community) AddMember(endpoint string, keys aiq_message.PublicKeySet) error {

	ek, err := base64.StdEncoding.DecodeString(keys.EncryptionKey)
	if err != nil {
		return err
	}
	sk, err := base64.StdEncoding.DecodeString(keys.SignatureKey)
	if err != nil {
		return err
	}

	m := aiq_message.MessageContact{
		Endpoint:      endpoint,
		EncryptionKey: ek,
		SignatureKey:  sk,
	}
	c.Members = append(c.Members, m)

	return nil
}

// AddContact adds a MessageContact to the community's members if it's not already present.
func (c *Community) AddContact(contact aiq_message.MessageContact) {
	for _, m := range c.Members {
		if bytes.Equal(m.SignatureKey, contact.SignatureKey) {
			return
		}
	}
	c.Members = append(c.Members, contact)
}

func (c *Community) LookupMemberByKey(pubkey string) *aiq_message.MessageContact {
	for _, m := range c.Members {
		if bytes.Equal(m.SignatureKey, []byte(pubkey)) {
			return &m
		}
	}
	return nil
}

// Save marshals the Community struct into a JSON format and writes it to the specified file.
func (c *Community) Save(filename string) error {
	// Marshal the struct into a JSON byte slice (using MarshalIndent for readability)
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal Community to JSON: %w", err)
	}

	// Write the JSON data to the file
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write JSON data to file %s: %w", filename, err)
	}

	return nil
}

// LoadCommunity reads a JSON file, unmarshals the content, and verifies the signature.
func LoadCommunity(filename string) (Community, error) {
	var c Community

	// Read the JSON file content
	data, err := os.ReadFile(filename)
	if err != nil {
		return Community{}, fmt.Errorf("failed to read file %s: %w", filename, err)
	}

	// Unmarshal the JSON byte slice into the Community struct
	if err := json.Unmarshal(data, &c); err != nil {
		return Community{}, fmt.Errorf("failed to unmarshal JSON into Community struct: %w", err)
	}

	// Verify the signature
	if err := c.Verify(); err != nil {
		// Crucial step: if verification fails, raise an error immediately.
		return Community{}, fmt.Errorf("community data integrity check failed: %w", err)
	}

	return c, nil
}

// GenerateCommunityUpdate loads a community from a file, wraps it in an AIQ message, and signs it.
func (community *Community) GenerateUpdate(signingKey ed25519.PrivateKey, recipients []aiq_message.MessageContact) ([]byte, error) {

	// Create the RequestEnveloppe
	envelope, err := NewCommunityUpdateRequest(*community)
	if err != nil {
		return nil, fmt.Errorf("failed to create community update request: %w", err)
	}

	// Serialize the envelope
	payload, err := envelope.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize envelope: %w", err)
	}

	// Generate the AIQ message
	return aiq_message.GenerateMessage(payload, signingKey, recipients)
}

// GenerateCommunitySubscribe creates a subscription request, wraps it in an AIQ message, and signs it with the member's keys.
func GenerateCommunitySubscribe(communityUUID string, memberInfo aiq_message.MessageContact, signingKey ed25519.PrivateKey, owner aiq_message.MessageContact) ([]byte, error) {
	// Create the RequestEnveloppe
	envelope, err := NewCommunitySubscribeRequest(communityUUID, memberInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to create community subscribe request: %w", err)
	}

	// Serialize the envelope
	payload, err := envelope.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize envelope: %w", err)
	}

	// Generate the AIQ message
	return aiq_message.GenerateMessage(payload, signingKey, []aiq_message.MessageContact{owner})
}

package aiq

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/FuraxFox/malswitch/internal/aiq_message"
)

type CommunityMember struct {
	Endpoint string                   `json:"endpoint"`
	Keys     aiq_message.PublicKeySet `json:"keys"`
}

type Community struct {
	UID         string            `json:"uuid"`
	Members     []CommunityMember `json:"members"`
	Threshold   string            `json:"maxlevel"`
	RequestKind bool              `json:"fullcontent"`
	Signature   []byte            `json:"signature"`
	Owner       CommunityMember   `json:"owner"`
}

func (c *Community) AddMember(endpoint string, keys aiq_message.PublicKeySet) {
	m := CommunityMember{
		Endpoint: endpoint,
		Keys:     keys,
	}
	c.Members = append(c.Members, m)
}

func (c *Community) LookeupMemberByKey(pubkey string) *CommunityMember {
	for _, m := range c.Members {
		if m.Keys.SignatureKey == pubkey {
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

	// 1. Read the JSON file content
	data, err := os.ReadFile(filename)
	if err != nil {
		return Community{}, fmt.Errorf("failed to read file %s: %w", filename, err)
	}

	// 2. Unmarshal the JSON byte slice into the Community struct
	if err := json.Unmarshal(data, &c); err != nil {
		return Community{}, fmt.Errorf("failed to unmarshal JSON into Community struct: %w", err)
	}

	// 3. Verify the signature
	if err := c.Verify(); err != nil {
		// Crucial step: if verification fails, raise an error immediately.
		return Community{}, fmt.Errorf("community data integrity check failed: %w", err)
	}

	return c, nil
}

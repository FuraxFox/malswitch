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

func (c *Community) LookupMemberByKey(pubkey string) *CommunityMember {
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
func GenerateCommunityUpdate(communityFile string, signingKey ed25519.PrivateKey, recipients []aiq_message.MessageContact) ([]byte, error) {
	// Load community from file
	community, err := LoadCommunity(communityFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load community: %w", err)
	}

	// Create the RequestEnveloppe
	envelope, err := NewCommunityUpdateRequest(community)
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

// ReceiveCommunityUpdate decrypts and verifies an AIQ community update message, verifies the community's internal signature, updates a local file, and generates an acknowledgment or error message.
func ReceiveCommunityUpdate(rawJSON []byte, decryptionKey []byte, signingKey ed25519.PrivateKey, correspondents []aiq_message.MessageContact, localCommunityFile string) ([]byte, error) {
	// Receive and decrypt AIQ message
	payload, sender, err := aiq_message.ReceiveMessage(rawJSON, decryptionKey, correspondents)
	if err != nil {
		return nil, fmt.Errorf("failed to receive AIQ message: %w", err)
	}

	// Deserialize request
	envelope, err := DeserializeRequest(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize request: %w", err)
	}

	// Validate request type
	if envelope.Type != CommunityUpdateRequestType || envelope.CommunityUpdate == nil {
		return generateErrorResponse("invalid request type", signingKey, []aiq_message.MessageContact{sender}, envelope.CommunityUUID)
	}

	community := envelope.CommunityUpdate.Community

	// Verify community signature
	if err := community.Verify(); err != nil {
		return generateErrorResponse("community verification failed: "+err.Error(), signingKey, []aiq_message.MessageContact{sender}, community.UID)
	}

	// Verify sender is the owner
	ownerPubKey, err := base64.StdEncoding.DecodeString(community.Owner.Keys.SignatureKey)
	if err != nil {
		return generateErrorResponse("failed to decode owner public key", signingKey, []aiq_message.MessageContact{sender}, community.UID)
	}
	if !bytes.Equal(sender.SignatureKey, ownerPubKey) {
		return generateErrorResponse("sender is not the community owner", signingKey, []aiq_message.MessageContact{sender}, community.UID)
	}

	// Update local file
	if err := community.Save(localCommunityFile); err != nil {
		return generateErrorResponse("failed to save community: "+err.Error(), signingKey, []aiq_message.MessageContact{sender}, community.UID)
	}

	// Generate success response
	respEnv, _ := NewCommunityUpdateAcceptedRequest(community.UID)
	respPayload, _ := respEnv.Serialize()
	return aiq_message.GenerateMessage(respPayload, signingKey, []aiq_message.MessageContact{sender})
}

func generateErrorResponse(message string, signingKey ed25519.PrivateKey, recipients []aiq_message.MessageContact, communityUUID string) ([]byte, error) {
	envelope, _ := NewErrorRequest(communityUUID, message)
	payload, _ := envelope.Serialize()
	return aiq_message.GenerateMessage(payload, signingKey, recipients)
}

// GenerateCommunitySubscribe creates a subscription request, wraps it in an AIQ message, and signs it with the member's keys.
func GenerateCommunitySubscribe(communityUUID string, memberInfo CommunityMember, signingKey ed25519.PrivateKey, owner aiq_message.MessageContact) ([]byte, error) {
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

// ReceiveCommunitySubscribe decrypts and verifies an AIQ subscription message and returns the received CommunityMember.
func ReceiveCommunitySubscribe(rawJSON []byte, decryptionKey []byte, correspondents []aiq_message.MessageContact) (*CommunityMember, error) {
	// Preliminary unmarshal to get the sender's public keys.
	// This is necessary because aiq_message.ReceiveMessage checks sender authorization
	// against the provided correspondents list. For a new subscription, the sender
	// is typically not yet in that list.
	var encryptedMsg aiq_message.EncryptedMessage
	if err := json.Unmarshal(rawJSON, &encryptedMsg); err != nil {
		return nil, fmt.Errorf("failed to preliminary unmarshal AIQ message: %w", err)
	}

	// Temporarily add the sender to the correspondents list for authorization.
	allCorrespondents := append(correspondents, encryptedMsg.Sender)

	// Receive and decrypt AIQ message
	payload, sender, err := aiq_message.ReceiveMessage(rawJSON, decryptionKey, allCorrespondents)
	if err != nil {
		return nil, fmt.Errorf("failed to receive AIQ message: %w", err)
	}

	// Deserialize request
	envelope, err := DeserializeRequest(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize request: %w", err)
	}

	// Validate request type
	if envelope.Type != CommunitySubscribeRequestType || envelope.CommunitySubscribe == nil {
		return nil, fmt.Errorf("invalid request type: expected %s", CommunitySubscribeRequestType)
	}

	member := envelope.CommunitySubscribe.Member

	// Verify signature: ensure the member's public key matches the AIQ message sender's signature key.
	memberPubKey, err := base64.StdEncoding.DecodeString(member.Keys.SignatureKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode member public key: %w", err)
	}

	if !bytes.Equal(sender.SignatureKey, memberPubKey) {
		return nil, fmt.Errorf("member public key mismatch with AIQ message sender")
	}

	return &member, nil
}

package aiq

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/FuraxFox/malswitch/internal/aiq_message"
)

func HandleCommunityUpdateMessage(rawJSON []byte, decryptionKey []byte, signingKey ed25519.PrivateKey, correspondents []aiq_message.MessageContact) (*Community, []byte, error) {

	// receive and verify the message
	community, sender, err := receiveCommunityUpdate(rawJSON, decryptionKey, correspondents)
	if err != nil {
		// something was wrong sending error
		envelope, _ := NewErrorRequest(community.UUID, "invalid community update")
		payload, _ := envelope.Serialize()
		errMsg, err2 := aiq_message.GenerateMessage(payload, signingKey, []aiq_message.MessageContact{*sender})
		if err2 != nil {
			err = fmt.Errorf("initial error '%v' and an another error was encountered while generating the answer: %v", err, err2)
		}
		return nil, errMsg, err
	}

	// generate acknowledge answer
	respEnv, _ := NewCommunityUpdateAcceptedRequest(community.UUID)
	respPayload, _ := respEnv.Serialize()
	msg, err := aiq_message.GenerateMessage(respPayload, signingKey, []aiq_message.MessageContact{*sender})
	if err != nil {
		return nil, nil, err
	}
	return community, msg, nil
}

// HandleCommunitySubscribe decrypts and verifies an AIQ subscription message and returns the received CommunityMember and the acknowledge message.
func HandleCommunitySubscribe(
	rawJSON []byte,
	decryptionKey []byte,
	signingKey ed25519.PrivateKey,
	correspondents []aiq_message.MessageContact) (*aiq_message.MessageContact, []byte, error) {

	member, cuuid, err := receiveCommunitySubscribe(rawJSON, decryptionKey, correspondents)
	if err != nil {
		// something was wrong sending error
		envelope, _ := NewErrorRequest(cuuid, "invalid subscription request")
		payload, _ := envelope.Serialize()
		errMsg, err2 := aiq_message.GenerateMessage(payload, signingKey, []aiq_message.MessageContact{*member})
		if err2 != nil {
			err = fmt.Errorf("initial error '%v' and an another error was encountered while generating the answer: %v", err, err2)
		}
		return nil, errMsg, err
	}
	// generate acknowledge answer
	respEnv, _ := NewCommunitySubscriptionQueuedRequest(cuuid)
	respPayload, _ := respEnv.Serialize()
	msg, err := aiq_message.GenerateMessage(respPayload, signingKey, []aiq_message.MessageContact{*member})
	if err != nil {
		return nil, nil, err
	}
	return member, msg, nil
}

// ReceiveCommunitySubscribe decrypts and verifies an AIQ subscription message and returns the received CommunityMember.
func receiveCommunitySubscribe(rawJSON []byte, decryptionKey []byte, correspondents []aiq_message.MessageContact) (*aiq_message.MessageContact, string, error) {
	// Preliminary unmarshal to get the sender's public keys.
	// This is necessary because aiq_message.ReceiveMessage checks sender authorization
	// against the provided correspondents list. For a new subscription, the sender
	// is typically not yet in that list.
	var encryptedMsg aiq_message.EncryptedMessage
	if err := json.Unmarshal(rawJSON, &encryptedMsg); err != nil {
		return nil, "", fmt.Errorf("failed to preliminary unmarshal AIQ message: %w", err)
	}

	// Temporarily add the sender to the correspondents list for authorization.
	allCorrespondents := append(correspondents, encryptedMsg.Sender)

	// Receive and decrypt AIQ message
	payload, sender, err := aiq_message.ReceiveMessage(rawJSON, decryptionKey, allCorrespondents)
	if err != nil {
		return nil, "", fmt.Errorf("failed to receive AIQ message: %w", err)
	}

	// Deserialize request
	envelope, err := DeserializeRequest(payload)
	if err != nil {
		return nil, "", fmt.Errorf("failed to deserialize request: %w", err)
	}

	// Validate request type
	if envelope.Type != CommunitySubscribeRequestType || envelope.CommunitySubscribe == nil {
		return nil, "", fmt.Errorf("invalid request type: expected %s", CommunitySubscribeRequestType)
	}

	member := envelope.CommunitySubscribe.Member

	// Verify signature: ensure the member's public key matches the AIQ message sender's signature key.
	if !bytes.Equal(sender.SignatureKey, member.SignatureKey) {
		return nil, "", fmt.Errorf("member public key mismatch with AIQ message sender")
	}

	return &member, envelope.CommunityUUID, nil
}

// ReceiveCommunityUpdate decrypts and verifies an AIQ community update message, verifies the community's internal signature, updates a local file, and generates an acknowledgment or error message.
func receiveCommunityUpdate(rawJSON []byte, decryptionKey []byte, correspondents []aiq_message.MessageContact) (*Community, *aiq_message.MessageContact, error) {

	// Receive and decrypt AIQ message
	payload, sender, err := aiq_message.ReceiveMessage(rawJSON, decryptionKey, correspondents)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to receive AIQ message: %w", err)
	}

	// Deserialize request
	envelope, err := DeserializeRequest(payload)
	if err != nil {
		return nil, &sender, fmt.Errorf("failed to deserialize request: %w", err)
	}

	// Validate request type
	if envelope.Type != CommunityUpdateRequestType || envelope.CommunityUpdate == nil {
		return nil, &sender, fmt.Errorf("invalid request type %v", envelope.Type)
		//generateErrorResponse("invalid request type", signingKey, []aiq_message.MessageContact{sender}, envelope.CommunityUUID)
	}

	community := envelope.CommunityUpdate.Community

	// Verify community signature
	if err := community.Verify(); err != nil {
		return nil, &sender, fmt.Errorf("community verification failed: %s", err.Error())
		//generateErrorResponse("community verification failed: "+err.Error(), signingKey, []aiq_message.MessageContact{sender}, community.UID), err
	}

	// Verify sender is the owner
	if !bytes.Equal(sender.SignatureKey, community.Owner.SignatureKey) {
		return nil, &sender, fmt.Errorf("sender is not the community owner")
	}

	return &community, &sender, nil
}

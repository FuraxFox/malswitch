/*
Search requests are signed objects describing a search.
They are encrypted before
*/
package aiq

import (
	"encoding/json"
	"fmt"

	"github.com/FuraxFox/malswitch/internal/aiq_message"
)

// Serialize
func (s *RequestEnveloppe) Serialize() ([]byte, error) {

	// 2. Marshal the signed struct to JSON
	data, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Search struct to JSON: %w", err)
	}

	return data, nil
}

// Deserialize reads a JSON byte slice, unmarshals the content into a Search struct,
// and verifies the embedded signature.
func DeserializeRequest(data []byte) (RequestEnveloppe, error) {
	var s RequestEnveloppe

	// 1. Unmarshal the JSON byte slice into the Search struct
	if err := json.Unmarshal(data, &s); err != nil {
		return RequestEnveloppe{}, fmt.Errorf("failed to unmarshal JSON into Search struct: %w", err)
	}

	return s, nil
}

func (s *RequestEnveloppe) String() string {
	buff, err := s.Serialize()
	if err != nil {
		return ""
	}
	return string(buff)
}

func NewSubmitSearchHashesRequest(community string, hashes []HashEntry) (*RequestEnveloppe, error) {
	enveloppe := RequestEnveloppe{
		CommunityUUID: community,
		Type:          SearchSubmitRequestType,
	}
	// TODO
	return &enveloppe, nil
}

func NewCommunityUpdateRequest(community Community) (*RequestEnveloppe, error) {
	enveloppe := RequestEnveloppe{
		CommunityUUID: community.UID,
		Type:          CommunityUpdateRequestType,
		CommunityUpdate: &CommunityUpdateRequest{
			Community: community,
		},
	}
	return &enveloppe, nil
}

func NewCommunityUpdateAcceptedRequest(communityUUID string) (*RequestEnveloppe, error) {
	enveloppe := RequestEnveloppe{
		CommunityUUID: communityUUID,
		Type:          CommunityUpdateAcceptedRequestType,
	}
	return &enveloppe, nil
}

func NewCommunitySubscribeRequest(communityUUID string, member aiq_message.MessageContact) (*RequestEnveloppe, error) {
	enveloppe := RequestEnveloppe{
		CommunityUUID: communityUUID,
		Type:          CommunitySubscribeRequestType,
		CommunitySubscribe: &CommunitySubscribeRequest{
			Member: member,
		},
	}
	return &enveloppe, nil
}

func NewCommunitySubscriptionQueuedRequest(communityUUID string) (*RequestEnveloppe, error) {
	enveloppe := RequestEnveloppe{
		CommunityUUID: communityUUID,
		Type:          CommunitySubscriptionQueuedRequestType,
	}
	return &enveloppe, nil
}

func NewSubmitSearchIPsRequest(community string, addresses []string) (*RequestEnveloppe, error) {
	enveloppe := RequestEnveloppe{
		CommunityUUID: community,
		Type:          SearchSubmitRequestType,
	}
	// TODO
	return &enveloppe, nil
}

func NewSubmitSearchYaraRequest(community string, rule string) (*RequestEnveloppe, error) {
	enveloppe := RequestEnveloppe{
		CommunityUUID: community,
		Type:          SearchSubmitRequestType,
	}
	// TODO
	return &enveloppe, nil
}

func NewSubmitSearchTextRequest(community string, words []string) (*RequestEnveloppe, error) {
	enveloppe := RequestEnveloppe{
		CommunityUUID: community,
		Type:          SearchSubmitRequestType,
	}
	// TODO
	return &enveloppe, nil
}

func NewSubmitResultRequest(community string, searchUUID string, results []SearchMatch) (*RequestEnveloppe, error) {
	enveloppe := RequestEnveloppe{
		CommunityUUID: community,
		Type:          SearchResultRequestType,
	}
	// TODO
	return &enveloppe, nil
}

func NewSearchAcceptedRequest(community string, searchUUID string) (*RequestEnveloppe, error) {
	enveloppe := RequestEnveloppe{
		CommunityUUID: community,
		Type:          SearchAcceptedRequestType,
		SearchReference: &SearchReferenceRequest{
			SearchUUID: searchUUID,
		},
	}
	return &enveloppe, nil
}

func NewSearchPullRequest(community string, searchUUID string) (*RequestEnveloppe, error) {
	enveloppe := RequestEnveloppe{
		CommunityUUID: community,
		Type:          SearchResultPullRequestType,
		SearchReference: &SearchReferenceRequest{
			SearchUUID: searchUUID,
		},
	}
	return &enveloppe, nil
}

func NewErrorRequest(community string, message string) (*RequestEnveloppe, error) {
	enveloppe := RequestEnveloppe{
		CommunityUUID: community,
		Type:          ErrorRequestType,
		Error: &ErrorRequest{
			Message: message,
		},
	}
	return &enveloppe, nil
}

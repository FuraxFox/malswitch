/*
Search requests are signed objects describing a search.
They are encrypted before
*/
package aiq

import (
	"encoding/json"
	"fmt"
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

func NewSubmitSearchHashesRequest(hashes []HashEntry) (*RequestEnveloppe, error) {
	// TODO
	return nil, nil
}

func NewSubmitSearchIPsRequest(addresses []string) (*RequestEnveloppe, error) {
	// TODO
	return nil, nil
}

func NewSubmitSearchYaraRequest(rule string) (*RequestEnveloppe, error) {
	// TODO
	return nil, nil
}

func NewSubmitSearchTextRequest(words []string) (*RequestEnveloppe, error) {
	// TODO
	return nil, nil
}

func NewSubmitResultRequest(uuid string, results []SearchMatch) (*RequestEnveloppe, error) {
	// TODO
	return nil, nil
}

func NewSearchAcceptedRequest(uiid string) (*RequestEnveloppe, error) {
	// TODO
	return nil, nil
}

func NewSearchPullRequest(uuid string) (*RequestEnveloppe, error) {
	// TODO
	return nil, nil
}

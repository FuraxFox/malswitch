/*
Search requests are signed objects describing a search.
They are encrypted before
*/
package aiq

import (
	"encoding/json"
	"fmt"
)

// IOC hash types can be validated against this list
const (
	IOC_TYPE_IP_LIST   = "IP_LIST"
	IOC_TYPE_HASH_LIST = "HASH_LIST"
	IOC_TYPE_YARA_RULE = "YARA_RULE"
	IOC_TYPE_TEXT      = "TEXT"
)

// Represents the structure of a single hash entry to allow for hash type identification.
type HashEntry struct {
	Value string `json:"value"` // The hash string (e.g., a0eebc99da0)
	Type  string `json:"type"`  // e.g., "MD5", "SHA256"
}

// structure to submit a search
type SearchRequest struct {
	CommunityUUID string `json:"community_uuid"`
	Content       struct {
		Type     string      `json:"type"`                // e.g., "IP_LIST", "HASH_LIST", "YARA_RULE", "GENERIC_STRING"
		IPs      []string    `json:"ips,omitempty"`       // Used for IP_LIST
		Hashes   []HashEntry `json:"hashes,omitempty"`    // Used for HASH_LIST
		YaraRule string      `json:"yara_rule,omitempty"` // Used for YARA_RULE
		Text     string      `json:"text,omitempty"`      // Used for IOC_TYPE_TEXT (or for simple text searches)
	} `json:"content"`
}

type SearchReference struct {
	SearchUUID string `json:"search_uuid"`
	Action     string `json:"search_action"`
}

type SearchMatch struct {
	MatchUUID  string `json:"match_uuid"`
	Reference  string `json:"reference"`
	ContentURL string `json:"content_uri,omitempty"`
	ContenType string `json:"content_type,omitempty"`
}

type SearchResult struct {
	SearchUUID   string        `json:"search_uuid"`
	Status       string        `json:"status"`
	MatchesCount int           `json:"matches_count,omitempty"`
	Matches      []SearchMatch `json:"matches,omitempty"`
}

// Serialize
func (s *SearchRequest) Serialize() ([]byte, error) {

	// 2. Marshal the signed struct to JSON
	data, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Search struct to JSON: %w", err)
	}

	return data, nil
}

// Deserialize reads a JSON byte slice, unmarshals the content into a Search struct,
// and verifies the embedded signature.
func DeserializeSearch(data []byte) (SearchRequest, error) {
	var s SearchRequest

	// 1. Unmarshal the JSON byte slice into the Search struct
	if err := json.Unmarshal(data, &s); err != nil {
		return SearchRequest{}, fmt.Errorf("failed to unmarshal JSON into Search struct: %w", err)
	}

	return s, nil
}

func (s *SearchRequest) String() string {
	buff, err := s.Serialize()
	if err != nil {
		return ""
	}
	return string(buff)
}

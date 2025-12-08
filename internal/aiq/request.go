/*
Search requests are signed objects describing a search.
They are encrypted before
*/
package aiq

type SearchSubmitRequest struct {
	Type     string      `json:"type"`                // e.g., "IP_LIST", "HASH_LIST", "YARA_RULE", "GENERIC_STRING"
	IPs      []string    `json:"ips,omitempty"`       // Used for IP_LIST
	Hashes   []HashEntry `json:"hashes,omitempty"`    // Used for HASH_LIST
	YaraRule string      `json:"yara_rule,omitempty"` // Used for YARA_RULE
	Text     string      `json:"text,omitempty"`      // Used for IOC_TYPE_TEXT (or for simple text searches)

}

type SearchResultRequest struct {
	SearchUUID   string        `json:"search_uuid"`
	Status       string        `json:"status"`
	MatchesCount int           `json:"matches_count,omitempty"`
	Matches      []SearchMatch `json:"matches,omitempty"`
}

type SearchReferenceRequest struct {
	SearchUUID string `json:"search_uuid"`
	Action     string `json:"search_action"`
}

type RequestEnveloppe struct {
	CommunityUUID   string                 `json:"community_uuid"`
	Type            RequestType            `json:"request_type"`
	SubmitRequest   SearchSubmitRequest    `json:"submit_request,omitempty"`
	ResultRequest   SearchResultRequest    `json:"result_request,omitempty"`
	SearchReference SearchReferenceRequest `json:"search_reference_request"`
}
